package com.saxonxyz.canton.kms.openbao

import com.typesafe.scalalogging.LazyLogging
import io.circe.{Json, JsonObject}
import io.circe.parser.parse
import sttp.client3._
import sttp.model.Uri

import java.io.FileInputStream
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.time.Duration
import java.util.Base64
import javax.net.ssl.{SSLContext, TrustManagerFactory}
import scala.jdk.CollectionConverters._
import scala.util.Try

/** A Transit key as Canton sees it: its type and the public key of version 1 (if asymmetric). */
final case class TransitKey(keyType: String, publicKey: Option[String], softDeleted: Boolean)

/** Thin client for the OpenBao / Vault Transit secrets engine HTTP API.
  *
  * Errors are returned as `Left("<what>: <status> - <body>")` so the driver can tell permanent
  * 4xx failures from retryable ones; transport failures carry no status and stay retryable.
  *
  * Every asymmetric operation is pinned to key version 1. Canton registers the public key it
  * reads at creation time and rotates by creating new keys, so a Transit-side rotation would
  * silently split what Canton verifies against from what Transit signs with.
  */
class OpenBaoTransitClient(config: OpenBaoKmsConfig, backend: SttpBackend[Identity, Any])
    extends LazyLogging {

  import OpenBaoTransitClient._

  private def token: String =
    config.tokenFile
      .map(f => new String(Files.readAllBytes(Paths.get(f)), StandardCharsets.UTF_8).trim)
      .orElse(config.token)
      .getOrElse(throw new IllegalStateException("no OpenBao token configured"))

  private def transit(path: String*): Uri = uri"${config.transitUrl}".addPath(path)

  private def send(what: String, req: Request[String, Any]): Either[String, Option[Json]] = {
    val withHeaders = req
      .header("X-Vault-Token", token)
      .headers(config.namespace.map(ns => Map("X-Vault-Namespace" -> ns)).getOrElse(Map.empty[String, String]))
      .readTimeout(config.requestTimeout)
    Try(withHeaders.send(backend)).toEither.left
      .map(e => s"$what: ${describe(e)}")
      .flatMap { resp =>
        if (resp.code.isSuccess)
          if (resp.body.trim.isEmpty) Right(None)
          else parse(resp.body).left.map(e => s"$what: unparseable response: ${e.getMessage}").map(Some(_))
        else Left(s"$what: ${resp.code.code} - ${resp.body}")
      }
  }

  private def post(what: String, uri: Uri, body: Json): Either[String, Option[Json]] =
    send(what, basicRequest.post(uri).contentType("application/json").body(body.noSpaces).response(asStringAlways))

  private def get(what: String, uri: Uri): Either[String, Option[Json]] =
    send(what, basicRequest.get(uri).response(asStringAlways))

  private def data(what: String, json: Option[Json]): Either[String, JsonObject] =
    json.flatMap(_.hcursor.downField("data").focus).flatMap(_.asObject).toRight(s"$what: no data in response")

  private def field(what: String, obj: JsonObject, name: String): Either[String, String] =
    obj(name).flatMap(_.asString).toRight(s"$what: response has no '$name'")

  /** Server is initialised, unsealed and reachable, and the token is valid. */
  def healthCheck(): Either[String, Unit] = {
    val sys = uri"${config.address.stripSuffix("/")}/v1/sys/health"
    for {
      _ <- Try(basicRequest.get(sys).response(asStringAlways).readTimeout(config.requestTimeout).send(backend))
        .toEither.left.map(e => s"health: ${describe(e)}")
        // 200 active, 429 unsealed standby; 501 not initialised, 503 sealed
        .flatMap(r => if (r.code.code == 200 || r.code.code == 429) Right(()) else Left(s"health: ${r.code.code} - ${r.body}"))
      _ <- get("token lookup", uri"${config.address.stripSuffix("/")}/v1/auth/token/lookup-self")
    } yield ()
  }

  def createKey(name: String, keyType: String): Either[String, Unit] =
    post(
      "create key",
      transit("keys", name),
      Json.obj(
        "type" -> Json.fromString(keyType),
        "exportable" -> Json.False,
        "allow_plaintext_backup" -> Json.False,
      ),
    ).map(_ => ())

  /** Right(None) when the key does not exist. */
  def readKey(name: String): Either[String, Option[TransitKey]] =
    get("read key", transit("keys", name)) match {
      case Left(err) if err.startsWith("read key: 404 ") => Right(None)
      case Left(err) => Left(err)
      case Right(json) =>
        data("read key", json).flatMap { d =>
          field("read key", d, "type").map { keyType =>
            val v1 = d("keys").flatMap(_.asObject).flatMap(_("1"))
            Some(
              TransitKey(
                keyType = keyType,
                publicKey = v1.flatMap(_.asObject).flatMap(_("public_key")).flatMap(_.asString).filter(_.nonEmpty),
                softDeleted = d("soft_deleted").flatMap(_.asBoolean).getOrElse(false),
              )
            )
          }
        }
    }

  /** Sign `input` (Transit hashes it with `hashAlgorithm`; ignored for ed25519). Returns the
    * raw signature: ASN.1 DER for ECDSA, 64 bytes for Ed25519.
    */
  def sign(name: String, input: Array[Byte], hashAlgorithm: Option[String]): Either[String, Array[Byte]] = {
    val uri = hashAlgorithm.fold(transit("sign", name))(h => transit("sign", name, h))
    post(
      "sign",
      uri,
      Json.obj(
        "input" -> Json.fromString(b64(input)),
        "key_version" -> Json.fromInt(1),
        "marshaling_algorithm" -> Json.fromString("asn1"),
      ),
    ).flatMap(data("sign", _)).flatMap(field("sign", _, "signature")).flatMap(unwrap("sign", _))
  }

  /** Decrypt an RSA-OAEP ciphertext produced with the version-1 public key. */
  def decryptAsymmetric(name: String, ciphertext: Array[Byte]): Either[String, Array[Byte]] =
    decrypt(name, s"vault:v1:${b64(ciphertext)}")

  /** Symmetric encryption. The opaque result is Transit's own `vault:vN:...` string, as bytes. */
  def encryptSymmetric(name: String, plaintext: Array[Byte]): Either[String, Array[Byte]] =
    post("encrypt", transit("encrypt", name), Json.obj("plaintext" -> Json.fromString(b64(plaintext))))
      .flatMap(data("encrypt", _))
      .flatMap(field("encrypt", _, "ciphertext"))
      .map(_.getBytes(StandardCharsets.UTF_8))

  def decryptSymmetric(name: String, ciphertext: Array[Byte]): Either[String, Array[Byte]] =
    decrypt(name, new String(ciphertext, StandardCharsets.UTF_8))

  private def decrypt(name: String, ciphertext: String): Either[String, Array[Byte]] =
    post("decrypt", transit("decrypt", name), Json.obj("ciphertext" -> Json.fromString(ciphertext)))
      .flatMap(data("decrypt", _))
      .flatMap(field("decrypt", _, "plaintext"))
      .flatMap(p => Try(Base64.getDecoder.decode(p)).toEither.left.map(e => s"decrypt: bad plaintext: ${e.getMessage}"))

  /** Transit refuses to delete a key until deletion_allowed is set on it. */
  def deleteKey(name: String): Either[String, Unit] =
    for {
      _ <- post("allow deletion", transit("keys", name, "config"), Json.obj("deletion_allowed" -> Json.True))
      _ <- send("delete key", basicRequest.delete(transit("keys", name)).response(asStringAlways))
    } yield ()
}

object OpenBaoTransitClient {

  def apply(config: OpenBaoKmsConfig): OpenBaoTransitClient = {
    val builder = HttpClient.newBuilder().connectTimeout(Duration.ofMillis(config.connectionTimeout.toMillis))
    config.caCertFile.foreach(f => builder.sslContext(sslContextTrusting(f)))
    new OpenBaoTransitClient(config, HttpClientSyncBackend.usingClient(builder.build()))
  }

  /** Marks a TLS certificate the driver does not trust: a configuration error, not retryable. */
  val TlsRejected = "TLS certificate rejected"

  /** sttp wraps transport failures as "Exception when sending request", which hides the cause
    * an operator needs (wrong CA, hostname mismatch, connection refused). Walk to the root cause.
    */
  private[openbao] def describe(e: Throwable): String = {
    val chain = Iterator.iterate(e)(_.getCause).takeWhile(_ != null).take(10).toSeq
    val root = chain.last
    val tls = chain.exists {
      case _: javax.net.ssl.SSLHandshakeException | _: java.security.cert.CertificateException => true
      case _ => false
    }
    val cause = s"${root.getClass.getSimpleName}: ${root.getMessage}"
    if (tls) s"$TlsRejected ($cause); check ca-cert-file and the server certificate's hostname"
    else s"${e.getMessage} ($cause)"
  }

  private[openbao] def b64(bytes: Array[Byte]): String = Base64.getEncoder.encodeToString(bytes)

  /** "vault:v1:<base64>" -> bytes. OpenBao keeps Vault's prefix for compatibility. */
  private[openbao] def unwrap(what: String, s: String): Either[String, Array[Byte]] =
    s.split(":", 3) match {
      case Array(_, version, body) if version.startsWith("v") =>
        Try(Base64.getDecoder.decode(body)).toEither.left.map(e => s"$what: bad base64: ${e.getMessage}")
      case _ => Left(s"$what: unexpected format '${s.take(20)}...'")
    }

  private def sslContextTrusting(pemFile: String): SSLContext = {
    val certs = {
      val in = new FileInputStream(pemFile)
      try CertificateFactory.getInstance("X.509").generateCertificates(in).asScala.toSeq
      finally in.close()
    }
    val ks = KeyStore.getInstance(KeyStore.getDefaultType)
    ks.load(null, null)
    certs.zipWithIndex.foreach { case (c, i) => ks.setCertificateEntry(s"ca-$i", c) }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    tmf.init(ks)
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(null, tmf.getTrustManagers, null)
    ctx
  }
}
