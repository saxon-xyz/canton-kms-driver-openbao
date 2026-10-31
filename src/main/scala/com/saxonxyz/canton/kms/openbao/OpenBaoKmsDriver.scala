package com.saxonxyz.canton.kms.openbao

import com.digitalasset.canton.crypto.kms.driver.api.v1._
import com.saxonxyz.canton.kms.openbao.OpenBaoKmsDriver._
import com.typesafe.scalalogging.LazyLogging
import io.opentelemetry.context.Context

import java.util.Base64
import scala.concurrent.{ExecutionContext, Future}

/** Canton KMS driver backed by the OpenBao (or HashiCorp Vault) Transit secrets engine.
  * The Canton key id is the Transit key name.
  */
class OpenBaoKmsDriver(config: OpenBaoKmsConfig, client: OpenBaoTransitClient, ec: ExecutionContext)
    extends KmsDriver
    with LazyLogging {

  private implicit val executionContext: ExecutionContext = ec

  override def supportedSigningKeySpecs: Set[SigningKeySpec] =
    Set(SigningKeySpec.EcCurve25519, SigningKeySpec.EcP256, SigningKeySpec.EcP384)

  override def supportedSigningAlgoSpecs: Set[SigningAlgoSpec] =
    Set(SigningAlgoSpec.Ed25519, SigningAlgoSpec.EcDsaSha256, SigningAlgoSpec.EcDsaSha384)

  override def supportedEncryptionKeySpecs: Set[EncryptionKeySpec] = Set(EncryptionKeySpec.Rsa2048)

  override def supportedEncryptionAlgoSpecs: Set[EncryptionAlgoSpec] = Set(EncryptionAlgoSpec.RsaEsOaepSha256)

  /** Run a client call on the driver's execution context, turning Left into a KmsDriverException. */
  private def call[A](what: String)(f: => Either[String, A]): Future[A] = Future {
    f match {
      case Right(a) => a
      case Left(err) => throw KmsDriverException(new RuntimeException(s"$what failed: $err"), retryable = isRetryable(err))
    }
  }

  private def unsupported(what: String): Nothing =
    throw KmsDriverException(new IllegalArgumentException(s"Unsupported $what"), retryable = false)

  override def health: Future[KmsDriverHealth] = Future {
    client.healthCheck() match {
      case Right(_) => KmsDriverHealth.Ok
      case Left(err) =>
        logger.warn(s"Health check failed: $err")
        KmsDriverHealth.Failed(err)
    }
  }

  private def generate(keyName: Option[String], default: String, transitType: String): Future[String] = {
    val name = uniqueKeyName(keyName, default)
    logger.info(s"Generating Transit key $name ($transitType)")
    call("generate key")(client.createKey(name, transitType)).map(_ => name)
  }

  override def generateSigningKeyPair(signingKeySpec: SigningKeySpec, keyName: Option[String])(
      traceContext: Context
  ): Future[String] =
    signingKeySpec match {
      case SigningKeySpec.EcCurve25519 => generate(keyName, "canton-signing-ed25519", "ed25519")
      case SigningKeySpec.EcP256 => generate(keyName, "canton-signing-ec-p256", "ecdsa-p256")
      case SigningKeySpec.EcP384 => generate(keyName, "canton-signing-ec-p384", "ecdsa-p384")
      case other => Future.failed(KmsDriverException(new IllegalArgumentException(s"Unsupported signing key spec: $other"), retryable = false))
    }

  override def generateEncryptionKeyPair(encryptionKeySpec: EncryptionKeySpec, keyName: Option[String])(
      traceContext: Context
  ): Future[String] =
    encryptionKeySpec match {
      case EncryptionKeySpec.Rsa2048 => generate(keyName, "canton-encryption-rsa-2048", "rsa-2048")
      case other => Future.failed(KmsDriverException(new IllegalArgumentException(s"Unsupported encryption key spec: $other"), retryable = false))
    }

  override def generateSymmetricKey(keyName: Option[String])(traceContext: Context): Future[String] =
    generate(keyName, "canton-symmetric", "aes256-gcm96")

  override def sign(data: Array[Byte], keyId: String, algoSpec: SigningAlgoSpec)(
      traceContext: Context
  ): Future[Array[Byte]] = {
    val hash = algoSpec match {
      case SigningAlgoSpec.Ed25519 => None
      case SigningAlgoSpec.EcDsaSha256 => Some("sha2-256")
      case SigningAlgoSpec.EcDsaSha384 => Some("sha2-384")
      case other => unsupported(s"signing algorithm spec: $other")
    }
    call("sign")(client.sign(keyId, data, hash))
  }

  override def decryptAsymmetric(ciphertext: Array[Byte], keyId: String, algoSpec: EncryptionAlgoSpec)(
      traceContext: Context
  ): Future[Array[Byte]] =
    algoSpec match {
      case EncryptionAlgoSpec.RsaEsOaepSha256 => call("decrypt")(client.decryptAsymmetric(keyId, ciphertext))
      case other => Future.failed(KmsDriverException(new IllegalArgumentException(s"Unsupported encryption algorithm spec: $other"), retryable = false))
    }

  override def encryptSymmetric(data: Array[Byte], keyId: String)(traceContext: Context): Future[Array[Byte]] =
    call("encrypt")(client.encryptSymmetric(keyId, data))

  override def decryptSymmetric(ciphertext: Array[Byte], keyId: String)(traceContext: Context): Future[Array[Byte]] =
    call("decrypt")(client.decryptSymmetric(keyId, ciphertext))

  override def getPublicKey(keyId: String)(traceContext: Context): Future[PublicKey] =
    call("get public key")(client.readKey(keyId)).map {
      case None => throw KmsDriverException(new RuntimeException(s"Key $keyId not found"), retryable = false)
      case Some(key) =>
        val spec: KeySpec = key.keyType match {
          case "ed25519" => SigningKeySpec.EcCurve25519
          case "ecdsa-p256" => SigningKeySpec.EcP256
          case "ecdsa-p384" => SigningKeySpec.EcP384
          case "rsa-2048" => EncryptionKeySpec.Rsa2048
          case other => unsupported(s"key type for a public key: $other (key $keyId)")
        }
        val material = key.publicKey.getOrElse(unsupported(s"key $keyId: no public key"))
        PublicKey(publicKeyDer(key.keyType, material), spec)
    }

  override def keyExistsAndIsActive(keyId: String)(traceContext: Context): Future[Unit] =
    call("check key")(client.readKey(keyId)).map {
      case Some(key) if !key.softDeleted => ()
      case Some(_) => throw KmsDriverException(new RuntimeException(s"Key $keyId is soft-deleted"), retryable = false)
      case None => throw KmsDriverException(new RuntimeException(s"Key $keyId not found"), retryable = false)
    }

  override def deleteKey(keyId: String)(traceContext: Context): Future[Unit] =
    if (!config.allowDeletion)
      Future.failed(KmsDriverException(new IllegalStateException(s"Deletion disabled by config (key $keyId)"), retryable = false))
    else {
      logger.info(s"Deleting Transit key $keyId")
      call("delete key")(client.deleteKey(keyId))
    }

  override def close(): Unit = ()
}

object OpenBaoKmsDriver {

  def apply(config: OpenBaoKmsConfig, ec: ExecutionContext): OpenBaoKmsDriver =
    new OpenBaoKmsDriver(config, OpenBaoTransitClient(config), ec)

  /** Transit key names go into URL paths, so keep them to [A-Za-z0-9_.-]. A random suffix
    * keeps Canton's repeated requests for the same name (or none) from colliding.
    */
  def uniqueKeyName(requested: Option[String], default: String): String = {
    val base = requested.map(_.replaceAll("[^A-Za-z0-9_.-]", "-")).filter(_.nonEmpty).getOrElse(default)
    s"$base-${java.util.UUID.randomUUID().toString.take(8)}"
  }

  private val HttpStatus = """: (\d{3}) - """.r

  /** A 4xx other than 429 is permanent (bad token, missing policy, unknown key), so Canton must
    * not retry it forever; 429, 5xx (including 503 sealed) and transport errors stay retryable.
    */
  def isRetryable(err: String): Boolean =
    HttpStatus.findFirstMatchIn(err).map(_.group(1).toInt) match {
      case Some(code) if code >= 400 && code < 500 => code == 429
      case _ => true
    }

  // SubjectPublicKeyInfo prefix for Ed25519: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (0 unused) }
  private val Ed25519SpkiPrefix: Array[Byte] =
    Array(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00).map(_.toByte)

  /** Canton wants X.509 SubjectPublicKeyInfo DER. Transit returns PEM SPKI for ECDSA and RSA,
    * but the bare 32-byte key, base64, for Ed25519.
    */
  def publicKeyDer(keyType: String, material: String): Array[Byte] =
    if (keyType == "ed25519") Ed25519SpkiPrefix ++ Base64.getDecoder.decode(material.trim)
    else
      Base64.getDecoder.decode(
        material.linesIterator.filterNot(_.startsWith("-----")).mkString.replaceAll("\\s", "")
      )
}
