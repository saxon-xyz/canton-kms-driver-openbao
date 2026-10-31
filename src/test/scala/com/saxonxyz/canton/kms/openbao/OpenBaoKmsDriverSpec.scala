package com.saxonxyz.canton.kms.openbao

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class OpenBaoKmsDriverSpec extends AnyWordSpec with Matchers {

  "isRetryable" should {
    "not retry permanent client errors" in {
      OpenBaoKmsDriver.isRetryable("sign: 403 - {\"errors\":[\"permission denied\"]}") shouldBe false
      OpenBaoKmsDriver.isRetryable("decrypt: 400 - {\"errors\":[\"invalid ciphertext\"]}") shouldBe false
    }
    "retry rate limiting, server errors, a sealed server and transport failures" in {
      OpenBaoKmsDriver.isRetryable("sign: 429 - slow down") shouldBe true
      OpenBaoKmsDriver.isRetryable("sign: 503 - {\"errors\":[\"Vault is sealed\"]}") shouldBe true
      OpenBaoKmsDriver.isRetryable("sign: Connection refused") shouldBe true
    }
    "not retry an untrusted TLS certificate" in {
      val e = new RuntimeException("Exception when sending request",
        new javax.net.ssl.SSLHandshakeException("PKIX path building failed"))
      val err = s"sign: ${OpenBaoTransitClient.describe(e)}"
      err should include("PKIX path building failed")
      OpenBaoKmsDriver.isRetryable(err) shouldBe false
    }
    "keep the root cause of other transport failures, and retry them" in {
      val e = new RuntimeException("Exception when sending request", new java.net.ConnectException("Connection refused"))
      val err = s"sign: ${OpenBaoTransitClient.describe(e)}"
      err should include("ConnectException: Connection refused")
      OpenBaoKmsDriver.isRetryable(err) shouldBe true
    }
  }

  "uniqueKeyName" should {
    "keep names URL-safe and unique" in {
      val a = OpenBaoKmsDriver.uniqueKeyName(Some("participant1 / namespace"), "default")
      val b = OpenBaoKmsDriver.uniqueKeyName(Some("participant1 / namespace"), "default")
      a should fullyMatch regex "participant1---namespace-[0-9a-f]{8}"
      a should not equal b
      OpenBaoKmsDriver.uniqueKeyName(None, "canton-symmetric") should startWith("canton-symmetric-")
    }
  }

  "unwrap" should {
    "strip Transit's version prefix" in {
      OpenBaoTransitClient.unwrap("sign", "vault:v1:AQID").map(_.toSeq) shouldBe Right(Seq[Byte](1, 2, 3))
      OpenBaoTransitClient.unwrap("sign", "vault:v12:AQID").map(_.toSeq) shouldBe Right(Seq[Byte](1, 2, 3))
    }
    "reject anything else" in {
      OpenBaoTransitClient.unwrap("sign", "AQID").isLeft shouldBe true
    }
  }

  "publicKeyDer" should {
    "wrap a bare Ed25519 key in SubjectPublicKeyInfo" in {
      val raw = Array.fill[Byte](32)(7)
      val der = OpenBaoKmsDriver.publicKeyDer("ed25519", Base64.getEncoder.encodeToString(raw))
      der.length shouldBe 44
      KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der)).getAlgorithm shouldBe "EdDSA"
    }
    "decode PEM SubjectPublicKeyInfo for ECDSA (a real Transit ecdsa-p256 key)" in {
      val pem =
        """-----BEGIN PUBLIC KEY-----
          |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVtbyhdtis2Kg1GMonmpIduNCFb2Z
          |Qk7yBzXZqv8GNIGQyf2nGaVezwqni7scnT0eYTa4r0toEAO9LWGkw4h+/A==
          |-----END PUBLIC KEY-----
          |""".stripMargin
      val der = OpenBaoKmsDriver.publicKeyDer("ecdsa-p256", pem)
      KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der)).getAlgorithm shouldBe "EC"
    }
  }
}
