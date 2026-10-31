package com.saxonxyz.canton.kms.openbao

import com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriver
import com.digitalasset.canton.crypto.kms.driver.testing.v1.{KmsDriverFactoryTest, KmsDriverTest}

import scala.concurrent.ExecutionContext

/** DA's reusable KMS driver test suite (com.daml %% kms-driver-testing), run against a real
  * OpenBao or Vault server. Needs BAO_ADDR and BAO_TOKEN (or VAULT_*), and a Transit engine
  * mounted at BAO_TRANSIT_MOUNT (default "transit"). Without them every test is cancelled.
  *
  *   docker run -d -p 127.0.0.1:8200:8200 quay.io/openbao/openbao server -dev -dev-root-token-id=devroot
  *   BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=devroot bao secrets enable transit
  */
private object DaSuiteEnv {
  val present: Boolean =
    Seq("ADDR", "TOKEN").forall(v => sys.env.contains(s"BAO_$v") || sys.env.contains(s"VAULT_$v"))

  def config(cancel: String => Nothing): OpenBaoKmsConfig =
    if (present) OpenBaoKmsConfig.fromEnvironment()
    else cancel("OpenBao not configured (BAO_ADDR, BAO_TOKEN)")
}

class OpenBaoDaKmsDriverTest extends KmsDriverTest {

  // The suite's afterAll closes its lazily created driver, which would build one (and fail)
  // when no server is configured.
  override def afterAll(): Unit = if (DaSuiteEnv.present) super.afterAll()

  override protected def newKmsDriver(): KmsDriver =
    OpenBaoKmsDriver(DaSuiteEnv.config(cancel(_)), ExecutionContext.global)

  if (DaSuiteEnv.present)
    "OpenBao KMS Driver" must {
      behave like kmsDriver(allowKeyGeneration = true)
    }
  else
    "OpenBao KMS Driver" must {
      "run against an OpenBao Transit engine" in cancel("OpenBao not configured")
    }
}

class OpenBaoDaKmsDriverFactoryTest extends KmsDriverFactoryTest {

  override type Factory = OpenBaoKmsDriverFactory

  override protected lazy val factory: OpenBaoKmsDriverFactory = new OpenBaoKmsDriverFactory

  override protected lazy val config: OpenBaoKmsDriverFactory#ConfigType = DaSuiteEnv.config(cancel(_))

  "OpenBao KMS Driver Factory" must {
    behave like kmsDriverFactory()
  }
}
