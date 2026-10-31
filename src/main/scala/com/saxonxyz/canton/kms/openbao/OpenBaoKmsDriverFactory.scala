package com.saxonxyz.canton.kms.openbao

import com.digitalasset.canton.crypto.kms.driver.api.v1.KmsDriverFactory
import com.typesafe.scalalogging.LazyLogging
import org.slf4j.Logger
import pureconfig._
import pureconfig.generic.auto._

import scala.concurrent.ExecutionContext

class OpenBaoKmsDriverFactory extends KmsDriverFactory with LazyLogging {

  override def name: String = "openbao"

  override def buildInfo: Option[String] = None

  override type ConfigType = OpenBaoKmsConfig

  override type Driver = OpenBaoKmsDriver

  override def configReader: ConfigReader[OpenBaoKmsConfig] = implicitly[ConfigReader[OpenBaoKmsConfig]]

  override def configWriter(confidential: Boolean): ConfigWriter[OpenBaoKmsConfig] = {
    val base = implicitly[ConfigWriter[OpenBaoKmsConfig]]
    if (confidential) base.contramap[OpenBaoKmsConfig](_.copy(token = Some("***")))
    else base
  }

  override def create(
      config: OpenBaoKmsConfig,
      loggerFactory: Class[?] => Logger,
      executionContext: ExecutionContext,
  ): OpenBaoKmsDriver = {
    logger.info(s"Creating OpenBao Transit KMS driver for ${config.address} (mount ${config.mountPath})")
    OpenBaoKmsDriver(config, executionContext)
  }
}
