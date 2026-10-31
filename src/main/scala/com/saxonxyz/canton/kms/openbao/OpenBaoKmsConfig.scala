package com.saxonxyz.canton.kms.openbao

import scala.concurrent.duration._

/** Configuration for the OpenBao / Vault Transit driver.
  *
  * @param address        server address, e.g. https://openbao.example:8200
  * @param token          auth token. Prefer `tokenFile` in Kubernetes so the token is not in config.
  * @param tokenFile      path to a file holding the token (read on every request, so a rotated
  *                       token is picked up without a restart)
  * @param mountPath      where the Transit secrets engine is mounted
  * @param namespace      Vault Enterprise / OpenBao namespace, sent as X-Vault-Namespace
  * @param caCertFile     PEM CA bundle to trust for the server's TLS certificate
  * @param allowDeletion  when false, deleteKey refuses; Transit keys are also created with
  *                       deletion_allowed=false and only switched on immediately before a delete
  */
case class OpenBaoKmsConfig(
    address: String,
    token: Option[String] = None,
    tokenFile: Option[String] = None,
    mountPath: String = "transit",
    namespace: Option[String] = None,
    caCertFile: Option[String] = None,
    requestTimeout: FiniteDuration = 30.seconds,
    connectionTimeout: FiniteDuration = 10.seconds,
    allowDeletion: Boolean = true,
) {
  require(token.isDefined || tokenFile.isDefined, "one of token or token-file must be set")

  def transitUrl: String = s"${address.stripSuffix("/")}/v1/${mountPath.stripPrefix("/").stripSuffix("/")}"
}

object OpenBaoKmsConfig {

  /** BAO_ADDR / BAO_TOKEN (or the VAULT_* equivalents), BAO_TRANSIT_MOUNT, BAO_CACERT. */
  def fromEnvironment(): OpenBaoKmsConfig = {
    def env(name: String): Option[String] =
      sys.env.get(s"BAO_$name").orElse(sys.env.get(s"VAULT_$name")).filter(_.nonEmpty)
    OpenBaoKmsConfig(
      address = env("ADDR").getOrElse(throw new IllegalArgumentException("BAO_ADDR is required")),
      token = env("TOKEN"),
      tokenFile = env("TOKEN_FILE"),
      mountPath = env("TRANSIT_MOUNT").getOrElse("transit"),
      namespace = env("NAMESPACE"),
      caCertFile = env("CACERT"),
    )
  }
}
