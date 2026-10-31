# OpenBao / Vault Transit KMS driver for Canton

A [Canton KMS driver](https://docs.canton.network/global-synchronizer/reference/kms-driver-guide)
that keeps a participant's keys in the **Transit secrets engine** of
[OpenBao](https://openbao.org) or HashiCorp Vault. Keys are generated inside OpenBao, are
created non-exportable, and never leave it: Canton sends data to sign or decrypt and gets
the result back.

Canton ships built-in support for AWS KMS and Google Cloud KMS only. This driver lets an
operator on any other provider, on premises, or on their own hardware follow the Canton
Foundation's advice to keep validator keys in a KMS, using a key service they run themselves.

Status: passes DA's driver test suite (`com.daml %% kms-driver-testing` 3.6.4), over plain HTTP
and over TLS with a private CA, and runs a
Canton 3.6.4 participant end to end. Not yet run in production.

## Supported keys

| Canton | Transit key type |
|---|---|
| Signing `EcCurve25519` / `Ed25519` | `ed25519` |
| Signing `EcP256` / `EcDsaSha256` | `ecdsa-p256` |
| Signing `EcP384` / `EcDsaSha384` | `ecdsa-p384` |
| Encryption `Rsa2048` / `RsaEsOaepSha256` | `rsa-2048` |
| Symmetric (KMS-managed) | `aes256-gcm96` |

The Canton key id is the Transit key name. Every asymmetric operation is pinned to key
**version 1**: Canton registers the public key it reads at creation and rotates by creating
new keys, so **do not rotate these keys in OpenBao**.

## Security model

- Keys are created with `exportable=false` and `allow_plaintext_backup=false`, so the API
  will not hand them out. They are used in OpenBao's memory and stored encrypted under its seal.
- OpenBao is not an HSM. Anyone with root on the OpenBao host could in principle reach key
  material. Run OpenBao on separate hosts from the participant, with audit logging, and choose
  the seal deliberately: auto-unseal through a cloud KMS or an HSM moves the root of trust there.
- Enable Canton's session signing keys (below). The trade-off, per the Canton docs, is that a
  memory snapshot of the participant exposes a session key for its lifetime.

## Get the driver

Download `canton-kms-driver-openbao-<version>.jar` and its `.sha256` from
[Releases](../../releases), and check it: `sha256sum -c canton-kms-driver-openbao-<version>.jar.sha256`.

Or build it: `sbt assembly` writes `target/scala-2.13/canton-kms-driver-openbao-0.1.0-SNAPSHOT.jar`.

The JAR is thin: Scala, circe, sttp, pureconfig and logback come from Canton at runtime and
`build.sbt` pins them to the versions Canton 3.6.4 ships. Use a driver release built for your
Canton minor version.

## OpenBao setup

```bash
bao secrets enable transit
bao policy write canton-participant - <<'EOF'
path "transit/keys/*"        { capabilities = ["create", "read", "update", "delete"] }
path "transit/keys/+/config" { capabilities = ["update"] }   # only needed for key deletion
path "transit/sign/*"        { capabilities = ["update"] }
path "transit/encrypt/*"     { capabilities = ["update"] }
path "transit/decrypt/*"     { capabilities = ["update"] }
EOF
bao token create -policy=canton-participant -period=768h
```

`auth/token/lookup-self` (in OpenBao's default policy) is used by the health check. For a
participant that must never delete keys, drop the `config`/`delete` grants and set
`allow-deletion = false`.

## Canton configuration

```hocon
canton.participants.participant.crypto.provider = kms
canton.participants.participant.crypto.kms {
  type = driver
  name = "openbao"
  config {
    address = "https://openbao.internal:8200"
    token-file = "/var/run/secrets/openbao/token"   # or: token = ${BAO_TOKEN}
    # mount-path = "transit"
    # namespace = "canton"                           # Vault Enterprise / OpenBao namespaces
    # ca-cert-file = "/var/run/secrets/openbao/ca.pem"
    # allow-deletion = true
  }
}
canton.participants.participant.crypto.session-signing-keys.enabled = true
```

`token-file` is re-read on every request, so a renewed token is picked up without a restart.

## Splice / Kubernetes

No custom image is needed. The Splice participant image's `bin/canton` appends
`EXTRA_CLASSPATH` to Canton's class path, so mount the JAR and point that variable at it.
The JAR is small enough (about 250 KB) to ship as a ConfigMap:

```bash
kubectl -n <namespace> create configmap canton-kms-driver \
  --from-file=driver.jar=canton-kms-driver-openbao-<version>.jar
kubectl -n <namespace> create secret generic openbao-canton \
  --from-file=token=<token-file> --from-file=ca.pem=<openbao-ca.pem>
```

Then, in the `splice-participant` Helm values. `.Values.kms` maps to Canton's `crypto.kms`,
camelCase keys become kebab-case, and **values are written into HOCON unquoted**, so quote
strings inside the YAML string: an unquoted `https://...` is read by HOCON as `https:`
followed by a `//` comment.

```yaml
kms:
  type: driver
  name: openbao
  config:
    address: '"https://openbao.internal:8200"'
    tokenFile: '"/var/run/secrets/openbao/token"'
    caCertFile: '"/var/run/secrets/openbao/ca.pem"'
additionalEnvVars:
  - name: EXTRA_CLASSPATH
    value: /opt/canton-kms/driver.jar
  - name: ADDITIONAL_CONFIG_SESSION_SIGNING_KEYS
    value: canton.participants.participant.crypto.session-signing-keys.enabled = true
extraVolumes:
  - name: kms-driver
    configMap:
      name: canton-kms-driver
  - name: openbao
    secret:
      secretName: openbao-canton
extraVolumeMounts:
  - name: kms-driver
    mountPath: /opt/canton-kms
  - name: openbao
    mountPath: /var/run/secrets/openbao
```

Checked: the official Splice 0.9.4 participant image
(`ghcr.io/digital-asset/decentralized-canton-sync/docker/canton-participant:0.9.4`) loads the
driver through `EXTRA_CLASSPATH`, creates its keys in OpenBao, and masks the token in its
config dump; `helm template` of `splice-participant` 0.9.4 renders the values above to the
intended HOCON. Not yet installed through the chart in a cluster.

A KMS participant must be a fresh participant: Canton cannot move an existing participant's
keys into a KMS (see the Canton Foundation's
[validator security guide](https://docs.canton.network/global-synchronizer/production-operations/validator-security)).

## Tests

Unit tests run with no server. DA's suite and the factory test need OpenBao (or Vault) and
are cancelled without it:

```bash
docker run -d --name openbao-dev -p 127.0.0.1:8200:8200 quay.io/openbao/openbao \
  server -dev -dev-root-token-id=devroot -dev-listen-address=0.0.0.0:8200
curl -s -H 'X-Vault-Token: devroot' -X POST http://127.0.0.1:8200/v1/sys/mounts/transit -d '{"type":"transit"}'
BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=devroot sbt test
```

The `VAULT_*` variable names work too.

## License

Apache-2.0
