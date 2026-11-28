# Naming and configuration

## Identifiers

- Each language's own idiom wins: Rust `snake_case` functions and `CamelCase` types, Go
  `MixedCaps` with initialisms in one case (`ID`, `URL`, `JWK`, `HTTPClient`, never `Id`,
  `Url`); the profiles add what their linters enforce.
- Names follow the specification they implement: gematik names (profiles, certificate
  types, OIDs) as the gemSpec writes them, one naming rule per layer
  ([decision-5](../../backlog/decisions/decision-5%20-%20PKI-naming-follows-gemSpec-one-rule-per-layer.md)).
- Tests are named after the requirement they prove
  ([testing](../design/testing.md#tests-name-the-requirement-they-prove)).

- A Go module and its Rust crate share a name, without the `ti-` prefix and a product
  client's `-client` suffix: `go/idpd` and `ti-idpd-client`, `go/tipki` and `ti-pki`,
  `go/pkcs12` and `ti-pkcs12`. So do what an operator sees of it: `idpd:` in YAML,
  `PEP_IDPD_*`, `/idpd-callback`. `go/brainpool` keeps its name, being wider than
  `ti-jwz`'s brainpool; `go/dpop`, `go/openid`, `go/oidf` have no crate yet.

## Environment variables

- Prefixed by the component that reads them: `ZERO_PDP_…`, `PEP_…`, `EPA_…`, `TI_…`,
  `TI_TEST_…` for test gates.
- A variable that holds a file or directory path ends in `_PATH` or `_DIR`
  (`PEP_SESSION_KEY_PATH`, `GEMATIK_API_TOOLS_DIR`).
- Secrets never travel as a variable's value: the variable names a file (`…_PATH`) and the
  command reads the secret from it. Secrets are not bootstrapped into or stored in the kv
  store either.
- One value stays a variable: the key of gematik's development federation
  (`PDP_OIDF_DEV_API_KEY`, `PEP_OIDF_DEV_API_KEY`). It opens a development environment,
  `*.dev.gematik.solutions`, and nothing else: it signs nothing, names no identity, guards
  no personal data and has no counterpart in test, reference or production. The transport
  sends it only over https to hosts below `.dev.gematik.solutions`, so a deployment
  outside that environment leaves it unset and never sees it.
- Transport ([servers](../design/servers.md), rule 29): a listener or peer is one variable
  that holds its URL, and what its TLS needs hangs on the same name with these suffixes.

  | Suffix | Meaning |
  |---|---|
  | `<COMPONENT>_<NAME>_URL` | Listener or peer URL; the scheme is the mode |
  | `…_TLS_CERT_PATH` | Certificate chain, PEM |
  | `…_TLS_KEY_PATH` | Private key, PEM |
  | `…_TLS_CA_PATH` | CA bundle to verify the other side |
  | `…_TLS_PEER_NAME` | Expected name of a peer, or allowlist for a listener |
  | `…_PLAINTEXT_ACCEPTED` | `true`: the operator accepts a plaintext (`http://`) listener or peer inside the cluster, which the deployment protects (rule 29); unset or any other value, plaintext there is refused |

## Helpers

- A helper is named after the `ti` command group it serves: `ti <group>` becomes
  `ti-<group>-helper`, crate and binary of the same name under `rust/helpers/<group>`;
  its protocol is `<group>/<n>` in `spec/ti-rpc`; its Go client is `go/tirpc/<group>`.
- Methods carry the names of the group's subcommands and the `--format json` schemas of
  `ti`, so a subprocess and a helper return the same shapes.
- `TI_<GROUP>_HELPER_PATH` overrides where a product finds the helper;
  `TI_<GROUP>_HELPER_SOCKET_PATH` names the Unix socket of a sidecar. A helper reads no
  other configuration than its flags and these variables: no profile, configuration
  directory, store, cache file or key file.

## Configuration

- Configuration is read at the edge: the command (or CLI) reads flags, environment and
  files, validates them and hands typed configuration to the libraries, which read
  nothing themselves ([architecture](../architecture.md#sans-io)).
- Environments are data, not behaviour: everything that differs between environments is
  a named field of the configuration, and an environment name only picks a preset.
  Library code never branches on the environment; the one decision code makes is the
  production tier, in one place, which rejects TEST-ONLY anchors and relaxed policies.
- Production refuses insecure configuration at start-up
  ([servers](../design/servers.md), rule 17).

## Paths in a container

A server image finds what it reads, and writes what it writes, in the same places in
Docker Compose, Kubernetes and OpenShift. `<component>` is the binary's name
(`zero-pep-proxy`, `hsm-proxy`). The variables still name each file (`…_PATH`, `…_DIR`).
These are the defaults that charts, Compose files and examples use. No server hard-codes
them. The permissions on each path are [servers](../design/servers.md) rule 27's.

| What | Where | Mounted from |
|---|---|---|
| Configuration that is not secret | `/etc/<component>/` | ConfigMap, read-only |
| A secret: key, password, client secret, API key | `/run/secrets/<component>/<secret>/<key>` | Secret, read-only, one volume per Secret |
| TLS of a listener or peer | `/run/secrets/<component>/<name>-tls/tls.crt`, `tls.key`, `ca.crt` | Secret of type `kubernetes.io/tls` (cert-manager, OpenShift's service CA) |
| CA bundle that is not secret | `/etc/<component>/ca/<name>.crt` | ConfigMap (OpenShift's `inject-cabundle`, trust-manager) |
| TI trust material from the producer (rule 8) | `/etc/telematik/` | volume the producer writes, read-only for consumers |
| PKCS#11 module of the HSM (rule 4) | `/opt/pkcs11/<vendor>/` | the operator's volume, read-only |
| Unix socket shared between containers | `/run/<component>/<name>.sock` | `emptyDir`, shared by the pod's containers |
| State that outlives a restart | `/var/lib/<component>/` | PVC |
| Cache | `/var/cache/<component>/` | `emptyDir` |
| Temporary files | `/tmp` | `emptyDir` |

- **Why these:** they are the Filesystem Hierarchy Standard's places, and Docker
  Compose's own `secrets:` mount under `/run/secrets`. In distroless and most base images
  `/var/run` links to `/run`. A read-only root filesystem (rule 8) then needs a volume
  only at the paths above.
- **Never at `/run/secrets` itself.** Kubernetes mounts the service account's token at
  `/var/run/secrets/kubernetes.io/serviceaccount`. OpenShift adds its service CA
  there. A volume at `/run/secrets` hides both. Each Secret is its own volume one
  level further down.
- **Secrets and configuration apart.** A secret is never in a ConfigMap, in `/etc`
  or in a variable's value. A value that is not secret is never in a Secret either, so
  `kubectl get configmap` shows the whole configuration and nothing that has to be
  rotated.
- **Whole directories, no `subPath`.** A Secret or ConfigMap is mounted as a directory,
  with the key names as file names. A `subPath` mount loses the atomic swap of the
  volume's `..data` link and the ownership OpenShift sets through `fsGroup`. Compose's
  long `secrets:` syntax gives the same file path with `target:`.
- **The volume types `restricted-v2` admits:** `configMap`, `secret`, `projected`,
  `downwardAPI`, `emptyDir`, `persistentVolumeClaim`, `ephemeral` and `csi`. A `hostPath`
  is not among them, and no default needs one. A `projected` volume combines several
  Secrets under one directory where a reader takes one directory.
