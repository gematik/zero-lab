# ti-hsm-proxy

The HSM proxy sidecar of a workload of the gematik Telematikinfrastruktur (TI): gematik's
HSM proxy interface (`gematik.zetaguard.hsmproxy.v1.HsmProxyService`, gemSpec_ZETA A_28829)
on a Unix socket, every key reached over PKCS#11 alone. The workload reaches its key through
the sidecar; the vendor's library is never in the workload's image
([servers](../../docs/design/servers.md), rule 6). A software token in development and a
vendor's module in production get the same calls.

Three layers in one crate, each usable without the next:

| Layer | What | Depends on |
|---|---|---|
| PKCS#11 adapter | `Module`, `Token`, `Pool`: load a module, log in, find or make keys by label, sign, encrypt, decrypt, a fixed pool of sessions | `cryptoki` |
| Operations | `HsmProxy`: the six operations of the interface without a transport, the keys it was told to serve, refusals as `Failure` | the adapter, the PEM/DER/JWK encoders |
| Transports | `transport`: the listener (Unix socket, TCP with own TLS or mTLS, TCP in plaintext the operator accepts) and its TLS; `transport::grpc`, behind the `grpc` feature (on by default): `HsmProxyService` and `grpc.health.v1`, the probe of `hsm-proxy health` | tokio, rustls; tonic, prost |

The gRPC code is generated from `proto/` by `just hsm-proxy-codegen` and committed, so a
build needs neither protoc nor prost-build; `just check` fails if it is stale. The sidecar
compiles the server only; the client is generated apart, into `tests/generated`, for the
tests.

## Running

```console
just hsm-proxy-simulator   # the sidecar in the simulator mode on a fresh SoftHSM2 token, one command
just hsm-proxy-softhsm2    # the token and the gRPC suites against SoftHSM2 2.7, or TI_HSM_PKCS11_MODULE_PATH
just hsm-proxy-codegen     # regenerate src/generated and tests/generated from proto/
```

Features:

| Feature | Default | What it adds | Where |
|---|---|---|---|
| `transport` | with `grpc` | what every transport shares: the listener (Unix, TLS, plaintext) and the TLS on rustls | every build that serves |
| `grpc` | on | the gRPC transport and `hsm-proxy health` | every build that serves |
| `simulator` | off | `HSM_PROXY_SIMULATOR`: a software token provisioned with TEST-ONLY PINs, missing keys made | the development image only |
| `conformance` | off | the probes the token suite asks a token with: a misuse it must refuse, a secret value it must not give out, a given GCM IV | the test suite only |

A production build has neither `simulator` nor `conformance` (servers.md rule 17); without
`simulator`, `HSM_PROXY_SIMULATOR=true` stops the start.

The binary `hsm-proxy` is configured by its environment:

| Variable | Meaning |
|---|---|
| `HSM_PROXY_LISTEN_URL` | where it listens, the scheme is the mode (servers.md rule 29): `unix:///absolute/path` inside the pod; `https://host:port` with its own TLS; `http://127.0.0.1:port` (or `[::1]`) on loopback inside the pod, plaintext without acceptance, as gematik's Java provider and ngx_pep's ossl_hsm need; `http://host:port` elsewhere in plaintext the operator accepts |
| `HSM_PROXY_LISTEN_TLS_CERT_PATH`, `_KEY_PATH` | for `https://`: the certificate chain and key, PEM, read at start; a key that does not match, or a certificate not valid now, stops the start |
| `HSM_PROXY_LISTEN_TLS_CA_PATH`, `_PEER_NAME` | for mTLS: the client CA bundle, and the identities admitted, DNS names or URIs (SPIFFE IDs), comma-separated; one without the other stops the start |
| `HSM_PROXY_LISTEN_PLAINTEXT_ACCEPTED` | for `http://` on an address other than loopback (refused on loopback, which accepts nothing): `true` is the operator's statement that the deployment protects the connection and decides who calls; the sidecar then neither encrypts nor checks the caller. Unset, plaintext stops the start; any other value too |
| `HSM_PROXY_PKCS11_MODULE_PATH` | the PKCS#11 module |
| `HSM_PROXY_PKCS11_MODULE_SHA256` | its SHA-256 in hex, checked before it is loaded (rule 7); required outside the simulator mode |
| `HSM_PROXY_TOKEN_LABEL` | the token |
| `HSM_PROXY_USER_PIN_PATH` | a file with the user PIN; required outside the simulator mode |
| `HSM_PROXY_KEYS_PATH` | the keys to serve: `{"keys": [{"key_id": "…", "kind": "ecdsa-p256"}]}`, kinds `ecdsa-p256`, `ecdsa-p384`, `aes-256-gcm` |
| `HSM_PROXY_GCM_IV` | `random` (C_GenerateRandom, which SoftHSM2 needs) or `token` (an HSM that makes the IV, as in FIPS mode); required outside the simulator mode |
| `HSM_PROXY_SESSIONS` | sessions on the token, default 4 |
| `HSM_PROXY_SESSION_WAIT_MS` | how long a call waits for a free session before UNAVAILABLE, default 2000 |
| `HSM_PROXY_HEALTH_INTERVAL_MS` | how often `grpc.health.v1` asks the token, default 5000 |
| `HSM_PROXY_SIMULATOR_SEED_PATH` | in the simulator mode: a file of at least 16 bytes whose SHA-256 is the seed missing keys are derived from (HKDF-SHA256 over the seed, the kind and the `key_id`) and put on the token, so that every run and replica with the seed has the same keys; without it they are made at random. TEST-ONLY: a derived key is as secret as the seed |
| `HSM_PROXY_SIMULATOR` | `true`, in a build with the feature `simulator`: the token is provisioned if it is not, with TEST-ONLY PINs, and missing keys are made. Each process gets a token directory of its own: two that start at once on one directory can each make a missing key, which leaves two keys under one label |

Outside the simulator mode a key of the list that is not on the token stops the start; a
vendor's HSM is provisioned by its own tools.

## Images

Two Dockerfiles, built from `rust/`, on base images pinned by digest:

| File | What it holds | For |
|---|---|---|
| [`Dockerfile`](Dockerfile) | the binary on `gcr.io/distroless/cc` (glibc), no module, no simulator | production: the vendor's module is mounted read-only and named with its SHA-256 |
| [`Dockerfile.simulator`](Dockerfile.simulator) | the binary with `simulator`, SoftHSM2 2.7.0 built from source, `HSM_PROXY_SIMULATOR=true` | development and tests only |

```console
docker build -f ti-hsm-proxy/Dockerfile -t hsm-proxy .
docker build -f ti-hsm-proxy/Dockerfile.simulator -t hsm-proxy-simulator .
```

The image runs under any UID with group 0 and a read-only root filesystem (servers.md rule
27); it writes only the socket's directory and, in the simulator, `/var/lib/softhsm/tokens`,
each an `emptyDir` or tmpfs. Dynamic linking is the one exception to rule 4, for `dlopen` of
the module.

## Health in a pod

A kubelet's gRPC and HTTP probes reach a port, not a Unix socket, and its gRPC probe speaks
no TLS, so the probes are `exec` probes of the binary itself, which needs no shell. On a TCP
listener the sidecar serves `grpc.health.v1` alone on a Unix socket in the temporary
directory (`$TMPDIR/hsm-proxy-health.sock`) for them; over mTLS, `grpc.health.v1` on the
listener answers without a client certificate, and every call of the interface needs one
of the allowlist:

- `hsm-proxy health ready` exits 0 if `grpc.health.v1` reports SERVING. The sidecar asks
  the token every `HSM_PROXY_HEALTH_INTERVAL_MS` and reports SERVING or NOT_SERVING; every
  session being busy counts as SERVING. A probe reads that state and never takes a session.
- `hsm-proxy health live` exits 0 if the socket answers at all. A restart does not bring
  back an HSM, so liveness does not ask the token.

```yaml
initContainers:
  - name: hsm-proxy
    restartPolicy: Always    # a native sidecar: the workload starts once the startup probe passes
    startupProbe:   { exec: { command: ["/hsm-proxy", "health", "ready"] }, periodSeconds: 1, failureThreshold: 30 }
    readinessProbe: { exec: { command: ["/hsm-proxy", "health", "ready"] }, periodSeconds: 10 }
    livenessProbe:  { exec: { command: ["/hsm-proxy", "health", "live"] },  periodSeconds: 20 }
```

A session the token lost (a restart, a logout) is replaced and its key found again by its
label; the call that met the loss is tried once more. A key found on the token is served
only if it is of the kind listed and sensitive and not extractable; a certificate only if
it certifies the key that signs.

Not here yet: access by component and `key_id` (A_28830) beyond the listener's allowlist,
a peer check on the socket (rule 8), metrics and a log line on a change of health (rule 31), certificate chains
beyond the end entity, P-521 and the brainpool curves in the interface, fuzz targets for
the keys file and the public point (TASK-397).

## Attestation to the HSM

gemSpec_ZETA A_28747 lets the ZETA keys be used only through an HSM proxy that is either
attested to the HSM, or paired with it in a documented key ceremony with access credentials
exclusive to the proxy; paired, A_28814 asks the proxy to seal those credentials so that only a
correctly started proxy has them after a restart. The sidecar takes the pairing: it needs no code
in the HSM and works with every vendor and with SoftHSM2. Sealing its credentials is not done yet
(TASK-403): today the PIN is a file.

Attested to the HSM means code inside the HSM that checks an attestation before a key is used.
What was found on 2026-11-20 (specifications checked through gemspec; the rest from the vendors'
public pages):

| Where | Attestation checked inside the HSM | Source |
|---|---|---|
| ePA für alle, Aktensystem | required: the VAU-Token-Modul runs only in the VAU-HSM and checks the attestation token and that VAU software and hardware are known to the HSM, fresh and replay-proof; the reference hashes come in under four eyes with gematik | gemSpec_Aktensystem_ePAfueralle 1.8.2 A_25281, A_25282-05, A_24667, A_24611-09, A_24612-07 |
| PoPP-Service | required: the HSM validates VAU images and tells PoPP and **ZETA Guard** images apart | gemSpec_PoPP_Service 1.1.0 A_26602 |
| E-Rezept Fachdienst | the specification asks for technical means only (A_19713); IBM's public `eRP-FD/vau-hsm` is a C firmware module for Utimaco CryptoServer that checks TPM 2.0 quotes covering secure boot and the SGX enclave, enrolled in a ceremony with gematik | gemSpec_FD_eRp 2.6.0; github.com/eRP-FD/vau-hsm |
| ePA SGD | a firmware module, evaluated for gematik, that checks certificates, not attestation | gemSpec_SGD_ePA 1.6.0 A_17907, A_17917 |
| ZETA HSM proxy, HCC, NCPeH | not required: attestation is checked in front of the HSM by a paired component | gemSpec_ZETA A_28747, A_28814; gemSpec_HCC A_29099, A_29102; NCPeH A_28104 |

So a ZETA Guard needs the HSM to check images only where it runs inside a PoPP-Service
(A_26602); that is vendor code, not something the sidecar or SoftHSM2 can provide.

| HSM | Code inside it | Can make a key usable only after a check | Simulator that runs that code |
|---|---|---|---|
| Utimaco CryptoServer, u.trust GP | firmware modules (SDK, C) | yes, a module that holds the key; the module leaves FIPS mode | yes, the SDK's: Linux i386 or Windows, no arm64, test and evaluation only |
| Entrust nShield 5 | CodeSafe 5 (SEE) | yes, a key's ACL binds it to the signed image; FIPS unaffected by Entrust's statement | none found |
| Thales Luna | Functionality Modules | only through its own commands; PKCS#11 cannot be intercepted; not FIPS | none ("no emulation mode") |
| Thales ProtectServer | Functionality Modules | yes, PKCS#11 can be patched | an emulation behind the customer portal |
| Azure, AWS, Google | none | a service policy outside the HSM only | — |
| SoftHSM2, Kryoptic | no extension point | only by patching the token | — |

Open: the HSMs and attestation formats of the ePA systems; whether any TI HSM checks AMD SEV-SNP
or Intel TDX evidence directly; how gematik weighs an HSM running such a module against the FIPS
or CC certificate it requires.

## Simulator token and ngx_pep's hsm_sim

The simulator mode brings SoftHSM2 2.7.0, built from source (maintainer, 2026-11-20). Kryoptic
was weighed and not taken: its token has no brainpool curves, macOS is untested upstream, its
default build does not build on Debian bookworm, and fixes for sensitive keys were not yet in a
release.

ngx_pep's `hsm_sim` stays beside the sidecar; the choice is ngx_pep's. `hsm-proxy` in the
simulator mode serves the same interface and can stand in for it, with these differences:

| | `hsm_sim` | `hsm-proxy`, simulator mode |
|---|---|---|
| Keys | derived from the `key_id` by HKDF, the curve from its suffix (`.p256`, …), so every replica has the same key | listed in `HSM_PROXY_KEYS_PATH` with their kind; made on the token at random, or derived from `HSM_PROXY_SIMULATOR_SEED_PATH` and put on it, the same in every replica |
| Way to the key | in process, OpenSSL | PKCS#11, as with a vendor's HSM |
| Listener | TCP, TLS optional | Unix socket, or TCP with own TLS/mTLS or in plaintext the operator accepts |
| Certificates | issued by a configured CA | the one the token keeps under the key's label, if any |

How an operator brings a vendor's module into the pod, what the image holds and what was
verified of each vendor's terms is in [docs/operating.md](docs/operating.md).

What SoftHSM2 does on this path, its throughput and the transport comparison are in
[docs/softhsm2.md](docs/softhsm2.md).

`publish = false`; the crate is not released.
