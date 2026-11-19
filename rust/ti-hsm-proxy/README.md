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
| gRPC transport | `grpc`, behind the `grpc` feature (on by default): `HsmProxyService` and `grpc.health.v1` on a Unix socket, the probe of `hsm-proxy health` | tonic, prost, tokio |

The gRPC code is generated from `proto/` by `just hsm-proxy-codegen` and committed, so a
build needs neither protoc nor prost-build; `just check` fails if it is stale.

## Running

```console
just hsm-spike    # the spike and the gRPC suite against SoftHSM2 2.7, or TI_HSM_PKCS11_MODULE_PATH
just hsm-bench    # throughput through the pool, direct and over JSON-RPC on a Unix socket
```

The binary `hsm-proxy` is configured by its environment:

| Variable | Meaning |
|---|---|
| `HSM_PROXY_LISTEN_URL` | `unix:///absolute/path` of the socket |
| `HSM_PROXY_PKCS11_MODULE_PATH` | the PKCS#11 module |
| `HSM_PROXY_PKCS11_MODULE_SHA256` | its SHA-256 in hex, checked before it is loaded (rule 7); required outside the simulator mode |
| `HSM_PROXY_TOKEN_LABEL` | the token |
| `HSM_PROXY_USER_PIN_PATH` | a file with the user PIN; required outside the simulator mode |
| `HSM_PROXY_KEYS_PATH` | the keys to serve: `{"keys": [{"key_id": "…", "kind": "ecdsa-p256"}]}`, kinds `ecdsa-p256`, `ecdsa-p384`, `aes-256-gcm` |
| `HSM_PROXY_GCM_IV` | `random` (C_GenerateRandom, which SoftHSM2 needs) or `token` (an HSM that makes the IV, as in FIPS mode); required outside the simulator mode |
| `HSM_PROXY_SESSIONS` | sessions on the token, default 4 |
| `HSM_PROXY_SESSION_WAIT_MS` | how long a call waits for a free session before UNAVAILABLE, default 2000 |
| `HSM_PROXY_HEALTH_INTERVAL_MS` | how often `grpc.health.v1` asks the token, default 5000 |
| `HSM_PROXY_SIMULATOR` | `true`: the token is provisioned if it is not, with TEST-ONLY PINs, and missing keys are made |

Outside the simulator mode a key of the list that is not on the token stops the start; a
vendor's HSM is provisioned by its own tools.

## Health in a pod

A kubelet's gRPC and HTTP probes reach a port, not a Unix socket, so the probes are `exec`
probes of the binary itself, which needs no shell:

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

Not here yet: mTLS and access by component (A_28830), a TCP listener, a peer check on the
socket (rule 8), reopening a broken session, metrics, certificate chains beyond the end
entity, P-521 and the brainpool curves in the interface.

What the spike found of SoftHSM2 is in [docs/spike-softhsm2.md](docs/spike-softhsm2.md).

`publish = false`; the crate is not released.
