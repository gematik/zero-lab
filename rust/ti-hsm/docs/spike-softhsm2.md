# Spike: the PKCS#11 path through SoftHSM2

TASK-389, step 1, 2026-11-19. The sidecar's way to a key is PKCS#11 alone; this spike drives it
through SoftHSM2 and records what the token did. Every statement below is an assertion of
[`tests/spike_softhsm2.rs`](../tests/spike_softhsm2.rs), run with `just hsm-spike`.

## Setup

| | |
|---|---|
| Token | SoftHSM2 2.7.0 (Homebrew), `C_GetInfo`: "Implementation of PKCS11 2.7", interface PKCS#11 3.2 |
| Host | macOS on arm64 (Apple Silicon), natively |
| Binding | `cryptoki` 0.12.1, approved 2026-11-19 |
| Token store | a fresh temporary directory per run (`SOFTHSM2_CONF`), provisioned by the suite with TEST-ONLY PINs |
| Second opinion | signatures verified with the RustCrypto verifiers ti-pki uses (`ecdsa`, `p256`, `p384`, `bp256`), digests with `sha2` |

## What worked as specified

| Area | Finding | Test |
|---|---|---|
| Mechanisms | `CKM_EC_KEY_PAIR_GEN`, `CKM_AES_KEY_GEN`, `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512`, `CKM_AES_GCM` are listed | `task_389_7_the_token_lists_the_mechanisms_the_interface_needs` |
| Signing key | made on the token with `CKA_SENSITIVE`, `CKA_EXTRACTABLE` false; reads back `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` true, `CKA_SIGN` true, `CKA_DECRYPT`, `CKA_UNWRAP`, `CKA_DERIVE` false | `task_389_4_a_signing_key_stays_on_the_token_and_only_signs` |
| Use of a signing key for encryption | refused, `CKR_KEY_FUNCTION_NOT_PERMITTED` | same |
| Key-encryption key | AES-256 made with `CKA_ENCRYPT` and `CKA_DECRYPT` only; reads back sensitive and never extractable, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_SIGN`, `CKA_DERIVE` false; its `CKA_VALUE` is not given out; signing with it is refused, `CKR_KEY_FUNCTION_NOT_PERMITTED` | `task_389_4_a_key_encryption_key_stays_on_the_token_and_only_encrypts_and_decrypts` |
| ECDSA over a digest | `CKM_ECDSA` on P-256 (SHA-256 digest) and P-384 (SHA-384 digest) returns r and s of the field length (64, 96 bytes), which verify with another implementation | `task_389_5_a_signature_over_a_digest_verifies_with_another_implementation` |
| ECDSA over a message | `CKM_ECDSA_SHA256`, `_SHA384`, `_SHA512` on P-256 and P-384, each combination verified with another implementation | `task_389_5_a_signature_over_a_message_verifies_with_another_implementation` |
| brainpoolP256r1 | keys made and signed with, over a digest and a message; verified with `bp256`. The open question of the task ("brainpool not confirmed") is answered for this build | `task_389_5_brainpool_p256r1_is_a_curve_this_token_signs_on` |
| AES-GCM | single-part `C_Encrypt` and `C_Decrypt` with a 12-byte IV and a 128-bit tag appended to the ciphertext; with associated data, without, and for an empty plaintext | `task_389_5_aes_gcm_authenticates_the_associated_data` |
| AES-GCM refusals | another associated data, a changed tag, a changed ciphertext: `CKR_ENCRYPTED_DATA_INVALID` | same |
| Keys by label | a key asked for and not there is made as a token object; asked for again, in this or another session, it is the same key; the same label on another curve is refused, not a second key | `task_389_3_a_key_asked_for_is_made_once_and_found_again` |
| `CKA_EC_POINT` | DER-wrapped in an OCTET STRING, as PKCS#11 specifies; the adapter returns the uncompressed SEC1 point and also takes the bare point some modules return | `task_389_7_the_public_point_is_der_wrapped_and_unwrapped_for_the_caller` |
| Errors | name the operation, the key's label and the return code (`decrypt with key …: PKCS#11 EncryptedDataInvalid`), and no data | `task_389_an_error_names_the_operation_the_key_and_the_return_code` |
| Session pool | a key found through one session signs through every other (one handle in all sessions of the application); 8 threads share 3 sessions, every signature verifies | `task_389_a_pool_lends_its_sessions_to_callers_on_several_threads` |
| Bounded wait | a caller that finds no free session within its wait gets `Error::Busy`, not a place in an unbounded queue | `task_389_a_caller_waits_for_a_session_only_as_long_as_it_says` |

## What did not, or differs from other tokens

- **SoftHSM2 does not make the GCM IV.** Handed a zeroed IV buffer it encrypts under the zero IV
  and leaves the buffer as it was. HSMs in FIPS mode do the opposite and ignore or overwrite the
  IV given. The adapter therefore has `Iv::Random` (from `C_GenerateRandom`, passed in) for
  SoftHSM2 and `Iv::FromToken` for those HSMs, and refuses a result whose IV came back
  unchanged, so a ciphertext under a fixed IV is never handed out. Which one a module needs is
  configuration of the sidecar, and the conformance suite has to find it per module (TASK-389
  #5). The interface allows both, since `Encrypt` returns the IV.
- **`CKA_VALUE` of a sensitive key** is answered with `CKR_ATTRIBUTE_SENSITIVE`, which cryptoki
  0.12 reports as an absent attribute, not as an error. The suite checks that no value comes
  back, not the return code.
- **`CKA_ENCRYPT` and `CKA_WRAP` of a private EC key** are not reported by SoftHSM2. The key
  was made with neither set; that it cannot encrypt is shown by the refusal, not by the
  attribute.
- **A digest of the wrong length** is never sent: the adapter refuses it, as the interface
  requires the digest to have the curve's length. What SoftHSM2 does with one was not tried.

## Throughput

[`benches/softhsm2.rs`](../benches/softhsm2.rs), run with `just hsm-bench`, 2026-11-19, on an
Apple M3 Pro (12 CPUs), SoftHSM2 2.7.0, 2 s per row. One caller per session unless stated.
The JSON-RPC rows send JSON-RPC 2.0 over a Unix socket. Every call goes over one connection,
with as many calls in flight as there are sessions. The server hands each call to a worker per
session and answers in the order the calls finish. Client and server share the machine's
CPUs with the token.

| Operation | Sessions | ops/s | p50 µs | p99 µs |
|---|---|---|---|---|
| ECDSA P-256, direct | 1 | 15 700 | 61 | 110 |
| ECDSA P-256, direct | 2 | 28 600 | 69 | 88 |
| ECDSA P-256, direct | 12 | 24 900 | 492 | 893 |
| ECDSA P-256, direct, 12 callers | 1 | 14 800 | 68 | 78 |
| ECDSA P-256, a key per caller | 12 | 25 800 | 450 | 631 |
| ECDSA P-384, direct | 1 | 6 100 | 163 | 185 |
| ECDSA P-384, direct | 8 | 28 000 | 284 | 409 |
| AES-256-GCM 1 KiB, direct | 2 | 35 100 | 54 | 84 |
| AES-256-GCM 1 KiB, direct | 12 | 28 800 | 79 | 2 538 |
| ECDSA P-256, JSON-RPC | 1 | 12 000 | 81 | 91 |
| ECDSA P-256, JSON-RPC | 4 | 24 000 | 165 | 218 |
| ECDSA P-256, JSON-RPC | 12 | 23 900 | 505 | 897 |
| `ping` (no token), JSON-RPC | 1 | 85 700 | 9 | 14 |
| `ping` (no token), JSON-RPC | 12 | 286 500 | 29 | 90 |

- **Sessions are what makes calls parallel.** Twelve callers on one session get what one
  caller gets. The callers queue for the session, and the pool's latency is the queue.
- **SoftHSM2 stops scaling at 25 000 to 35 000 operations a second.** That holds whatever the
  operation, and it holds as well with a key per caller. So it is a limit of the whole module,
  not of one key. Its cause was not investigated. Above that point, more sessions only make
  each call wait longer. A vendor's HSM has limits of its own, and the pool's size is set to
  them.
- **The transport is not the bottleneck.** JSON-RPC adds about 20 µs to each call. That
  matters only with a single call in flight (12 000 against 15 700 a second). From 4 calls in
  flight on, signing through JSON-RPC is as fast as signing directly. With no token behind
  it, one connection carries 85 000 to 290 000 calls a second. That is ten times what
  SoftHSM2 does, and far more again than a network HSM with its millisecond round trips.

## Transport: JSON-RPC against gRPC

2026-11-19, for the open decision of TASK-389 (AC #1). gemSpec_ZETA V2.0.0_CC settles the
interface. A_28829 (Kap. 5.11 HSM Proxy) requires `hsm-proxy.proto`, which is gRPC. A_28830
requires that the calling components can be authenticated with mTLS. A_28816 (Kap. 5.11.1)
requires a minimal trusted computing base: "DARF NICHT mehr Komponenten enthalten als für die
Bereitstellung der HSM-Proxy-Funktionalität erforderlich". The comparison below shows what
the required transport costs. The question to gematik is in zeta-backlog TASK-18.

### Software bill of materials

Two throwaway crates were resolved against this workspace's lock file: `ti-hsm` with JSON-RPC
(`serde`, `serde_json`, `base64ct`), and `ti-hsm` with a gRPC server on a Unix socket (`tonic`
0.14 with `server`, `router` and `codegen`, `tonic-prost`, `prost`, `tonic-health`, `tokio`,
`tokio-stream`, build dependency `tonic-prost-build`). Neither has TLS: mTLS (A_28830) would
add rustls and its crypto provider to both. The SBOMs are CycloneDX 1.6 for
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. They were made from
`cargo metadata`, not checked against the CycloneDX schema, and not committed.

| | JSON-RPC | gRPC |
|---|---|---|
| Crates at run time | 17 | 61 |
| of them new to this workspace | 0 | 36 |
| Crates at build time only | 6 | 38 |
| of them new to this workspace | 0 | 28 |
| Tool | none | `protoc`, or generated code committed |
| Licences | MIT, Apache-2.0, ISC, Unlicense, Unicode-3.0, all compatible with EUPL-1.2 | the same, and BSD-3-Clause, Zlib |

- **Both have these 13 crates at run time:** `ti-hsm`, `cryptoki`, `cryptoki-sys`,
  `libloading`, `secrecy`, `thiserror`, `zeroize`, `bitflags`, `cfg-if`, `itoa`, `log`,
  `memchr` and `serde_core`.
- **JSON-RPC adds four:** `serde`, `serde_json`, `zmij` and `base64ct`.
- **gRPC adds 48, these among them:** `tokio`, `mio`, `socket2`, `libc`, `hyper`,
  `hyper-util`, `h2`, `http`, `httparse`, `axum`, `axum-core`, `tower`, `tracing`, `bytes`,
  `futures-*`, `prost`, `tonic`, `tonic-health` and `tonic-prost`.

### Throughput

Each server ran as its own process with n sessions and signed a P-256 digest. One connection
carried n calls at once. The `HealthCheck` rows do not use the token, so they measure the
transport alone. The gRPC server uses the route `gematik.zetaguard.hsmproxy.v1.HsmProxyService/Sign`
with the field numbers of the proto. Its messages were written with prost by hand, to need no
`protoc`. A `Sign` call runs on tokio's blocking pool, and the client is tonic on one HTTP/2
channel. The JSON-RPC server is a plain reader thread with a worker per session, its client
the one from the benchmark. The test machine was an M3 Pro with 12 CPUs, running SoftHSM2
2.7.0, 3 s per row. Client, server and token share the CPUs. The setup is in the scratch
harness of TASK-389, which is not committed, because it would bring tonic into this workspace.

| Call | n | JSON-RPC ops/s | gRPC ops/s | p50 µs JSON / gRPC | p99 µs JSON / gRPC |
|---|---|---|---|---|---|
| Sign | 1 | 11 600 | 9 900 | 82 / 99 | 97 / 118 |
| Sign | 2 | 20 000 | 17 200 | 96 / 116 | 109 / 133 |
| Sign | 4 | 25 000 | 25 300 | 158 / 157 | 256 / 207 |
| Sign | 12 | 25 300 | 25 300 | 465 / 474 | 1 463 / 845 |
| HealthCheck | 1 | 78 800 | 45 400 | 10 / 21 | 14 / 34 |
| HealthCheck | 4 | 190 700 | 78 200 | 16 / 48 | 27 / 94 |
| HealthCheck | 12 | 277 100 | 82 100 | 30 / 142 | 84 / 265 |

| | JSON-RPC | gRPC |
|---|---|---|
| Server CPU time per `Sign`, SoftHSM2 included | 80–109 µs | 94–124 µs |
| Server CPU time per `HealthCheck` | 7–15 µs | 10–23 µs |
| Client CPU time per call | 4–9 µs | 20–40 µs |
| Server binary, stripped, fat LTO, macOS arm64 | 0.5 MB | 1.2 MB |
| Server resident memory | 6–7 MiB | 7–9 MiB |

- **The token bounds signing, not the transport.** From 4 calls in flight on, both protocols
  sign as fast as SoftHSM2 allows, about 25 000 a second. With one call in flight, gRPC adds
  about 17 µs to each.
- **gRPC costs more per call.** One connection carries about 82 000 calls a second over gRPC,
  against 277 000 over JSON-RPC. gRPC also takes about 15 µs more server CPU time per call.
  At 25 000 signatures a second that is 0.4 of a core. Against a network HSM's round trip of
  1 to 5 ms it does not matter.
- **gRPC's p99 under load is better** (845 against 1 463 µs at n = 12). The JSON-RPC server
  shares one queue and one write lock among its workers, where tokio schedules more fairly.
  That is a matter of the measured server, not of the protocol, but it was not tried.
- **Not measured:** Linux, mTLS, tuning of tonic and h2, and the clients there are (Go's
  gRPC in zeta-pdp-go, ngx_pep).

## Not covered by the spike

- The gRPC interface and the sidecar (decided after this spike, maintainer 2026-11-19).
- Multi-part signing and encryption (`C_SignUpdate`): single-part only, which every operation
  of the interface needs; some HSMs do raw `CKM_ECDSA` single-part only.
- Linux and x86_64: run only on macOS arm64 so far.
- Deterministic keys for tests that compare output (TASK-389 #3): SoftHSM2 makes keys from its
  own random source; output is comparable only through a given IV, not a given key.
- Kryoptic, NSS softokn and every vendor's module.
- A broken session, or a token that logs the application out: the pool does not reopen
  sessions or log in again. A session is lost if an operation panics.
