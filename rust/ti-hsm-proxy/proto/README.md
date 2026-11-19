# Protocol buffers of the HSM proxy

The contract the sidecar serves, unchanged from where it comes from. `just hsm-proxy-codegen`
generates `src/generated/` from these files; nothing else reads them.

| File | Source | Commit | Licence |
|---|---|---|---|
| `gematik/zetaguard/hsmproxy/v1/hsm-proxy.proto` | [gematik/zeta](https://github.com/gematik/zeta) `src/gRPC/hsm-proxy.proto`, the `[hsm-proxy.proto]` of gemSpec_ZETA A_28829; identical to ngx_pep's `hsm_proto/hsm-proxy.proto` | `49f10d8c1922b5c52a1b67a64df57b57c87c5bc1` (2026-03-17) | Apache-2.0 |
| `google/api/annotations.proto`, `google/api/http.proto` | [googleapis/googleapis](https://github.com/googleapis/googleapis), imported by `hsm-proxy.proto` for its HTTP annotations | `984d83793d5b3461ffdefe4fc81e0112cb6c94fb` | Apache-2.0 |
| `google/rpc/status.proto`, `google/rpc/error_details.proto` | the same; imported by `hsm-proxy.proto`, used by none of its messages | `984d83793d5b3461ffdefe4fc81e0112cb6c94fb` | Apache-2.0 |

Taken 2026-11-19. An update replaces a file whole, from its source, and changes this table.
