# spec/store interoperability matrix

Written by `spec/store/interop/run.sh`: the Go implementation (`go/store`, `go/sqlitestore`)
and the Rust one (`ti_store::store` with `ti`'s backends) on one profile's files, through
`go/sqlitestore/cmd/store-interop` and `ti-cli/examples/store-interop.rs`.

- Run: 2026-10-20T10:10Z on Darwin arm64
- go1.27.3 darwin/arm64, rustc 1.98.1
- Take race: 20 rounds of 8 Go and 8 Rust processes released together

| Backend | Direction | Case | Result |
|---|---|---|---|
| sqlite | go → rust | sealed get (oauth.access) | pass |
| sqlite | go → rust | sealed query by tag (issuer) | pass |
| sqlite | go → rust | sealed query by two tags (issuer, subject) | pass |
| sqlite | go → rust | sealed get (popp) | pass |
| sqlite | go → rust | sealed record without expiry (tsl.state) | pass |
| sqlite | go → rust | plain get (well-known, cache) | pass |
| sqlite | go → rust | take by the other, then gone | pass |
| sqlite | rust → go | sealed get (oauth.access) | pass |
| sqlite | rust → go | sealed query by tag (issuer) | pass |
| sqlite | rust → go | sealed query by two tags (issuer, subject) | pass |
| sqlite | rust → go | sealed get (popp) | pass |
| sqlite | rust → go | sealed record without expiry (tsl.state) | pass |
| sqlite | rust → go | plain get (well-known, cache) | pass |
| sqlite | rust → go | take by the other, then gone | pass |
| sqlite | both | take race: 20 rounds × 16 takers, one winner each | pass |
| sqlite | both | take race winners: go 3, rust 17 | pass |
| files | go → rust | sealed get (oauth.access) | pass |
| files | go → rust | sealed query by tag (issuer) | pass |
| files | go → rust | sealed query by two tags (issuer, subject) | pass |
| files | go → rust | sealed get (popp) | pass |
| files | go → rust | sealed record without expiry (tsl.state) | pass |
| files | go → rust | plain get (well-known, cache) | pass |
| files | go → rust | take by the other, then gone | pass |
| files | rust → go | sealed get (oauth.access) | pass |
| files | rust → go | sealed query by tag (issuer) | pass |
| files | rust → go | sealed query by two tags (issuer, subject) | pass |
| files | rust → go | sealed get (popp) | pass |
| files | rust → go | sealed record without expiry (tsl.state) | pass |
| files | rust → go | plain get (well-known, cache) | pass |
| files | rust → go | take by the other, then gone | pass |
| files | both | take race: 20 rounds × 16 takers, one winner each | pass |
| files | both | take race winners: go 4, rust 16 | pass |
