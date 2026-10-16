# Shared sealed store: conformance

How an implementation of [README.md](README.md) proves conformance: the corpus and its manifest,
the generator, the adapter protocol every implementation provides, and the interoperability matrix.

## Layout

```text
README.md          the requirements (STORE-nnn)
schema.sql         the SQLite schema of format level 1
migrations/        one file per level after the first (none yet)
testdata/
  manifest.json    every case: kind, rules covered, input, expected code and output
tool/              storeconformance: generates the manifest, verifies adapters (Go, stdlib only)
interop/           one adapter per implementation, and matrix.md of the last run (TASK-103.8)
```

## Corpus

The manifest is **generated and committed**. Every input is fixed, so a run of the generator writes
the same bytes; `go test ./...` in `tool/` fails if the committed file is stale. All key material is
derived from labels such as `zl-store TEST-ONLY data key 1` and protects nothing.

The generator writes each case from two sources that must agree: the result code the case states,
taken from the rules, and the tool's reference evaluation of the input. A disagreement stops the
generator. The reference holds keys in ordinary memory and is not an implementation to embed.

| Kind | What it checks | Rules |
|---|---|---|
| `derive` | `k_value`, `k_name`, `k_index` from a data key | E |
| `name`, `tag` | record names and blind-index tags, sealed and plain; syntax and size limits | C, D |
| `seal` | the sealed record a writer produces from fixed key, kid, profile, nonce and payload | F |
| `open` | opening sealed records, and every way one must fail: other profile, id or namespace, flipped tag, ciphertext or nonce, raised `not_after`, swapped or unknown kid, wrong version, truncation, kid syntax | F |
| `plain`, `plain_open` | plain records | F |
| `keyring_write`, `keyring` | the keyring file a writer produces, and reading it with the `key-file` wrapper; wrong KEK, moved profile id, unknown wrapper, structural errors | G |
| `kek_file` | the key-encryption key file and its permissions | J |
| `record_file_write`, `record_file` | record files of the files backend | I |
| `files_meta`, `db_level` | format levels and which implementation may open what | K |
| `profile` | profile name and paths from option, environment, active file and home directory, on Linux, macOS and Windows | J |
| `capabilities` | the capabilities a backend declares | B, H, I |
| `scenario` | a sequence of operations on a fresh backend, compared step by step: put, get, take, delete, batch, query with tags, expiry ranges and paging, cleanup; on indexed backends also 100,000 records | B |

Byte strings are lowercase hex. Integers are below 2^53. A scenario's `fill` step writes records
`name = SHA-256(seed ‖ u32 i)`, `value = u32 i`; its `scan` step pages through a namespace and
answers the count and the SHA-256 of all names in order.

## Adapter protocol

An implementation provides an adapter: a program that reads one request per line on its standard
input and writes one response per line on its standard output, in order, until its input ends.

```json
{"id": "open-basic", "kind": "open", "input": {...}}
{"id": "open-basic", "code": "ok", "output": {...}}
```

- `code` is a [result code](README.md#result-codes); `output` is compared exactly when the expected
  code is `ok` and ignored otherwise.
- An adapter answers `{"id": ..., "code": "unsupported"}` for a kind it does not implement, and for
  a scenario on a backend it does not have. The verifier reports these loudly; with `-strict` they
  fail the run.
- `seal`, `keyring_write` and `record_file_write` take the nonce or other random value from the
  input; an implementation exposes this only to its adapter, never to its callers.
- `profile` is pure: the adapter passes the given environment to the implementation's resolution
  function; it does not touch the real environment.
- A `scenario` runs on a fresh, empty store of the named backend in a temporary directory.

## Running

```sh
cd spec/store/tool
go run . generate                 # rewrite testdata/manifest.json
go run . generate -check          # fail if it is stale
go test ./...                     # manifest current, rules defined, reference passes, verifier rejects
go run . verify -- ADAPTER [ARGS...]
go run . verify -strict -markdown ../interop/matrix.md -name rust -- ADAPTER [ARGS...]
go run . adapter                  # the reference, as an adapter, for comparing answers
```

## Independent check

The vectors of the kinds `derive`, `name`, `tag`, `seal`, `open` and `keyring` were checked on
2026-10-15 with a separate program written from README.md alone, on Node.js 26.11.1 (`node:crypto`:
`hkdfSync`, `createHmac`, `aes-256-gcm`): 44 checks, all in agreement. The program is not
committed; the check is repeated when a rule of sections E, F or G changes.

## Result code mapping

| Code | `go/store` | `ti_store::store` | JVM |
|---|---|---|---|
| `not_found` | `store.ErrNotFound` | `StoreError::NotFound` | TASK-111 |
| `expired` | `store.ErrExpired` | `StoreError::Expired` | |
| `malformed` | `store.ErrMalformed` | `StoreError::Malformed` | |
| `unsupported_version` | `store.ErrUnsupportedVersion` | `StoreError::UnsupportedVersion` | |
| `unknown_kid` | `store.ErrUnknownKid` | `StoreError::UnknownKid` | |
| `auth_failed` | `store.ErrAuthFailed` | `StoreError::AuthFailed` | |
| `limit_exceeded` | `store.ErrLimitExceeded` | `StoreError::LimitExceeded` | |
| `invalid_argument` | `store.ErrInvalidArgument` | `StoreError::InvalidArgument` | |
| `capability_missing` | `store.ErrCapabilityMissing` | `StoreError::CapabilityMissing` | |
| `no_keyring` | `store.ErrNoKeyring` | `StoreError::NoKeyring` | |
| `insecure_permissions` | `store.ErrInsecurePermissions` | `StoreError::InsecurePermissions` | |
| `busy` | `store.ErrBusy` | `StoreError::Busy` | |
| `backend_error` | `store.ErrBackend` | `StoreError::Backend` | |

In Go, `errors.Is(err, store.ErrNotFound)` matches by code and `store.CodeOf(err)` returns
it; in Rust, `StoreError::code` does. The adapters:

```sh
# in spec/store/tool
(cd ../../../go/store && go build -o /tmp/store-conformance ./cmd/store-conformance)
go run . verify -- /tmp/store-conformance
(cd ../../../rust && cargo build -p ti-store --features test-util --example conformance)
go run . verify -- ../../../rust/target/debug/examples/conformance
```

The Go adapter answers every kind but the SQLite backend's scenarios and capabilities;
`go test ./...` in `go/sqlitestore` runs those from the manifest. The Rust adapter answers the kinds of ti-store; the SQLite and files backends
are `ti`'s, and `cargo test -p ti-cli --lib store::` runs their `capabilities` and
`scenario` cases from the manifest.
