# Provenance

Test material for the offline tests (`tests/offline.rs`, `check.rs`, `probe.rs`,
`facades.rs`, `recorded.rs`), `src/sds.rs`' unit tests and the `soap` fuzz target. No
credentials: the recordings hold bodies only.

| File | Source | Version, date | Refresh |
|---|---|---|---|
| `ehex-connector.sds` | Service directory (`connector.sds`) of an eHEX infinity Konnektor, captured by the tests of the Kotlin client (`src/sds.rs`) | Konnektor 6.0.2, firmware 2.0.1; added in 5a427922 (2026-09-27); capture date unknown | Capture `connector.sds` from a Konnektor, replace the file and write its SHA-256 to `ehex-connector.sds.sha256` (`ehex_fixture_is_pinned` checks it) |
| `ehex-connector.sds.sha256` | SHA-256 of `ehex-connector.sds` | with it | `shasum -a 256 ehex-connector.sds` |
| `go-connector.sds`, `go-get-cards.xml`, `go-get-cards-fault.xml` | Fixtures of the Go client's tests, `go/kon/cards_test.go` (hand-written, product `Test`/`TEST`) | added in 5a427922 (2026-09-27); `go/kon` was removed in 1bb297fb (2026-10-10), its last version is in git history | None: kept as they are, so the Rust client stays comparable with what the Go client read |
| `recorded/ehex-6.0.2/` | A session with a real Konnektor and a TEST-ONLY SMC-B, written by `tests/e2e.rs` with `TI_TEST_KON_RECORD_DIR`: service directory, GetCards, GetPinStatus, ReadCardCertificate, ExternalAuthenticate, GetJobNumber, Sign/Verify/Encrypt/DecryptDocument, numbered in call order (`NN-<operation>.request.xml`, `NN-<operation>.response-<status>.xml`) | eHEX infinity 6.0.2, firmware 2.0.1; added in 8f17cb2c (2026-09-27); recording date otherwise unknown | `TI_TEST_KON_PATH=<praxis.kon> TI_TEST_KON_RECORD_DIR=<dir> just konnektor-e2e-interactive` (PIN entry at the terminal), then copy the test's directory here; `tests/recorded.rs` replays it byte for byte, so its expectations change with it |
