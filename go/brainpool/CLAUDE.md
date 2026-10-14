# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
go build ./... && go vet ./... && go test ./...
go test -tags openssl_cross ./...        # cross-checks against the openssl CLI (skips if absent)
go test -run x -fuzz FuzzParseCertificate -fuzztime 30s
cd .. && just golangci brainpool          # golangci-lint with the workspace configuration
cd internal/bp256/fiat && go run generate.go -field p   # regenerate; needs the docker image from PROVENANCE.md
```

## Architecture

Brainpool curves (RFC 5639) for the gematik TI. `doc.go` has the constant-time posture table and a file index; `README.md` the full security rationale and references.

**Root** — `curves.go` (P256r1/P384r1/P512r1 as an isomorphism onto the twisted t1 curves over the deprecated big.Int `crypto/elliptic` path; the `curves` table is the only place a curve is identified by name/OID), `x509.go` (`ParseCertificate` swaps the SPKI algorithm OID for an unassigned same-length one so `crypto/x509` parses everything and leaves the key nil, then decodes the Brainpool key and restores the `Raw*` slices; `ValidatePublicKey`; `MarshalPKIXPublicKey`), `keys.go` (SEC1/PKCS#8 keys, public point recomputed from d), `sign.go` (`SignFunc`, `SignFuncPrivateKey`, `ECDH`, `GenerateKey` — the only callers of `internal/bp256`).

**internal/bp256** — the constant-time brainpoolP256r1 core: `Sign` (RFC 6979, low-s), `ECDH`, `PublicKey`, all on fixed-width bytes. `point.go` is RCB complete addition + Montgomery ladder; `scalar.go`/`ecdsa.go` the mod-n arithmetic; `fiat/` the generated fields (`Element` mod p, `Scalar` mod n) — four generated files, never hand-edited, checksums in `fiat/PROVENANCE.md`.

**josebp** — JWS/JWE/JWK over these curves for the IDP-Dienst and ePA. Its exported surface is what gemidp/epa/ti call; helpers are unexported.

## House rules

- A secret scalar on brainpoolP256r1 never goes through `elliptic.Curve` methods: signing, ECDH and public-key derivation route through `hasConstantTimeCore` → `internal/bp256`. Verification and parsing are public data and use the standard library.
- Every key that arrives from outside (certificate, JWK, ECDH peer) passes `ValidatePublicKey` before any arithmetic.
- Exported iff a consumer (gempki, gemidp, epa, kon, ti, or josebp) calls it. Breaking changes ship as a minor bump; consumers are in-repo and pin explicitly.
- Tests: the standard library `testing` package, no assertion libraries; the differential tests in `internal/bp256` use `brainpool.P256r1()` (big.Int) as the oracle; Wycheproof vectors live in `testdata/`.
