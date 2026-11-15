---
id: doc-5
title: 'SPIKE result: ZETA/ASL and ePA VAU on the Go standard library'
type: other
created_date: '2026-11-15T17:38:00Z'
updated_date: '2026-11-15T17:38:00Z'
---
SPIKE TASK-339, 2026-11-15. Code on branch spike/asl-stdlib (not merged); plan in the task.

## Verdict

Yes: ZETA/ASL and ePA VAU both run on the Go standard library alone. go/epa needs neither cloudflare/circl
nor fxamacker/cbor outside its tests; `go list -deps ./epa/...` names neither.

| Question | Answer | Evidence |
|---|---|---|
| ASL's KEM | ML-KEM-768 (FIPS 203), gemSpec_Krypt 2.51.0 ch. 7, A_26921/A_26932 | `crypto/mlkem` as is |
| ePA VAU's Kyber768 v3.02 (A_24425-01) | Built on `crypto/mlkem` + `crypto/sha3`: shared secret = SHAKE256(K ‖ SHA3-256(c), 32); gematik's lib-vau does the same on BouncyCastle | agrees with circl both ways on 2000 fresh key pairs each; live ePA connect, RU provider 2 |
| CBOR | Own strict codec on `x/crypto/cryptobyte` (already a dependency), about 400 lines, no reflection | 14 differential fuzz targets against fxamacker; lib-vau (Java), libasl (Rust) vectors; live ePA connect |
| ASL as a protocol | Profile beside VAU: ML-KEM-768 fields, ZETA-ASL-CID / -nonPU-Tracing, /ASL, no vau-np, big-endian IV counter, error codes 1–9 | own client ↔ own server; interop with gematik's libasl both ways, offline harness |

Live: `TestEPA_Connect/provider2` against the reference environment passed on the final branch state (handshake
both KEM directions, record status, consent), so the real Aktensystem reads our CBOR and our strict decoder
reads its answers. Kyber v3.02 KATs could not be run directly: Go's ML-KEM API takes no Kyber key seed; the
differential test against circl (which passes them) stands in.

## Size (non-test lines, with comments)

kyber.go 73, internal/cbor 517 (decoder ~305 code lines), codec.go 437 (tables for 9 message types, both
profiles), profile.go 129, server_errors.go 74. Removed: circl (~large), fxamacker/cbor ~9,900 lines plus
x448/float16 ~1,200, both reflection-based.

## The trade-off for CBOR (maintainer's decision, dependencies.md rule 1)

Own code is a parser of hostile input. In its favour: ~300 decoder lines without reflection, lengths checked
before allocation, and it is stricter than fxamacker's defaults, which accept a map of integer keys as an empty
M4, case-folded keys, duplicates (last wins), null as nil, tags, non-shortest heads, and trailing bytes after
CertData and errors. Its risk is interop, not memory safety: strictness can refuse a real peer (Jackson writes
null by default; libasl sends `"ocsp_response": null`, accepted for ASL only). The live run found no such case
for VAU. Same shape as zeta-pdp-go's App Attest decoder (pdp/attest/apple/cbor.go), stricter; both could share
one package.

## Findings beside the question

- IV counter byte order: go/epa/vau writes it little-endian; libasl big-endian; gemSpec_Krypt says only
  "IV = a ‖ Zähler". ASL follows libasl; VAU unchanged.
- The VAU client does not check that a response carries its request's counter (A_24633); ASL now does.
- A_26940/A_26942/A_26943 write header names with "/" ("ZETA/ASL-CID"), which HTTP does not allow; A_26935,
  the examples and libasl use hyphens. gemSpec_ZETA A_26480 points to "[gemSpec_Krypt#8]", now chapter 7.
- The minimum record length is 72 bytes (A_24630/A_26928); the code had 71.
- Not proven: A_26938 certificate checks for ASL (role OID, OCSP at most 24 h old); both interop sides skipped them.

## Proposed follow-up tasks (created once accepted)

1. go/epa: Kyber768 on crypto/mlkem, circl only in tests (from 27ae33da), with a release; revises TASK-96.
2. go/epa: own CBOR codec in place of fxamacker, or keep fxamacker (decision above); with a `just fuzz-epa`
   recipe and longer fuzz runs.
3. An ASL module (client and server) for ZETA: from the profile, plus A_26938 certificate and OCSP checks; home
   (go/epa/vau, a new go/asl, or zeta-pdp-go) to decide.
4. VAU client checks the response counter (A_24633).
5. VAU IV counter byte order: confirm with gematik, then align.
6. Shared CBOR package for zero-lab and zeta-pdp-go (App Attest), if task 2 keeps own code.
