---
id: decision-18
title: VAU and ASL on the standard library's ML-KEM; CBOR stays fxamacker, strict
date: '2026-11-16T18:20:00Z'
status: accepted
---
## Context

TASK-96 (2026-11-05) kept cloudflare/circl because ePA VAU asks for Kyber768 v3.02, which the standard library's
crypto/mlkem (FIPS 203) does not speak on the wire. The SPIKE TASK-339 (doc-5, branch spike/asl-stdlib) showed
Kyber v3.02 built on crypto/mlkem and crypto/sha3 (shared secret SHAKE256(K ‖ SHA3-256(c))), as gematik's lib-vau
does on BouncyCastle: it agrees with circl both ways and passed a live ePA connect. ZETA/ASL uses ML-KEM-768
directly. The spike also built an own CBOR codec (about 400 lines on cryptobyte) in place of fxamacker/cbor.

## Decision

Maintainer, 2026-11-16:
- circl leaves go/epa: Kyber768 v3.02 is built on crypto/mlkem and crypto/sha3; circl stays only as a test
  comparison. This supersedes TASK-96's ruling on circl.
- CBOR stays github.com/fxamacker/cbor (maintained, not in the standard library), decoded with strict options
  instead of the defaults: duplicate keys, tags and unknown fields refused where the format is fixed, bounded
  nesting and lengths. The own codec stays on the spike branch as a fallback, not merged.
- ZETA/ASL is implemented in zero-lab, later; its package structure (beside VAU in go/epa/vau, a protocol package
  both use, or an own module) is decided before that work starts.

## Consequences

- go/epa drops circl from its non-test dependencies; a release of epa follows.
- fxamacker's decoder is configured strictly; inputs it accepted silently before (duplicates last-wins, case-folded
  keys, tags, null as nil, trailing bytes) are refused, which a live ePA run must confirm.
- Server-key verification stays optional (TASK-342): off or warn only warns; enforce checks everything.
