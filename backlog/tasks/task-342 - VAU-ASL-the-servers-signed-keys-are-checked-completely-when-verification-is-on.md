---
id: TASK-342
title: >-
  VAU/ASL: the server's signed keys are checked completely when verification is
  on
status: Done
assignee: []
created_date: '2026-11-16T18:19:00Z'
updated_date: '2026-11-16T20:25:00Z'
labels: []
dependencies: []
ordinal: 357000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The VAU client checks the server's signed keys after M2 and before M3 (key_exchange.go validateSignedPublicVAUKeys): CertData chain and profile and the ES256 signature through CertVerifier (ti pki verify, verify-signature). Verification stays optional, as the maintainer decided on 2026-11-16: without a verifier, or with mode off or warn, the handshake goes on and a warning says what was not checked. With verification on (enforce), every check of gemSpec_Krypt A_24624 (VAU) and A_26938 (ASL) must hold, and today some are missing or skipped: an empty cert_hash skips the check even under enforce; cert_hash is not compared with the SHA-256 of the fetched certificate; signed_pub_keys.exp is decoded but never checked against now; the stapled ocsp_response (status good, at most 24 h old) is ignored (the ti verifier asks OCSP online instead, and not at all when Offline); the CertData fetch has no context and no body limit. Applies to both profiles of the ASL spike (TASK-339, branch spike/asl-stdlib).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 With verification on, a handshake is refused before M3 for: an empty cert_hash, a cert_hash that is not the SHA-256 of the fetched certificate, exp not after now, a stapled OCSP response that is missing, not good or older than 24 h, a chain or signature the verifier refuses; one test per case named after A_24624 / A_26938
- [x] #2 Without a verifier, or with mode off or warn, the handshake goes on and logs one warning naming each check that was not done or did not hold
- [x] #3 The CertData fetch runs under the handshake's context and reads a bounded body
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Verification stays optional (off/warn/no verifier: one warning naming each unchecked or failed check). Under enforce the handshake is refused before M3 for empty or wrong cert_hash, expired keys, missing/not good/older than 24 h/foreign-issued stapled OCSP (checked with go/tipki), a certificate the CertData CA did not sign, another profile than epa-vau-aut, another environment, or a chain/signature the verifier refuses; CertData fetch under the handshake context, bounded. Live ePA connect and entitlement passed in enforce. Released in epa v0.27.0.
<!-- SECTION:FINAL_SUMMARY:END -->
