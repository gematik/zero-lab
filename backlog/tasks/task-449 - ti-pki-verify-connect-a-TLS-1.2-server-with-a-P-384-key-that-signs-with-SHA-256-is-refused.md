---
id: TASK-449
title: >-
  ti pki verify --connect: a TLS 1.2 server with a P-384 key that signs with
  SHA-256 is refused
status: Done
assignee: []
created_date: '2026-11-27T10:48:00Z'
updated_date: '2026-11-28T10:25:00Z'
labels:
  - ti-cli
  - bug
dependencies: []
ordinal: 457000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti pki verify --connect idp-ref.app.ti-dienste.de fails: UnsupportedSignatureAlgorithmForPublicKeyContext (ecdsa-with-SHA256, P-384). The server speaks TLS 1.2, its key is P-384 and it signs ServerKeyExchange with ecdsa+SHA256, which TLS 1.2 allows (the scheme names the hash, not the curve; RFC 8422). The handshake check of ti-client/src/peer.rs (Capture) maps SHA-256 only to P-256 and brainpool P256, unlike ti-tls's WEB_SCHEMES, which takes the mixed pairs. The handshake there proves only possession of the key; ti-pki decides trust on the chain afterwards.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A TLS 1.2 handshake signature by a P-384 key with SHA-256, and by a P-256 key with SHA-384, verifies in the chain capture
- [x] #2 TLS 1.3 schemes still bind the curve
- [x] #3 ti pki verify --connect idp-ref.app.ti-dienste.de gets past the handshake
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Cause: ti-client/src/peer.rs's SCHEMES mapped TLS 1.2's ecdsa+SHA256 only to P-256 and brainpool P256. Added the mixed NIST pairs as ti-tls's WEB_SCHEMES has them, after the first entry, so TLS 1.3 stays curve-bound. Loopback tests with a server signing P-384/SHA-256 and P-256/SHA-384 under TLS 1.2, and the TLS 1.3 refusal. TEST-ONLY p384 fixture in ti-cli/tests/fixtures/tls/web. idp-ref.app.ti-dienste.de verifies VALID.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-client peer: TLS 1.2 ECDSA schemes name the hash, not the curve (RFC 8422), so the chain capture now accepts a P-384 key signing SHA-256 and a P-256 key signing SHA-384; TLS 1.3 schemes stay bound to their curve. Tests with a loopback rustls server and mixed keys for both directions and the TLS 1.3 refusal; fixture web/p384. ti pki verify --connect idp-ref.app.ti-dienste.de verifies VALID. Ships with the next ti release.
<!-- SECTION:FINAL_SUMMARY:END -->
