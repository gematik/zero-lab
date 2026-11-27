---
id: TASK-449
title: >-
  ti pki verify --connect: a TLS 1.2 server with a P-384 key that signs with
  SHA-256 is refused
status: To Do
assignee: []
created_date: '2026-11-27T10:48:00Z'
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
- [ ] #1 A TLS 1.2 handshake signature by a P-384 key with SHA-256, and by a P-256 key with SHA-384, verifies in the chain capture
- [ ] #2 TLS 1.3 schemes still bind the curve
- [ ] #3 ti pki verify --connect idp-ref.app.ti-dienste.de gets past the handshake
<!-- AC:END -->
