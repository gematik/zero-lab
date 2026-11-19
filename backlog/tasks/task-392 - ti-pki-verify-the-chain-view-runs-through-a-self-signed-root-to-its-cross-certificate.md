---
id: TASK-392
title: >-
  ti pki verify: the chain view runs through a self-signed root to its
  cross-certificate
status: To Do
assignee: []
created_date: '2026-11-19 12:42'
updated_date: '2026-11-19 12:43'
labels:
  - rust
  - pki
  - cli
dependencies: []
references:
  - rust/ti-cli/src/commands/inspect.rs
priority: low
ordinal: 405000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Observed 2026-11-19 with ti-cli 0.6.2 against dienst.vsdd2.ru.service-ti.de. The server sends five certificates: the leaf, GeoTrust G5 TLS ECC P-384 SHA384 2022 CA2, the self-signed DigiCert TLS ECC P384 Root G5 (until 2046), the cross-certificate of the same name issued by DigiCert Global Root G3 (until 2036), and the self-signed Global Root G3. `ti pki verify --connect` draws them as one line of descent:

```
✓ dienst.vsdd2.ru.service-ti.de
└── ✓ GeoTrust G5 TLS ECC P-384 SHA384 2022 CA2
    └── ✓ DigiCert TLS ECC P384 Root G5           CA · until 2046-01-15
        └── ✓ DigiCert TLS ECC P384 Root G5       CA · until 2036-03-31
            └── ✓ DigiCert Global Root G3
```

A self-signed certificate is a trust anchor, and a path ends there (RFC 5280 §6.1). Shown under it, the cross-certificate looks like the issuer of the root. It has the same name and key, so a signature check does not tell them apart. The view should show the path that was verified, ending at the anchor it ended at, and list what the server sent beyond that apart.

Not checked: whether the verdict's path (rustls-webpki) ended at Root G5 or at Global Root G3, and which part of the CLI builds the view, the verified path or the certificates as sent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The chain view shows the verified path, ending at its trust anchor, and lists the certificates the server sent outside that path separately
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: the same connection fails in the zeta CLI. ZETA SDK 2.0.1 checks the revocation of the chain as sent, and stops at the self-signed Root G5 the server sends. That is in zeta-backlog TASK-19.
<!-- SECTION:NOTES:END -->
