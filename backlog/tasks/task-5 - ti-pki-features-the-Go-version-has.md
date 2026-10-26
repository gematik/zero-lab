---
id: TASK-5
title: 'ti pki: features the Go version has'
status: Done
assignee: []
created_date: '2026-10-09 13:55'
updated_date: '2026-10-10 17:08'
labels:
  - ti-cli
dependencies: []
priority: low
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Still missing compared with the Go ti pki: roots bundle, tsl fetch, tsl intermediates, verify --ocsp-responder and --ocsp-max-age, inspect --short.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each command or flag exists with text, Markdown and JSON output and a published schema, or is dropped with a reason
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Go → Rust:
- roots bundle → pki roots bundle (PEM, or --p12 Java truststore)
- tsl fetch → pki tsl export (the TSL as published, once it verified)
- tsl intermediates → pki tsl bundle (with tsl show's filters)
- verify --ocsp-responder / --ocsp-max-age → the same flags on pki verify
- inspect --short → pki inspect --short (subject, expiry, Telematik-ID)

Dropped:
- tsl fetch --with-signature: ti verifies the TSL's inline XMLDSig, not gematik's .sig.
- The TSL as a JSON dump: ti never shows TSL metadata as fact; tsl show is the reviewed view.

Also: GEM.RCA7 is the anchor in every environment, and --nist-only verifies as a client without brainpool would.
<!-- SECTION:NOTES:END -->
