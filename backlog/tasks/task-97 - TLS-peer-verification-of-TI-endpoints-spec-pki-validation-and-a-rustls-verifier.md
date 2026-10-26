---
id: TASK-97
title: >-
  TLS peer verification of TI endpoints: spec/pki-validation and a rustls
  verifier
status: To Do
assignee: []
created_date: '2026-10-15 05:20'
labels:
  - ti-pki
  - spec
  - keys
dependencies: []
references:
  - docs/architecture.md
  - rust/docs/design.md
priority: medium
ordinal: 95000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The host owns the transport, the core owns trust (docs/architecture.md): most client logic talks HTTPS to TI endpoints, and a host's TLS stack would verify them against the system store with its own defaults. The trust anchors, the validation profile per certificate type, the algorithm and key rules (for example no RSA end-entity certificates where the gematik rules forbid them) and the OCSP rules (when required, freshness, responder authorisation, stapling) must be one contract.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 spec/pki-validation with rules, result codes and a corpus for certificate and TLS peer verification of TI endpoints
- [ ] #2 ti-pki supplies a rustls ServerCertVerifier implementing it; the ureq and reqwest adapters use it for TI endpoints; which endpoints are TI endpoints is core configuration
<!-- AC:END -->
