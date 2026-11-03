---
id: TASK-97
title: >-
  TLS peer verification of TI endpoints: spec/pki-validation and a rustls
  verifier
status: To Do
assignee: []
created_date: 2026-10-15 05:20
updated_date: '2026-11-01T16:11:00Z'
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
- [ ] #3 the rule set and corpus cover the end-entity checks the Go hosts ask the helper for (SMC-B and HBA profiles, admission, IDP-Dienst)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-01 (TASK-165): the rule set must also cover what the PDP's token exchange (TASK-168) and the Go relying parties (TASK-171) ask the stateless ti-pki-helper: SMC-B and HBA end-entity checks with the hci-aut and hp-aut profiles, OCSP, the admission extension, and the IDP-Dienst profile; the corpus is what Rust and the helper's Go client both run.
<!-- SECTION:NOTES:END -->
