---
id: TASK-223
title: 'ti-idpd: discovery verification diverges from IDPV-001 and IDPV-003'
status: In Progress
assignee: []
created_date: '2026-11-05T22:03:00Z'
updated_date: '2026-11-06T06:23:00Z'
labels:
  - ti-idpd
  - security
dependencies: []
priority: high
ordinal: 230000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found during TASK-50: ti-idpd verifies the discovery document's signature with the x5c key before the trust check, where IDPV-001 asks for the trust check first, and it accepts unchecked certificates with a warning (Checked::Unchecked), against IDPV-003 / A_20617-01. The idpv_001 tests prove only that a refused certificate stops the flow.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the signer's certificate is checked before its key is used (IDPV-001), with a test that fails against the current order
- [ ] #2 an unchecked certificate stops the flow, or the exception is decided and recorded with its reason (IDPV-003, A_20617-01)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On fix/ti-idpd-discovery-trust-order (../zero-lab-223), 8a432e33: discovery::parse takes the CertificateTrust and checks the x5c signer before verifier_from_certificate; idpv_001_the_discovery_signer_is_checked_before_its_key_verifies_anything fails with the old order (signature error before the trust check) and passes now. AC 2 waits on the maintainer: IDPV-003 forbids the downgrade, but ti-cli's --idp-unverified uses it, for IDPs outside the TI PKI and for its own fake-IDP integration tests.
<!-- SECTION:NOTES:END -->
