---
id: TASK-97.4
title: 'TLS verification (d): hosts take the profile per endpoint'
status: In Progress
assignee: []
created_date: '2026-11-06T07:36:00Z'
updated_date: '2026-11-06T08:49:00Z'
labels:
  - ti-cli
  - security
dependencies: []
parent_task_id: TASK-97
priority: medium
ordinal: 238000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-97 part (d): ti-cli and the ureq adapters verify TI endpoints with the ti profile and internet endpoints with the web profile.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-cli takes the profile per endpoint from configuration, with no system-store fallback for ti; the Konnektor's .kon pinning stays as it is
- [x] #2 a rustls ClientConfig per profile for other rustls clients
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/pki-validation: all of ti-cli's https endpoints (TSL download points, IDP-Dienst, FHIR-Directory with Keycloak) present public certificates (D-Trust EV, GlobalSign EV; checked live), so ti-cli verifies every one under web; ePA and KIM, which take ti (maintainer), are not in ti-cli. No --tls option: nothing needs it yet. ti-tls feature ureq: agent() with the profile's ClientConfig through ureq's unversioned connector API (TASK-13), UreqFetch for OCSP and CRLs. The live test (ti-tls tests/real_world.rs, --ignored) found that D-Trust's EV CA signs ECDSA-SHA256 with a P-384 key: ti-pki gained ECDSA_P384_SHA256 and ECDSA_P256_SHA384 (RFC 5758 known answers from OpenSSL), in web's lists only. -k now skips the check for downloads only, as documented; before, it also reached the IDP-Dienst and FHIR-Directory agents. The Konnektor's .kon pinning is unchanged. Full just check green (817 + 128).
<!-- SECTION:NOTES:END -->
