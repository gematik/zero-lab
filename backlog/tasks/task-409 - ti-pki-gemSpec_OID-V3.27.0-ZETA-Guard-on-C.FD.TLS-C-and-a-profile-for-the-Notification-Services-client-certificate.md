---
id: TASK-409
title: >-
  ti-pki: gemSpec_OID V3.27.0, ZETA Guard on C.FD.TLS-C and a profile for the
  Notification Service's client certificate
status: In Progress
assignee: []
created_date: '2026-11-23T20:13:00Z'
updated_date: '2026-11-23T20:14:00Z'
labels:
  - rust
  - ti-pki
  - zeta
dependencies: []
priority: medium
ordinal: 422000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
gemSpec_OID V3.27.0 (13.11.2026, CI_26_4-1) changes one requirement against V3.26.0, which ti-pki's tables follow (oid.rs:26): GS-A_4446-21 allows the technical role oid_zeta-guard (1.2.276.0.76.4.328) on C.FD.TLS-C besides C.FD.AUT. The Notification Service in a ZETA Guard (gemSpec_ZETA V1.3.2 A_25652) authenticates with such a certificate at the app vendors' push gateways; the aim is one certificate check for every TI 2.0 Fachdienst that sends push notifications through ZETA, not only DiPag. ti today treats the role as not admitted on C.FD.TLS-C (oid.rs:331) and has no profile for the certificate; the draft C_12646 had applied the change and was taken back for V3.26.0 (ReleaseNotes 2026-11). gemSpec_PKI stays at V2.28.0, gemSpec_ZETA at V1.3.2.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-pki's OID tables follow gemSpec_OID V3.27.0: oid_zeta-guard is admitted on C.FD.AUT and C.FD.TLS-C, every citation of GS-A_4446-20 and of V3.26.0 moves to -21 and V3.27.0, and a diff of the two versions' tables shows no other change left out
- [ ] #2 A profile for the Notification Service's client certificate (working name zeta-guard-tls-c): type C.FD.TLS-C, extended key usage clientAuth, technical role oid_zeta-guard, a CA of the component PKI named in the verified TSL, revocation checked hard-fail like the other profiles; ti pki verify --validation-profile takes it, select_for_cert picks it for such a certificate, and zeta-guard-aut stays C.FD.AUT only
- [ ] #3 Tests named after GS-A_4446-21 and the profile's rules pass with generated certificates (role on C.FD.TLS-C admitted, the same role on another TLS type refused, the profile refusing C.FD.AUT and a certificate without the role), and the traceability table is regenerated
- [ ] #4 The requirement that makes the push gateways check this certificate is found (gemF_PushNotification or the DiPag specification) and cited in the profile's documentation; if it states further checks (a name, a role list, a pinned CA), they are part of the profile or a follow-up task
- [ ] #5 ti-cli's schema, AGENTS.md profile list and ReleaseNotes name the new profile and the gemSpec_OID version
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read gemSpec_OID V3.27.0 GS-A_4446-21 and diff the role and type tables against V3.26.0 once more in code form (tools: the scratchpad diff showed only the C.FD.TLS-C addition and the requirement suffix).
2. oid.rs: TECH_ROLE_ZETA_GUARD admits C.FD.AUT and C.FD.TLS-C; the module doc and tests move to V3.27.0; the test that pinned the role to C.FD.AUT pins both types.
3. profile.rs: add zeta-guard-tls-c next to zeta-guard-aut, with type C.FD.TLS-C, clientAuth, role oid_zeta-guard, hard-fail revocation; extend select_for_cert and the profile listing; keep zeta-guard-aut unchanged.
4. Find the push gateway's check in gemF_PushNotification (and the DiPag documents); cite it in the profile, or record that no further checks are stated.
5. Tests: generated C.FD.TLS-C and C.FD.AUT certificates with and without the role through the validator and the CLI (ti pki verify --validation-profile zeta-guard-tls-c --format json); traceability regenerated with TRACE_BLESS=1 cargo test -p ti-pki --test traceability.
6. ti-cli: schema, tests/cli.rs profile list (currently pins the list), AGENTS.md, ReleaseNotes.
7. just check-changed in rust/; full just check before merge.
<!-- SECTION:PLAN:END -->
