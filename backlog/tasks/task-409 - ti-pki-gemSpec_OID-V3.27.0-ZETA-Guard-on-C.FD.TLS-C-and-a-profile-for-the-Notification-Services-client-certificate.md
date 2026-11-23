---
id: TASK-409
title: >-
  ti-pki: gemSpec_OID V3.27.0, ZETA Guard on C.FD.TLS-C and a profile for the
  Notification Service's client certificate
status: Done
assignee: []
created_date: '2026-11-23T20:13:00Z'
updated_date: '2026-11-23T20:49:00Z'
labels:
  - rust
  - ti-pki
  - zeta
dependencies:
  - TASK-410
priority: medium
ordinal: 422000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
gemSpec_OID V3.27.0 (13.11.2026, CI_26_4-1) changes one requirement against V3.26.0, which ti-pki's tables follow (oid.rs:26): GS-A_4446-21 allows the technical role oid_zeta-guard (1.2.276.0.76.4.328) on C.FD.TLS-C besides C.FD.AUT. The Notification Service in a ZETA Guard (gemSpec_ZETA V1.3.2 A_25652) authenticates with such a certificate at the app vendors' push gateways; the aim is one certificate check for every TI 2.0 Fachdienst that sends push notifications through ZETA, not only DiPag. ti today treats the role as not admitted on C.FD.TLS-C (oid.rs:331) and has no profile for the certificate; the draft C_12646 had applied the change and was taken back for V3.26.0 (ReleaseNotes 2026-11). gemSpec_PKI stays at V2.28.0, gemSpec_ZETA at V1.3.2.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-pki's OID tables follow gemSpec_OID V3.27.0: oid_zeta-guard is admitted on C.FD.AUT and C.FD.TLS-C, every citation of GS-A_4446-20 and of V3.26.0 moves to -21 and V3.27.0, and a diff of the two versions' tables shows no other change left out
- [x] #2 A profile for the Notification Service's client certificate (working name zeta-guard-tls-c): type C.FD.TLS-C, extended key usage clientAuth, technical role oid_zeta-guard, a CA of the component PKI named in the verified TSL, revocation checked hard-fail like the other profiles; ti pki verify --validation-profile takes it, select_for_cert picks it for such a certificate, and zeta-guard-aut stays C.FD.AUT only
- [x] #3 Tests named after GS-A_4446-21 and the profile's rules pass with generated certificates (role on C.FD.TLS-C admitted, the same role on another TLS type refused, the profile refusing C.FD.AUT and a certificate without the role), and the traceability table is regenerated
- [x] #4 The requirement that makes the push gateways check this certificate is found (gemF_PushNotification or the DiPag specification) and cited in the profile's documentation; if it states further checks (a name, a role list, a pinned CA), they are part of the profile or a follow-up task
- [x] #5 ti-cli's schema, AGENTS.md profile list and ReleaseNotes name the new profile and the gemSpec_OID version
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-23: paused on the maintainer's call; builds on TASK-410 (stable test data) so the new fixture changes only itself. Source changes kept as a patch; they add the role type and zeta-guard-tls-c in Rust and Go, GS-A_4446-21 tests, and the fixture line in generate.sh.

2026-11-23, branch feat/ti-pki-oid-3.27, on top of TASK-410. Rust and Go: oid_zeta-guard admitted on C.FD.AUT and C.FD.TLS-C (GS-A_4446-21), tables cite V3.27.0; profile zeta-guard-tls-c (C.FD.TLS-C, role oid_zeta-guard, hard-fail) in ti-pki and go/tipki. Tests: gs_a_4446_21_zeta_guard_is_admitted_on_fd_aut_and_fd_tls_c, gs_a_4446_21_zeta_guard_tls_c_takes_the_notification_services_client_certificate (accepts the role on TLS-C, refuses TLS-C without it and FD.AUT with it), prof_003 selection; corpus and traceability re-blessed. The new fixture is one certificate and one key. Gateway check: gemF_PushNotification V1.4.0 A_28981 (C.FD.TLS-C of the component PKI with the client's role; V1.4.0 names oid_epa_mgmt and oid_erezept, not yet oid_zeta-guard) and A_28982 (method 1 pinning, method 2 TI PKI + validity + role, no revocation); the profile also checks revocation hard-fail, cited in both profiles.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Merged with feat/ti-pki-oid-3.27. ti-pki and go/tipki follow gemSpec_OID V3.27.0 (GS-A_4446-21: oid_zeta-guard on C.FD.AUT and C.FD.TLS-C), and the profile zeta-guard-tls-c checks the ZETA Guard Notification Service's client certificate (gemF_PushNotification A_28981, A_28982; revocation hard-fail on top). The new fixture is one certificate and one key.
<!-- SECTION:FINAL_SUMMARY:END -->
