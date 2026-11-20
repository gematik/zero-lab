---
id: TASK-404
title: >-
  hsm-proxy: the Java clients reach it in plaintext gRPC over TCP, which it
  takes only once the operator accepts plaintext
status: To Do
assignee: []
created_date: '2026-11-20 08:26'
updated_date: '2026-11-20 09:00'
labels:
  - rust
  - hsm
  - transport
dependencies:
  - TASK-401
references:
  - rust/ti-hsm-proxy
  - docs/design/servers.md
priority: medium
ordinal: 417000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found 2026-11-20 checking the ZETA clients (origin/main of each): keycloak-zeta, keycloak-integrity-provider and the notification service reach the HSM proxy through gematik's zeta-guard-java-hsm-proxy-provider (Apache-2.0), which speaks plaintext gRPC over TCP only ('mTLS support is planned (A_28830)'); the Helm chart gives them HSM_PROXY_ENDPOINT as host:port. ngx_pep's ossl_hsm takes http:// on loopback only and https:// with TLS or mTLS, no Unix socket. hsm-proxy takes plaintext on TCP only with HSM_PROXY_LISTEN_MESH (servers.md rule 29), also on loopback inside the pod. So the Java clients reach it unchanged (TASK-389 #1) only behind a declared mesh. To decide: whether loopback TCP inside the pod counts as inside the pod, as a Unix socket does (a change of rule 29), or the clients wait for mTLS in the Java provider.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 It is decided and in rule 29 whether a plaintext listener on loopback inside the pod needs a declared mesh
- [ ] #2 hsm-proxy serves the Java provider and ossl_hsm as they are, or the gap is recorded against TASK-389 #1
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-20: the maintainer replaced the mesh declaration by an acceptance: HSM_PROXY_LISTEN_PLAINTEXT_ACCEPTED=true (like terms of service, the value exactly true), no mesh named, since the sidecar cannot tell whether one protects the connection. With it the Java clients reach the sidecar unchanged; the open question stays whether loopback inside the pod needs the acceptance too.
<!-- SECTION:NOTES:END -->
