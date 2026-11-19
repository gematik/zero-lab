---
id: TASK-401
title: >-
  hsm-proxy: a TCP listener, own TLS/mTLS or http:// with a declared mesh (rule
  29)
status: To Do
assignee: []
created_date: '2026-11-19 15:20'
labels:
  - rust
  - hsm
  - transport
dependencies:
  - TASK-399
  - TASK-389
references:
  - rust/ti-hsm-proxy
  - docs/design/servers.md
priority: medium
ordinal: 414000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The sidecar listens on a Unix socket only (HSM_PROXY_LISTEN_URL unix://). Inside the cluster, rule 29 (TASK-399) allows two modes: https:// with the sidecar's own TLS from HSM_PROXY_LISTEN_TLS_CERT_PATH, _KEY_PATH and, for mTLS, _CA_PATH with an allowlist _PEER_NAME; or http:// (h2c) with HSM_PROXY_LISTEN_MESH naming the mesh, refused without it. TLS material is read at start (rule 8); the profile follows gemSpec_Krypt as constants; start-up refuses a key that does not match its certificate, an invalid certificate and an empty CA bundle (rule 17). Needs the maintainer's approval of tokio-rustls (tonic's tls-ring feature), the one new crate; rustls, ring and webpki are in the workspace through ti-tls. Open: A_28830, access by calling component and key_id, which over mTLS can come from the client certificate's identity; over a mesh only from the mesh's policy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 HSM_PROXY_LISTEN_URL takes https:// with own TLS or mTLS, and http:// only with HSM_PROXY_LISTEN_MESH; each mode is logged and reported at start
- [ ] #2 Tests over TCP: a client without a certificate, with one outside the allowlist, and with an expired one is refused under mTLS; plaintext without a declared mesh does not start
- [ ] #3 It is recorded whether A_28830 is met per mode, or the gap is a task of its own
<!-- AC:END -->
