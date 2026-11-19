---
id: TASK-402
title: 'hsm-proxy: access by calling component and key_id (A_28830)'
status: To Do
assignee: []
created_date: '2026-11-19 15:42'
labels:
  - rust
  - hsm
  - security
dependencies:
  - TASK-401
references:
  - rust/ti-hsm-proxy
priority: medium
ordinal: 415000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
gemSpec_ZETA A_28830: the HSM proxy must be able to restrict the operations by calling component and key_id, the components authenticated by mTLS. After TASK-401: on a Unix socket the sidecar does not ask who calls and serves the configured keys (maintainer, 2026-11-19); over its own mTLS the listener admits the identities of HSM_PROXY_LISTEN_TLS_PEER_NAME to every key; behind a declared mesh the mesh's policy decides who calls. Missing: per key, which identities may use it, e.g. a list of callers per entry of the keys file, honoured over mTLS and refused at start where the mode cannot tell callers apart.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Over mTLS a key can be restricted to named identities, and a call by another identity is refused with PERMISSION_DENIED
- [ ] #2 A keys file that restricts keys under a mode that cannot tell callers apart does not start
<!-- AC:END -->
