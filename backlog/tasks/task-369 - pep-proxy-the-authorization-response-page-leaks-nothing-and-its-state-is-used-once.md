---
id: TASK-369
title: >-
  pep/proxy: the authorization response page leaks nothing and its state is used
  once
status: To Do
assignee: []
created_date: '2026-11-17T06:45:00Z'
labels:
  - pep-proxy
  - security
  - oauth
dependencies: []
priority: low
ordinal: 384000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No response of `/oauth2/callback` (`go/pep/proxy/proxy.go:440-494`; renderer `render.go:55-56`) sets `Referrer-Policy: no-referrer` or `Cache-Control: no-store`. The error page is rendered at the URL that carries `code` and `state` (RFC 9700 §4.2.4, §4.3.1). The state is consumed only after a successful exchange (`proxy.go:461-463`). After a failed exchange it stays valid for `LoginStateTTL` (15 min, `session.go:45`), whereas §4.2.4 says it SHOULD be invalidated on first use. Found by the RFC 9700 audit of TASK-259 (2026-11-17).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every callback response carries `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. Test named after RFC 9700 §4.2.4.
- [ ] #2 The state is consumed on the first callback that names it, whatever its outcome. Test extends `TestRFC9700_2_1_SessionStateSingleUse`.
<!-- AC:END -->
