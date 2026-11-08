---
id: TASK-276
title: >-
  jwz: producing a token checks its header against the policy (typ, kid, key
  references)
status: To Do
assignee: []
created_date: '2026-11-08T15:20:00Z'
updated_date: '2026-11-08T15:26:00Z'
labels:
  - jwz
  - security
milestone: m-1
dependencies: []
priority: high
ordinal: 292000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by TASK-258 (RFC 8725 §3.11, producer side). jws::sign, sign_async, jws::json::sign and jwe::encrypt check algorithm and curve against the policy (TASK-271) but not the header: a profile with a typ signs a token without it and then refuses it, contradicting the README's claim that jwz never produces what its profile refuses. The same holds for require_kid and key_references. TASK-269 (RFC 10070's client-authentication+jwt) needs it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 sign and encrypt (compact and JSON) run the policy's header checks (typ, require_kid, key references, crit) on the header they produce, before signing or encrypting, and refuse with PolicyViolation
- [ ] #2 tests named after RFC 8725 §3.11 prove that a profile with a typ neither produces nor accepts a token without it
<!-- AC:END -->
