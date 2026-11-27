---
id: TASK-447
title: >-
  zero-pep-proxy and zero-pdp take the database as an address, a user and a
  password file
status: To Do
assignee: []
created_date: '2026-11-27T09:19:00Z'
labels:
  - kv
  - pep
dependencies: []
ordinal: 456000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
go/kv/docs/hosts.md says the DSN is the address and nothing else, user and password beside it, the address from configuration and user and password from files, and SplitURL only for a host that still holds one URL. zero-pep-proxy (PEP_DATABASE_URL, taken apart in database.go) and zero-pdp (DATABASE_URL) still hold one URL with the password in it, in a variable, which servers.md refuses for the proxy URL. Found by zeta-authserver-go TASK-224 (its decision-19), which took AUTHSERVER_DATABASE_URL, AUTHSERVER_DATABASE_USER and AUTHSERVER_DATABASE_PASSWORD_PATH. zero-pdp is frozen: there at least the documentation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-pep-proxy takes PEP_DATABASE_URL as the address alone (refused with user information), PEP_DATABASE_USER and PEP_DATABASE_PASSWORD_PATH; its docs and compose follow
- [ ] #2 zero-pdp's frozen host is recorded as an exception or changed the same way
<!-- AC:END -->
