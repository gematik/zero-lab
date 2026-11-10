---
id: TASK-283
title: ti pki verify --connect <server> --validation-profile web
status: To Do
assignee: []
created_date: '2026-11-10T18:40:00Z'
labels:
  - rust
  - ti-cli
dependencies:
  - TASK-282
priority: medium
ordinal: 299000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback: no command checks a web server under the web profile; verify --connect validates only against the TI PKI. Add web as a validation profile with --connect: the server's chain checked by ti-tls's web verifier (system roots, the name, revocation), reported like verify's other results with the warnings.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti pki verify --connect HOST --validation-profile web reports the web verdict, the revocation source and warnings; exit 0 valid, 1 refused; web is refused without --connect
- [ ] #2 JSON schema, help and AGENTS.md updated; tests against a loopback TLS server with a test root
<!-- AC:END -->
