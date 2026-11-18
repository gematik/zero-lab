---
id: TASK-384
title: >-
  Go: listeners and peers from one transport grammar, one egress client (rules
  29 and 30)
status: To Do
assignee: []
created_date: '2026-11-18 21:34'
labels:
  - go
  - servers
  - security
dependencies:
  - TASK-383
references:
  - docs/design/servers.md
priority: medium
ordinal: 398000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No Go server meets servers.md rules 29 and 30 (TASK-382): zero-pep-proxy listens on PEP_ADDR in plaintext (go/pep/proxy/cmd/zero-pep-proxy/main.go:200), no command reads a certificate, key or CA bundle for its listener, none listens on a Unix socket, none reloads key material or reports its effective transport, and outbound fetches (trust material, OCSP, JWKS, entity statements) each build their own http.Client instead of going through one egress client. To be split per server and per bullet when the Go profile task (TASK-383) has named the constructs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each Go server builds its listeners and peers from URLs as rule 29 says, https by default, with the refusals of rule 17
- [ ] #2 Outbound fetches to external hosts go through one egress client that meets rule 30
- [ ] #3 The transport tests of rule 26 run against each image
<!-- AC:END -->
