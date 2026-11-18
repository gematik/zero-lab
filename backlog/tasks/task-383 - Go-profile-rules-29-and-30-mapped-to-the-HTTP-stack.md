---
id: TASK-383
title: 'Go profile: rules 29 and 30 mapped to the HTTP stack'
status: To Do
assignee: []
created_date: '2026-11-18 21:34'
labels:
  - go
  - docs
  - servers
dependencies:
  - TASK-382
references:
  - go/docs/design.md
  - docs/design/servers.md
priority: medium
ordinal: 397000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rules 29 (transport grammar) and 30 (egress client) are new (TASK-382). go/docs/design.md maps the server rules to Go and says nothing yet about them: which package holds the listener and peer construction from a URL, how crypto/tls reloads a certificate and CA bundle (GetCertificate, GetConfigForClient), how a Unix socket listener is created and a stale one detected, where the fixed TLS profile of gemSpec_Krypt lives, and how the one egress client takes its proxy (http.Transport.Proxy, CONNECT only). The profile maps and does not restate the rules.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go/docs/design.md names, for each bullet of rules 29 and 30, the Go construct or package that meets it, without restating the rule
<!-- AC:END -->
