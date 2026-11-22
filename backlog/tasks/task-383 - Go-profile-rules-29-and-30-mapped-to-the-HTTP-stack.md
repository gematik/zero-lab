---
id: TASK-383
title: 'Go profile: rules 29 and 30 mapped to the HTTP stack'
status: Done
assignee: []
created_date: '2026-11-18 21:34'
updated_date: '2026-11-22 16:03'
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
- [x] #1 go/docs/design.md names, for each bullet of rules 29 and 30, the Go construct or package that meets it, without restating the rule
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: rule 29 no longer asks for TLS reload without restart (TASK-395): TLS material is read at start and rotated by a rollout. Nothing to map for reload.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/docs/design.md section 10 maps every bullet of servers.md rules 29 and 30 to its Go construct: the listener URL and its parsing (zero-pep-proxy's listen.go), loopback and the operator's acceptance, crypto/tls from files with VerifyConnection for the allowlist and the profile constants, egress.NewClient with its rule in the Proxy hook, egress.SelfVerifying passed as a function, egress.NewTransport for peers. It names what is not built in Go: Unix-socket listeners, peers by URL, the admin listener's report, a private-range check of resolved addresses, and the forward proxy's checks (TASK-407). It replaces the bullet that claimed an SSRF constructor with DNS checks that does not exist.
<!-- SECTION:FINAL_SUMMARY:END -->
