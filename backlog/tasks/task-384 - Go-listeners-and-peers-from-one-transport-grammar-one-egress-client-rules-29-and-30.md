---
id: TASK-384
title: >-
  Go: zero-pep-proxy and zero-epa from one transport grammar and one egress
  client (rules 29 and 30)
status: In Progress
assignee: []
created_date: '2026-11-18 21:34'
updated_date: '2026-11-22 12:47'
labels:
  - go
  - servers
  - security
dependencies:
  - TASK-408
references:
  - docs/design/servers.md
priority: medium
ordinal: 398000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
servers.md rules 29 and 30 (TASK-382) for the Go servers that need them, cut down on 2026-11-22 by the maintainer. zero-pep-proxy listens on PEP_ADDR in plaintext (go/pep/proxy/cmd/zero-pep-proxy/main.go), and its outbound fetches (OIDF entity statements and JWKS, idpd, trust material, OCSP) build their own http.Client each, as zero-epa's (TSL, OCSP) do. Scope: zero-pep-proxy's listener becomes a URL of the transport scheme (TASK-385): https with own TLS, or http:// once the operator accepts plaintext (…_PLAINTEXT_ACCEPTED=true), as behind zerobin's Caddy edge; key material read at start (rule 8), no reload. Both servers' outbound fetches go through one egress client with the allowlist of rule 2, the limits of rule 24 and the response checks of rule 28; plain http only for OCSP and CRLs. Out of scope: zero-caddy (Caddy owns its listeners and TLS, ACME included), metsubushi (a smoke-test echo server without egress or keys), zero-pdp (frozen, decision-19), forward proxy support (TASK-407, on demand).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zero-pep-proxy builds its listener from a URL as rule 29 says (https by default, http:// only with the operator's acceptance), refuses at start what rule 17 refuses, and reports the mode (rule 7)
- [ ] #2 zero-pep-proxy's and zero-epa's outbound fetches to external hosts go through one egress client with the allowlist, limits and response checks of rule 30; plain http only for OCSP and CRLs
- [ ] #3 Tests named after rules 29 and 30 prove the listener modes and refusals and the egress client's allowlist, limits and http refusal, on the code, not per image
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-19: zero-pdp is out of scope. go/pdp is frozen (decision-19), so 'each Go server' means zero-pep-proxy, zero-caddy, zero-epa and metsubushi.

2026-11-22, cut down by the maintainer: the description's 'none reloads key material' is obsolete since TASK-395 (read at start, rotated by a rollout); zero-caddy and metsubushi out of scope; forward proxy split to TASK-407; AC #3 (rule 26 transport tests against each image) replaced by tests on the code.

2026-11-22: the egress client moves to go/egress (TASK-408); TASK-384 takes it from there. No listener TLS in titls (maintainer).
<!-- SECTION:NOTES:END -->
