---
id: TASK-98.5
title: Every Go client on its profile
status: Done
assignee: []
created_date: '2026-11-06T14:01:00Z'
updated_date: '2026-11-06T18:25:00Z'
labels:
  - go
  - security
dependencies: []
parent_task_id: TASK-98
ordinal: 248000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Inventory of Go clients and the endpoints they reach; epa proxy and probe verify under ti (closes TASK-229 and removes the TASK-180 nolint), internet clients under web, no fallback to unverified TLS.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 epa proxy and probe verify under ti
- [x] #2 every other Go client of a TI or internet endpoint uses its profile
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On spec/go-pki-validation (9e49a5a4, fa4defe4, 637b40df): titls.NewWebHTTPClient; epa: WithInsecureSkipVerify/WithCertPool removed, WithTLSConfig required (no default, no fallback), ProxyConfig.TLSConfig; zero-epa proxy and probe fetch the TSL per environment (dev on ref's material) over the web profile and verify the Aktensysteme under ti, TASK-180 nolints gone; idpd defaults to the web profile when handed no client; zero-pdp and zero-pep-proxy hand web clients to idpd, openid, oidf and the PDP backend; oidf's mTLS layering now keeps the base TLS config whole. Gap: TASK-236 (pep/proxy upstream). go mod tidy -diff fails in epa, idpd, pdp, pep/proxy until tipki is tagged and synced. Live proof pending: gated ePA/IDP suites.

Maintainer's decision: the host provides the client, enforced by type: idpd.NewClientFromConfig(config, httpClient) and NewAuthenticator(config, httpClient) take it as a parameter (HTTPClient field removed), nil refused; no fallback inside idpd; go/docs/design.md §2 stays as is.
<!-- SECTION:NOTES:END -->
