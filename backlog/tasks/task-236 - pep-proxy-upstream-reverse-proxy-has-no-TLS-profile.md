---
id: TASK-236
title: 'pep/proxy: upstream reverse proxy has no TLS profile'
status: Done
assignee: []
created_date: '2026-11-06T17:16:00Z'
updated_date: '2026-11-07T10:44:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 252000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-98.5's inventory: the zero-pep-proxy gateway forwards to its upstream with an http.Transport whose TLS is Go's default, not a spec/pki-validation profile. Decide the upstream's profile (web for an internet upstream; a local upstream may be plain or mTLS) and wire it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 the gateway's upstream transport verifies under the profile chosen for it, or the exception is documented
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-11-07, go-batch db7a1050: proxy.Config.UpstreamTransport; an https route without it refuses to start; zero-pep-proxy passes the web profile's transport (titls.NewWebHTTPClient's, without its client timeout so long transfers stay possible). Documented exception: an http upstream is local (same pod or network) and has no TLS. Test TestTLSV001_AnHTTPSUpstreamGoesThroughTheHostsTransportOnly. Docs: CONFIG.md, docs/gateway.md.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
zero-pep-proxy's gateway reaches https upstreams only through the host's web-profile transport and refuses to start without one; http upstreams are the documented local exception. Merged from go-batch.
<!-- SECTION:FINAL_SUMMARY:END -->
