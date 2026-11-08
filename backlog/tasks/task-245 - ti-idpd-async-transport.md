---
id: TASK-245
title: 'ti-idpd: async transport'
status: Done
assignee: []
created_date: '2026-11-07T15:52:00Z'
updated_date: '2026-11-08T08:54:00Z'
labels:
  - ti-idpd
  - architecture
dependencies: []
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 261000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: every trait a product client defines is async, without Send, in one variant (as soap::Transport, load::Transport, Fetch and CacheStore already are), so the same client runs in a browser over fetch. ti-idpd's http::Transport (rust/ti-idpd/src/http.rs) is the only synchronous one.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ti-idpd's http::Transport::send is async without a Send bound, with the reason noted as in soap::Transport
- [x] #2 the operations that send are async; ti-cli and ti-directory call them through block_on
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
http::Transport::send is async (allow async_fn_in_trait with the soap::Transport reason) with the blanket impl for &T; UreqTransport and ti-cli's Logged keep blocking bodies. authenticator::authenticate (already async) awaits the transport through a private send helper, as ti-directory's owner::login does; exchange::login_bearer and login_client_credentials became async, called from ti-cli through block_on. Pure builders and parsers (discovery, challenge, keycloak, token) stay synchronous. CertificateTrust stays synchronous: it is not a transport and not in this task's scope. ti-cli's block.rs doc now names the ti crates in general, not only ti-pki.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-idpd's http::Transport is async without a Send bound; the native host blocks inside the async fn.
<!-- SECTION:FINAL_SUMMARY:END -->
