---
id: TASK-245
title: 'ti-idpd: async transport'
status: In Progress
assignee: []
created_date: '2026-11-07T15:52:00Z'
updated_date: '2026-11-07T19:01:00Z'
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
- [ ] #1 ti-idpd's http::Transport::send is async without a Send bound, with the reason noted as in soap::Transport
- [ ] #2 the operations that send are async; ti-cli and ti-directory call them through block_on
<!-- AC:END -->
