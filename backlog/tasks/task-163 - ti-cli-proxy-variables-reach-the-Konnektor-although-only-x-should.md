---
id: TASK-163
title: 'ti-cli: proxy variables reach the Konnektor although only -x should'
status: Done
assignee: []
created_date: '2026-11-01T14:59:00Z'
updated_date: '2026-11-01T15:04:00Z'
labels:
  - ti-cli
  - security
dependencies: []
priority: high
ordinal: 173000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found in TASK-55. ti-cli/src/connector.rs and AGENTS.md say a proxy is used for a Konnektor only when -x is given, because a proxy from the environment would route its traffic and credentials elsewhere. But ureq's default configuration reads the proxy variables (config.rs: Proxy::try_from_env), and the builder only overrides them with an explicit -x.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 With proxy variables set and no -x, a Konnektor call goes directly, proven by a test
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
The Konnektor's agent starts with no proxy; only -x sets one. Proven by proxy_variables_do_not_apply_to_the_konnektor: with the variables pointing at a closed port, the call failed with connection refused before the fix and succeeds now.
<!-- SECTION:FINAL_SUMMARY:END -->
