---
id: TASK-55
title: 'Dependencies: socks through ureq''s socks-proxy feature'
status: To Do
assignee: []
created_date: '2026-10-14 20:43'
labels:
  - ti-cli
  - deps
dependencies: []
references:
  - rust/docs/design.md
priority: medium
ordinal: 53000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
socks 0.3.4 (and byteorder) come in through ureq's socks-proxy feature for ti-cli's socks5:// proxies; the crate is barely maintained (design goal 8).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decided with the maintainer: keep socks5 proxies (documented as a known compromise) or drop the feature and the crates
<!-- AC:END -->
