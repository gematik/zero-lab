---
id: TASK-55
title: 'Dependencies: socks through ureq''s socks-proxy feature'
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-01T15:04:00Z'
labels:
  - ti-cli
  - deps
milestone: m-0
dependencies: []
references:
  - docs/conventions/dependencies.md
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
- [x] #1 decided with the maintainer: keep socks5 proxies (documented as a known compromise) or drop the feature and the crates
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decided by the maintainer: SOCKS is not needed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ureq's socks-proxy feature, socks and byteorder are gone. -x socks5:// is refused by the option's parser, and a SOCKS URL in the proxy variables with http_setup (exit 2): without the feature ureq only logs such a proxy and connects directly, past the proxy the user asked for. just check green. Found on the way: TASK-163.
<!-- SECTION:FINAL_SUMMARY:END -->
