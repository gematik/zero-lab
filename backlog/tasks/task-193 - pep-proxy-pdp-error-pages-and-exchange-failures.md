---
id: TASK-193
title: 'pep/proxy, pdp: error pages and exchange failures'
status: Done
assignee: []
created_date: '2026-11-02T22:59:00Z'
updated_date: '2026-11-05T19:19:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 203000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pep/proxy error pages show err.Error(), including authorization server response bodies. pdp answers an exchange failure with JSON to the browser instead of redirecting to the client. verifyClient echoes client not found and jose details.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Clients and browsers see generic text; pdp redirects to the client
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
pep/proxy shows generic text and logs the detail with the request's code and state scrubbed; an upstream error and description are no longer reflected. pdp redirects a callback failure to the client once it knows it. verifyClient answers client authentication failed for every rejected assertion, so unknown clients and bad signatures read alike.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
pep/proxy and pdp show generic text, redirect callback failures to the client and answer every rejected client assertion alike.
<!-- SECTION:FINAL_SUMMARY:END -->
