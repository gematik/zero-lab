---
id: TASK-20
title: 'jwz: WebCrypto backend'
status: To Do
assignee: []
created_date: '2026-10-10 05:58'
updated_date: '2026-10-11 11:48'
labels:
  - jwz
  - wasm
dependencies: []
priority: medium
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
In the browser, non-extractable WebCrypto keys instead of RustCrypto keys in wasm memory: a crate implementing jwz's async crypto and key traits over SubtleCrypto.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ES256 and ECDH-ES with non-extractable keys, tested in headless Chrome (just jwz-browser)
- [ ] #2 Interop with the RustCrypto backend in both directions
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-10-11: moved from high to medium; browser-only, not on the path of the big release or the ZETA client.
<!-- SECTION:NOTES:END -->
