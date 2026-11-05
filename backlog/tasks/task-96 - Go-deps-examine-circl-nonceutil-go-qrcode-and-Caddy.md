---
id: TASK-96
title: 'Go deps: examine circl, nonceutil, go-qrcode and Caddy'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-05T20:15:00Z'
labels:
  - go
  - deps
dependencies: []
references:
  - docs/conventions/dependencies.md
  - go/docs/design.md
priority: medium
ordinal: 94000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
circl (Kyber768 vs crypto/mlkem, depends on the VAU spec), nonceutil (pre-1.0, MPL-2.0), go-qrcode (unmaintained since 2020), zaddy's about 550 modules through Caddy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a decision per dependency recorded, follow-up tasks where something is replaced
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decisions, 2026-11-05 (maintainer): circl stays: epa/vau needs Kyber768, which the standard library's crypto/mlkem (ML-KEM-768, FIPS 203) does not replace on the wire; look again when the VAU protocol moves to ML-KEM. nonceutil: already gone from every go.mod. go-qrcode stays: pure Go, one call in pep/proxy/qr.go drawing our own authorization URL, a stable standard; look again on a reported vulnerability. Caddy stays in zaddy: the plugin is Caddy by purpose, and its 164 indirect modules stay in that module and its image, outside the libraries.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
circl, go-qrcode and Caddy stay, each with its reason recorded; nonceutil was already gone. No follow-up task.
<!-- SECTION:FINAL_SUMMARY:END -->
