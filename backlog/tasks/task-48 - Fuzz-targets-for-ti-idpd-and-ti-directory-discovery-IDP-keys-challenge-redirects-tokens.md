---
id: TASK-48
title: >-
  Fuzz targets for ti-idpd and ti-directory: discovery, IDP keys, challenge,
  redirects, tokens
status: Done
assignee: []
created_date: 2026-10-14 20:42
updated_date: '2026-11-05T20:58:00Z'
labels:
  - ti-idpd
  - ti-directory
  - fuzz
dependencies: []
references:
  - docs/design/testing.md
  - rust/docs/design.md
priority: medium
ordinal: 46000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design goal 9. The IDP-Dienst and FHIR-Directory answers are parsed before their signatures are checked.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 fuzz targets for every response parser of both crates, seeded from fixtures, and a just recipe
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fuzz crates rust/ti-idpd/fuzz (discovery, key, challenge, code_redirect) and rust/ti-directory/fuzz (owner_redirect, token, keycloak_token, sign_in), with just fuzz-ti-idpd and just fuzz-ti-directory. Seeds: the reference IDP-Dienst's published discovery document and keys (captured 2026-11-05), hand-made redirects and tokens, and the crash inputs found. Invariants: a discovery document's signed issuer is the IDP asked; no challenge verifies without the IDP's signature; a code redirect's code is not empty and its URL is the Location; an owner redirect yields its Location; sign-in goes to the directory's endpoint. Found and fixed: a panic in ti-idpd's percent decoding on a non-ASCII byte after %, a sign taken as a hex digit, and an empty code accepted. 30 s per target without a crash.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti-idpd and ti-directory have a fuzz target for each response parser, with seeds and just recipes; the fuzzing found and fixed a panic and an empty-code acceptance in ti-idpd's redirect handling.
<!-- SECTION:FINAL_SUMMARY:END -->
