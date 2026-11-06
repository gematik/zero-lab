---
id: TASK-224
title: 'cargo-vet: own audits of the remaining secret-handling and parser crates'
status: To Do
assignee: []
created_date: '2026-11-05T22:12:00Z'
updated_date: '2026-11-06T06:19:00Z'
labels:
  - deps
  - supply-chain
dependencies: []
ordinal: 231000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Left from TASK-59. Still exempted and security-relevant: quick-xml (hostile input), ureq, ureq-proto, http, httparse, security-framework(-sys), schannel, tls_codec, num-bigint, jiff, base64, and zeroize 1.9.0 (1.9.1 fixes an uninitialised read in the wasm32 barrier fallback and is audited by Mozilla; the bump changes rust/docs/unsafe-exceptions.md, which needs the maintainer). Smallest next candidates for own audits: base64ct, block-padding, aes-kw, aes-gcm. Trust entries expire 2027-11-05.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 zeroize at 1.9.1 or its exemption kept with the reason
- [ ] #2 each crate listed is covered by an import, a trusted publisher or an own audit, or its exemption carries the reason
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
pbkdf2 0.13.0 mcf finding reported to RustCrypto privately on 2026-11-06, per their security policy; a one-byte final field accepts about 1 in 256 wrong passwords, an empty one is refused by the parser. Not used here.
<!-- SECTION:NOTES:END -->
