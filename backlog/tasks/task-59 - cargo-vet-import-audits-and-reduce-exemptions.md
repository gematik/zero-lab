---
id: TASK-59
title: 'cargo-vet: import audits and reduce exemptions'
status: Done
assignee: []
created_date: 2026-10-14 20:43
updated_date: '2026-11-05T22:12:00Z'
labels:
  - deps
  - supply-chain
dependencies: []
references:
  - docs/conventions/dependencies.md
  - rust/docs/design.md
priority: medium
ordinal: 57000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
cargo-vet exempts 241 of 272 crates.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 audits imported from trusted organisations, exemptions reduced, and own audits for the crates that handle secrets
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
On worktree-agent-a28859bc6af715542 (78133f78, d282fad2, 1b6abb0f; rust/supply-chain only). Exemptions 180 -> 101; cargo vet --locked: 104 fully audited, 2 partially, 99 exempted. Import ariel-os added. 69 per-crate trust entries (RustCrypto repos and maintainers, dalek, ff/group, rustls maintainers, rust-lang, dtolnay/serde), safe-to-deploy, expiring 2027-11-05. Own full audits: cmov 0.5.4, ctutils 0.4.6, hkdf 0.13.0, hmac 0.13.0, pbkdf2 0.13.0, rpassword 7.5.4, rtoolbox 0.0.6; delta zeroize_derive 1.4.2->1.5.0. Open: zeroize 1.9.0 stays exempted (1.9.1 fixes an uninitialised read in the wasm32 barrier fallback; bump touches rust/docs/unsafe-exceptions.md, maintainer decision); pbkdf2 mcf-feature finding (unused here) to report upstream; still exempted security-relevant: quick-xml, ureq, ureq-proto, http, httparse, security-framework(-sys), schannel, tls_codec, num-bigint, jiff, base64.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ariel-os imported, 69 per-crate trust entries, 8 own audits; exemptions 180 -> 101. Remaining crates in TASK-224. Merged into main at 50ea3d15.
<!-- SECTION:FINAL_SUMMARY:END -->
