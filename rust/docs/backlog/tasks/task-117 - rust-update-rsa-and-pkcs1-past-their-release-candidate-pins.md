---
id: TASK-117
title: 'rust: update rsa and pkcs1 past their release-candidate pins'
status: Done
assignee: []
created_date: '2026-10-20 10:41'
updated_date: '2026-10-20 12:23'
labels:
  - rust
  - deps
dependencies: []
priority: high
ordinal: 102000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The workspace pins rsa = "=0.10.0-rc.18" (Cargo.toml; the only rsa line on the current RustCrypto stack) and resolves pkcs1 0.8.0-rc.4. Newer are rsa 0.10.0-rc.19 and pkcs1 0.8.0-rc.5. A fresh resolution outside the lockfile (found by the TASK-116 spike) picks a pkcs1 that rsa rc.18 no longer compiles against (encoding.rs: RsaPrivateKey/RsaPublicKey lost their lifetime and gained a type parameter), so the pin holds only through Cargo.lock. Move both to the latest compatible pair, keep the known-compromise entry in docs/development.md current, and run just check, just vet and the RSA paths (ti-pki rsa feature, jwz-rsa-guard).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 rsa and pkcs1 at the latest compatible versions, pinned in [workspace.dependencies]
- [x] #2 a fresh resolution builds (cargo generate-lockfile in a scratch copy)
- [x] #3 just check and just vet pass
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
rsa =0.10.0-rc.19 (workspace pin); pkcs1 0.8.0-rc.5 and spki 0.8.1 follow through the lockfile. pkcs1 is not a direct dependency of any crate, so a pin in [workspace.dependencies] would not take effect; what keeps a fresh resolution building is rsa's own requirement at rc.19. Fresh resolution checked: cargo generate-lockfile in a scratch copy, workspace (without jwz, as just check builds it) with all features builds. cargo vet exemptions moved to the new versions; rustls 0.23.46 remains TASK-114. jwz browser stamp regenerated for the workspace manifest.

just vet passes after also moving rustls' exemption to 0.23.46 (TASK-114, closed with this).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
rsa moved to 0.10.0-rc.19 with pkcs1 0.8.0-rc.5 and spki 0.8.1; a fresh resolution builds again (it broke with rc.18). docs/development.md's known-compromise entry and the cargo vet exemptions follow; just check passes.
<!-- SECTION:FINAL_SUMMARY:END -->
