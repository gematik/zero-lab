---
id: TASK-117
title: 'rust: update rsa and pkcs1 past their release-candidate pins'
status: To Do
assignee: []
created_date: '2026-10-20 10:41'
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
- [ ] #1 rsa and pkcs1 at the latest compatible versions, pinned in [workspace.dependencies]
- [ ] #2 a fresh resolution builds (cargo generate-lockfile in a scratch copy)
- [ ] #3 just check and just vet pass
<!-- AC:END -->
