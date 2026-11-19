---
id: TASK-397
title: >-
  ti-hsm-proxy: fuzz targets for the keys file, the module hash and the public
  point
status: To Do
assignee: []
created_date: '2026-11-19 14:29'
labels:
  - rust
  - fuzz
dependencies:
  - TASK-389
references:
  - rust/ti-hsm-proxy/src/config.rs
  - rust/ti-hsm-proxy/src/pkcs11.rs
priority: medium
ordinal: 410000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the code review of feat/ti-hsm-spike (2026-11-19): ti-hsm-proxy has parsers without fuzz targets, against 'a new parser comes with its fuzz target' (CLAUDE.md, docs/design/testing.md#fuzzing). The keys file (config::parse_keys, JSON through serde with deny_unknown_fields), the module hash (config::parse_sha256) and the decoding of CKA_EC_POINT (Token::public_point, a DER OCTET STRING or a bare point) take input the sidecar does not write. The crate has no fuzz/ workspace yet; jwz/fuzz is the model.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 rust/ti-hsm-proxy/fuzz has targets for the keys file, the module hash and the public point, excluded from the workspace like jwz/fuzz
- [ ] #2 Each target runs clean for the time the fuzzing guide asks, and its corpus or seeds are committed
<!-- AC:END -->
