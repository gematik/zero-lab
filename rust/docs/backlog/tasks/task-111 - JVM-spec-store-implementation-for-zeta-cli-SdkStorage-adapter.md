---
id: TASK-111
title: 'JVM: spec/store implementation for zeta-cli (SdkStorage adapter)'
status: To Do
assignee: []
created_date: '2026-10-15 17:51'
labels:
  - zeta
  - spec
  - deps
dependencies:
  - TASK-103.1
priority: low
ordinal: 117000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zeta-cli (Kotlin/JVM, ZETA SDK) persists through SdkStorage; it plugs in StorageConfig.Custom(JsonFileStorage), one plaintext JSON per profile at $XDG_CONFIG_HOME/telematik/zeta/<profile>.storage.json. Implement spec/store in Kotlin (JCA crypto, sqlite-jdbc after approval) as an SdkStorage adapter so zeta-cli shares profiles and the store with ti and zero-epa; add interop/jvm to the matrix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a Kotlin adapter passes the spec/store corpus
- [ ] #2 zeta-cli --profile reads and writes the same state.db as ti and zero-epa
- [ ] #3 interop/matrix.md includes the JVM
<!-- AC:END -->
