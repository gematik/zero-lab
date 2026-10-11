---
id: TASK-36
title: 'epa: decide vau_cert_verify default (warn or enforce)'
status: To Do
assignee: []
created_date: '2026-10-11 11:48'
labels:
  - epa
  - go
dependencies: []
priority: medium
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
zero-epa verifies the VAU CertData chain (profile epa-vau-aut, env detected) and the signature over signed_pub_keys through ti, default warn since TASK-24. The plan was to make enforce the default once RU runs showed the verdicts are reliable. Collect the verdicts of the RU/dev runs (zero-epa probe, just epa-connect-test), decide, and change the default in ProxyConfig and the docs; tag go/epa.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 decision recorded (decision record or task notes) with the evidence from RU runs
- [ ] #2 default changed or kept accordingly; go/epa tagged if changed
<!-- AC:END -->
