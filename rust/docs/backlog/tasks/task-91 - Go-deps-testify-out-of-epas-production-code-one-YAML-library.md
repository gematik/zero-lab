---
id: TASK-91
title: 'Go deps: testify out of epa''s production code, one YAML library'
status: To Do
assignee: []
created_date: '2026-10-14 20:44'
labels:
  - go
  - deps
  - epa
dependencies: []
references:
  - go/docs/design.md
priority: medium
ordinal: 89000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
epa/config.go parses YAML with testify/assert/yaml; three YAML libraries are in use (yaml.v2 deprecated, gopkg.in/yaml.v3 archived).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 go.yaml.in/yaml/v3 everywhere, testify gone from every module, v2/v3 decoding differences checked
<!-- AC:END -->
