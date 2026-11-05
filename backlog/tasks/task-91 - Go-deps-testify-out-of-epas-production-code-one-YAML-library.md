---
id: TASK-91
title: 'Go deps: testify out of epa''s production code, one YAML library'
status: Done
assignee: []
created_date: 2026-10-14 20:44
updated_date: '2026-11-05T19:19:00Z'
labels:
  - go
  - deps
  - epa
dependencies: []
references:
  - docs/conventions/dependencies.md
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
- [x] #1 go.yaml.in/yaml/v3 everywhere, testify gone from every module, v2/v3 decoding differences checked
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
go/epa reads YAML with go.yaml.in/yaml/v3 and prints with it; testify left proof_test.go and config.go. The decoding is unchanged, as testify's yaml wraps yaml.v3. Left outside our code: kv lists testify indirect because pgx's tests use it, and zaddy reaches gopkg.in/yaml.v3 through Caddy.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
go/epa reads and prints YAML with go.yaml.in/yaml/v3; testify left its code. Only pgx's tests keep testify as an indirect line in kv.
<!-- SECTION:FINAL_SUMMARY:END -->
