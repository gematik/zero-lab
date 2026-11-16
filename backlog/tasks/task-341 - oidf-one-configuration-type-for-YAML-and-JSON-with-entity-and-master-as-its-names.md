---
id: TASK-341
title: >-
  oidf: one configuration type for YAML and JSON, with entity and master as its
  names
status: To Do
assignee: []
created_date: '2026-11-16T18:14:00Z'
labels: []
dependencies: []
ordinal: 356000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
oidf.FileConfig is read from YAML by zero-pdp and zero-pep-proxy; zeta-pdp-go reads a JSON file into a type of its own and copies it over, with other names (entity, master, master_jwk). The maintainer wants one type for both (2026-11-16): FileConfig and what it holds get json tags beside the yaml ones, with the same names, and the names become entity (was sub), master (was fed_master_url), master_entity_statement_uri and master_jwk. A configuration with the old names is refused at start (unknown field), as every misspelt one is; the release notes say so.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 FileConfig reads the same relying party from YAML and from JSON
- [ ] #2 The names are entity, master, master_entity_statement_uri and master_jwk in both; the old ones are refused
- [ ] #3 zero-pdp, zero-pep-proxy, their examples and tests use the new names
<!-- AC:END -->
