---
id: TASK-187
title: 'pep: authorization server metadata is not checked'
status: To Do
assignee: []
created_date: '2026-11-02T15:42:00Z'
labels:
  - go
  - security
dependencies: []
priority: medium
ordinal: 197000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
discoverMetadata never compares md.Issuer with the configured issuer (RFC 8414 3.3) or requires https on endpoints, and clientAssertion uses the unchecked issuer as aud. oauth/oidc FetchDiscoveryDocument likewise checks neither status nor issuer. Several nolint reasons in pep/proxy/backend_pdp.go rest on this metadata. Reported while clearing lint (TASK-86).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Issuer and https are enforced, with tests
<!-- AC:END -->
