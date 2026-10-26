---
id: TASK-40
title: 'ti directory: FHIR operations with the owner token (search, own entries)'
status: To Do
assignee: []
created_date: '2026-10-11 11:48'
labels:
  - ti-directory
  - ti-cli
dependencies:
  - TASK-33
priority: low
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-33 yields tokens for every path; using them is left to curl. Add ti directory search (GET /search with FHIR search parameters, the Bundle as a table) and reading the own OrganizationDirectory/HealthcareService entries (/owner), maybe certificates lookup (/certificates). Only if a consumer wants it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti directory search returns entries for a name or Telematik-ID with any token that carries search:read
<!-- AC:END -->
