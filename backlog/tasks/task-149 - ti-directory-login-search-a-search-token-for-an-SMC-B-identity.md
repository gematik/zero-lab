---
id: TASK-149
title: 'ti directory login search: a search token for an SMC-B identity'
status: To Do
assignee: []
created_date: '2026-10-28T17:16:00Z'
labels:
  - ti-cli
  - directory
milestone: m-0
dependencies: []
priority: medium
type: feature
ordinal: 157000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
gemSpec_VZD_FHIR_Directory V1.7.0 opens /search to SMC-B and HBA (since 1.4.0, e.g. the ePA Ombudsstelle) only through the owner token of /owner-authenticate, whose aud lists /search; /service-authenticate's search-access_token is for Fachdienste with client credentials, /tim-authenticate for TI-Messenger clients. Today an LE that only wants to search must know that login owner is the way. login search names the purpose: the owner flow through the IDP-Dienst with an identity (--p12, --cert/--key, --card), reported as the token for the Search API.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti directory login search takes an identity (--p12, --cert --key, --card) and returns the directory token through the owner flow; no RegService token, no client credentials
- [ ] #2 The report and --help say the token is the owner token, whose aud includes /search, and which scopes it carries
- [ ] #3 AGENTS.md, the JSON schema and the Unreleased notes describe it; tests prove it against the loopback directory
<!-- AC:END -->
