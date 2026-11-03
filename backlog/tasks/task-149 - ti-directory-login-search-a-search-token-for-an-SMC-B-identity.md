---
id: TASK-149
title: 'ti directory login search: a search token for an SMC-B identity'
status: Done
assignee: []
created_date: '2026-10-28T17:16:00Z'
updated_date: '2026-10-28T19:23:00Z'
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
- [x] #1 ti directory login search takes an identity (--p12, --cert --key, --card) and returns the directory token through the owner flow; no RegService token, no client credentials
- [x] #2 The report and --help say the token is the owner token, whose aud includes /search, and which scopes it carries
- [x] #3 AGENTS.md, the JSON schema and the Unreleased notes describe it; tests prove it against the loopback directory
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Waiting for the maintainer's run against RU (login search with an SMC-B p12, then a /search request with the token).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ti directory login search takes a card identity (--p12, --cert/--key, --card) and runs the owner flow through the IDP-Dienst: gemSpec_VZD_FHIR_Directory V1.7.0 gives a card identity access to /search only with the owner token. The report is the owner report plus directory.search_url and the warning search_not_in_audience when aud does not name it; schema, --help, AGENTS.md, README and the Unreleased notes describe it; four loopback tests. HITL 2026-10-28 (maintainer): ti directory login search --env ref --p12 smcb.p12 --format json works against RU.
<!-- SECTION:FINAL_SUMMARY:END -->
