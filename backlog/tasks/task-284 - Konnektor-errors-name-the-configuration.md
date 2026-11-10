---
id: TASK-284
title: Konnektor errors name the configuration
status: Done
assignee: []
created_date: '2026-11-10T18:40:00Z'
updated_date: '2026-11-10T19:52:00Z'
labels:
  - rust
  - ti-cli
dependencies: []
priority: medium
ordinal: 300000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ti 0.6.0 test feedback: 'Konnektor: transport: io: Connection reset by peer (os error 54)' does not say which .kon failed. Maintainer: name the configuration only; the URL and the calls stay with -v.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 a Konnektor error reads 'Konnektor <name>: …'; kinds, exit codes and the hint unchanged; tested
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CliError::Connector and CardRestricted carry the configuration's name (Option<Box<str>>, kept small for clippy's result_large_err); for_connector() attaches it where a command opened a session (commands/connector.rs through its open closure, identity.rs for --card). Tests: error::tests::a_konnektor_error_names_its_configuration, connector::an_unreachable_konnektor_is_named_by_its_configuration.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Konnektor errors name the .kon configuration ('Konnektor praxis: …'); the address and the calls stay with -v; kinds, exit codes and hints unchanged.
<!-- SECTION:FINAL_SUMMARY:END -->
