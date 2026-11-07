---
id: TASK-250
title: 'ti-client: commands as a synchronous API, ti-cli a thin front end'
status: In Progress
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T21:38:00Z'
labels:
  - ti-client
  - ti-cli
  - architecture
dependencies:
  - TASK-249
  - TASK-248
  - TASK-246
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 266000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: the command-line tool and the Tauri app run the same operations, so the operations live in ti-client and return the engines' model types; ti-cli only parses arguments, reads its configuration and prints. A desktop app depending on ti-cli would pull in clap and terminal output.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 each ti command's operation is a function of ti-client returning an engine's model type or a typed result; ti-cli calls it and prints
- [ ] #2 ti-cli's output, exit codes and schemas are unchanged
- [ ] #3 ti-client does not depend on clap or on terminal output
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Group pki (2026-11-07): the operations of pki verify, verify-signature, inspect, tsl show/verify/bundle/export, roots list/bundle, trust export, pkcs12 convert, identity inspect/sign and the IDP certificate check are in ti-client: trust::Session (from ti-cli trust.rs, over ti_client::Dirs; warnings through a closure, TSL state lines through the client's Observer), pki::{verify, inspect, signature, tsl, roots, bundle, export}, pkcs12, identity (card key behind a private trait, Identity::on_card takes the Konnektor), idp_trust (the session opened by a closure once needed, generic over the front end's error), input, peer, text::span. Results derive Serialize in the shape of the JSON; ti-cli wraps them with the schema field (serde flatten) and renders. ti_client::Error grew the variants ti-cli maps one to one (From<ti_client::Error> for CliError). cache clear already called ti_client::file_cache::clear; unchanged. ti-client has a traceability table now. Outputs of 37 offline invocations (text, markdown, JSON, stderr, exit codes) compared before and after: identical. Left for later groups or tasks: product rules now in ti-client rather than ti-pki (TSLDET-023 at-time loader, the AUT key-usage rule), the profile directory resolved before environment detection in verify.
<!-- SECTION:NOTES:END -->
