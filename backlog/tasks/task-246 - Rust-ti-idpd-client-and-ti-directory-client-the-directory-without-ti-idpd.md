---
id: TASK-246
title: 'Rust: ti-idpd-client and ti-directory-client, the directory without ti-idpd'
status: In Progress
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T19:01:00Z'
labels:
  - ti-idpd
  - ti-directory
  - architecture
dependencies:
  - TASK-245
references:
  - docs/architecture.md
priority: medium
type: task
ordinal: 262000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: product clients are named ti-<product>-client, and no product client depends on another; what one needs from another product comes in through a trait that ti-client implements. ti-directory today uses ti-idpd's http types (exchange.rs, request.rs, token.rs, keycloak.rs, owner.rs), its authenticator for the owner login (owner.rs) and its Env and Idp (lib.rs). The FHIR-Directory is its own product.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ti-idpd is renamed ti-idpd-client and ti-directory ti-directory-client: crate names, directories, docs, traceability and fuzz targets
- [ ] #2 ti-directory-client has its own async transport trait and does not depend on ti-idpd-client
- [ ] #3 ti-directory-client takes its IDP-Dienst token through a trait (an access token valid for the next request, and a call when the directory refuses it with 401 so it is not handed out again, followed by one retry)
- [ ] #4 the host side implements that trait over ti-idpd-client and refreshes the token before it expires; a test proves the directory retries once after a refused token
<!-- AC:END -->
