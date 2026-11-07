---
id: TASK-249
title: 'ti-client: host library with the transports, block_on and file storage'
status: To Do
assignee: []
created_date: '2026-11-07T15:53:00Z'
labels:
  - ti-client
  - architecture
  - deps
dependencies:
  - TASK-245
references:
  - docs/architecture.md
  - docs/conventions/dependencies.md
priority: medium
type: feature
ordinal: 265000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: product clients do no I/O and carry no HTTP client; ti-client is the one native host library that the command-line tool and the desktop app share. Today the ureq adapters sit in the product crates behind a ureq feature (ti-connector-client, ti-idpd, ti-tls, ti-jwks), and ti-cli holds block_on (src/block.rs), the file cache store (src/file_cache.rs) and its own Http and Logged transports. ti-client holds I/O adapters and runs commands; protocol logic stays in the product clients, so ti-client does not become a commons crate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 new crate ti-client holds the ureq transports for every product client's trait (one agent per profile from ti-tls's rustls configuration), block_on, and the file-backed CacheStore
- [ ] #2 ti-connector-client, ti-idpd(-client) and ti-tls have no ureq feature and no ureq dependency
- [ ] #3 ti-client's Client is Send + Sync and its public API is synchronous
- [ ] #4 ti-client contains no protocol logic: a rule of a product (a message, a check, a token rule) found there moves to its client
- [ ] #5 cargo vet, deny and the unsafe-free check pass; no new dependency
<!-- AC:END -->
