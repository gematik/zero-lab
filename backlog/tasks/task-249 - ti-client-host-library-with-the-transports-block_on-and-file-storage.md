---
id: TASK-249
title: 'ti-client: host library with the transports, block_on and file storage'
status: In Progress
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T21:01:00Z'
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
- [x] #1 new crate ti-client holds the ureq transports for every product client's trait (one agent per profile from ti-tls's rustls configuration), block_on, and the file-backed CacheStore
- [x] #2 ti-connector-client, ti-idpd(-client) and ti-tls have no ureq feature and no ureq dependency
- [x] #3 ti-client's Client is Send + Sync and its public API is synchronous
- [x] #4 ti-client contains no protocol logic: a rule of a product (a message, a check, a token rule) found there moves to its client
- [x] #5 cargo vet, deny and the unsafe-free check pass; no new dependency
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Commits: ti-client skeleton (block_on, FileCache, files); ti_tls::konnektor (the Konnektor's .kon trust: pins, CA chains naming expectedHost/SNI, OS verifier supplied by the host for an empty store, insecureSkipVerify) so ti-tls gains no dependency and ti-connector-client stays free of rustls; ti_client::connector (UreqTransport, probe, check_config, server_certificate) with check::run, check::host_port and Credentials::client_identity left in ti-connector-client; ti_client::tls (agent per profile, UreqFetch) from ti-tls; ti_client::net/http (Net, proxy, web_config, Http with an Observer hook instead of printing, UreqTransport for ti-idpd-client and ti-directory-client) and Client (Send + Sync, synchronous) from ti-cli and ti-idpd-client. ti-connector-client, ti-idpd-client and ti-tls have no ureq feature. No new crate in Cargo.lock; just check-changed passes (797 tests, unsafe-free, core-deps, machete, deny, vet). Follow-ups: the two adapters' own max-age parsing duplicates ti_cache::CacheControl; the probe/peer/connector-setup commands still use ureq in ti-cli until TASK-250.
<!-- SECTION:NOTES:END -->
