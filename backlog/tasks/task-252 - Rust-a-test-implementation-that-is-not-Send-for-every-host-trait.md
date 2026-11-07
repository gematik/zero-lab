---
id: TASK-252
title: 'Rust: a test implementation that is not Send for every host trait'
status: In Progress
assignee: []
created_date: '2026-11-07T15:53:00Z'
updated_date: '2026-11-07T20:22:00Z'
labels:
  - architecture
  - tests
  - wasm
dependencies: []
references:
  - docs/architecture.md
priority: low
type: task
ordinal: 268000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Decision-15: the traits product clients define are async without a Send bound, so a browser host (JS fetch, not Send) can implement them. Nothing proves that the clients keep working with a host that is not Send; a Send-only assumption in client code (a spawned future, a Send bound added by accident) would break wasm silently, since ti-wasm uses few clients today.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 each async host trait (soap::Transport, load::Transport, Fetch, CacheStore, idpd's and the directory's transports, the directory's token trait) has a test implementation holding an Rc, and a test drives the client through it
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Each async host trait has a test double holding an Rc, driven through the client's real code with a noop-waker or futures-lite block_on: ti-connector-client soap::Transport and ti-cache CacheStore (offline.rs, connect_cached + cards().list); ti-pki load::Transport, CacheStore and RevocationChecker (validate.rs, OcspChecker with store inside Validator::validate); ti-tls Fetch (verifier.rs, WebCheck::verify); ti-cache CacheStore (cache.rs, Cache::get); ti-idpd-client http::Transport and CertificateTrust (flow.rs, authenticator::authenticate); ti-directory-client http::Transport and Tokens (tokens.rs, tokens::send); ti-jwks http::Transport and CacheStore (source.rs, JwksSource::keys). Not covered on native: ti-pki's Loader and the loader structs (HttpLoader, CachingLoader, Reload) bound MaybeSend/MaybeSync, which is Send+Sync on native by design, so a !Send transport cannot drive them outside wasm32; ti-tls WebVerifier/TiVerifier need Send+Sync for rustls.
<!-- SECTION:NOTES:END -->
