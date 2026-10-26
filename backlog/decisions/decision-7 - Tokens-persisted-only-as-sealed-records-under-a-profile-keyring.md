---
id: decision-7
title: Tokens persisted only as sealed records under a profile keyring
date: '2026-10-15 17:46'
status: accepted
---
## Context

TASK-30 decided "no token cache (a bearer token is a secret)" for `ti directory login`. The CLIs now need to keep many tokens across invocations and across languages: OAuth access and refresh tokens, PoPP tokens (one per patient or card), and `.well-known` documents. Fetching them anew per invocation costs a login (with a card or Konnektor round trip) each time, and a refresh token that is not kept is useless. A plain token file, the alternative, puts bearer secrets and patient identifiers on disk in clear.

## Decision

1. Tokens and other secrets are persisted only through the shared store (TASK-103, `spec/store`), in sealed namespaces: AES-256-GCM per record, key name and indexed metadata HMAC-hashed, the record bound to its key, namespace, profile and expiry.
2. The data keys live in a per-profile keyring, wrapped by a `KeyWrapper` (key-file now; Keychain, Secure Enclave, TPM, DPAPI later, TASK-104). Without a keyring a sealed namespace refuses to write; there is no plain-text fallback.
3. Subject identifiers (KVNR, Telematik-ID, ICCSN) appear only as blind-index tags, never in clear.
4. A record's lifetime is bounded by its `not_after`, sealed into the record; the store never extends it.
5. Deleting a profile removes its keyring first, which makes its records unreadable.

This supersedes the "no token cache" sentence of TASK-30.

## Consequences

- TASK-105 adds the token consumers.
- Rollback of the whole store file (restoring an old `state.db`) is not detected; a refresh token restored that way is still bounded by its own expiry and the server's rotation.
- A process that holds the unwrapped keyring holds every token of its profile for its lifetime, as it would hold one fetched token.
