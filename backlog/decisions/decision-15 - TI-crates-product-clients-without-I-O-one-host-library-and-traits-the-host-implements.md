---
id: decision-15
title: >-
  TI crates: product clients without I/O, one host library, and traits the host
  implements
date: '2026-11-07T15:52:00Z'
status: accepted
---
## Context

The Rust workspace has grown to 14 crates, and three hosts will use them: ti-cli, ti-wasm and a Tauri desktop app. The current structure (TASK-226, TASK-227) has these problems:

- **Transport traits and their adapters are scattered.** ti-pki, ti-idpd, ti-jwks and ti-connector-client each define their own transport trait, and ti-connector-client, ti-idpd, ti-tls and ti-jwks each carry a ureq adapter behind a feature.
- **ti-report mixes two things.** It holds JSON projections for ti-cli and ti-wasm, and a use case of its own: the offline certificate check.
- **ti-directory depends on ti-idpd,** for its HTTP types and the owner login.
- **ti-jwks is used by no crate.**
- **ti-types holds a Clock trait and a clap integration** besides plain types.
- **A desktop app cannot depend on ti-cli** without pulling in clap and terminal output.

The maintainer's aims, 2026-11-07:

- as few crates as possible;
- self-contained crates with as few dependencies as possible;
- no "commons" crate;
- duck types: narrow interfaces the hosts implement easily.

## Decision

1. **Product clients do no I/O and are named `ti-<product>-client`.** This covers ti-connector-client, ti-idpd-client, ti-directory-client and, when they come, ti-epa-client, ti-erp-client and ti-kim-client. Product first, so that a later `ti-<product>-mock` sorts beside its client.
2. **No product client depends on another.** Whatever one needs from another product comes in through a trait the client defines and ti-client implements. For example, ti-directory-client takes its IDP-Dienst token through such a trait; ti-client refreshes the token before it expires, and the client reports a token the directory refused with 401.
3. **ti-client is the one native host library.** It holds:
   - the ureq transports for every client's trait;
   - the file storage;
   - configuration;
   - `RemoteJwks`;
   - `block_on`;
   - the commands, as a synchronous API.
   It holds no protocol logic: a rule of a product found there moves to that product's client. The product crates lose their ureq features. ti-cli and ti-app are thin front ends over ti-client. ti-wasm has no ti-client; it uses the product clients directly, over JS fetch.
4. **Every trait a product client defines is async, without a Send bound, in one variant.** Most already are; ti-idpd's transport is the exception (TASK-245).
   - Native implementations block inside `async fn`, so each future is finished at its first poll.
   - ti-client blocks at its boundary.
   - There are no sync/async twins: the client logic exists once, and an `async fn` with a blocking body is as short as a sync implementation.
   - A Send bound (through a `MaybeSend` marker) waits until a host needs Send futures, such as a tokio server or an async HTTP client.
   - jwz keeps its sync and async pairs, because callers use them directly and jwz is published for other people's hosts.
5. **Time enters as a function, `impl Fn() -> Timestamp`, everywhere.** A struct that keeps the function takes it as a type parameter.
   - `ti_types::Clock` goes.
   - rustls verifiers use the `now` rustls passes.
   - jwz accepts any `Fn() -> u64` as a `Clock`.
   - A function lets a long operation, such as PIN entry or a login, read the time again, and lets ti-wasm pass `Date.now()`.
6. **ti-types holds only types several crates exchange:** `Env`, `Tier` and `Timestamp`, with optional serde and nothing else. clap moves to ti-cli.
7. **ti-report goes.** Its read-only projections become plain Rust types in `ti_pki::model` (`model::Certificate`, `model::Tsl`, `model::Check`): the response model of ti-pki's use cases.
   - The name is not `report`, which says nothing about certificate and TSL images.
   - It is not `view`, which an MVVM reader takes for a view model with state and commands. These types have neither; the UI's view model lives in the frontend.
   - It is not `json`, which names a format the types do not depend on.
   - `Serialize` is derived only under ti-pki's optional `serde` feature, which ti-cli and ti-wasm enable. This follows decision-13: the library declares the shape, as Go's struct tags do, and the host brings the format.
   - The derive stays in ti-pki, because Rust's orphan rule keeps a host from implementing `Serialize` for ti-pki's types.
   - The offline check and certificate formatting become regular ti-pki API, because ti-wasm needs them and cannot reach ti-client.
   - Every product client gets its own `model` module when it needs one.
8. **JWK Sets come through jwz.**
   - jwz gains `KeyResolver` and `AsyncKeyResolver`, `JwkSet::signing_keys` (RFC 7517 §4.2–4.4), and `Jws::verify_with` / `verify_with_async`.
   - ti-client implements the resolver over HTTP as `RemoteJwks`, keeping ti-jwks's rules.
   - ti-jwks goes.
9. **ti-tls keeps its dependency on ti-pki, unchanged and not optional.** ti-pkcs12 and ti-cache stay crates of their own: ti-pkcs12 is a self-contained parser, and ti-cache's policy is shared by ti-pki (TSL) and ti-connector-client (SDS).
10. **ti-app is a Tauri app in a workspace of its own,** so its dependency tree stays out of rust/Cargo.lock and the workspace audits. Its commands are async and run ti-client in `spawn_blocking`.

ZETA is left out. It works differently from the other products and gets its own decision.

## Consequences

- **The crates afterwards are:**
  - jwz, ti-jwz
  - ti-types, ti-cache
  - ti-pki, ti-tls, ti-pkcs12
  - ti-connector-client, ti-idpd-client, ti-directory-client
  - ti-client
  - ti-cli, ti-wasm
  - ti-app, in its own workspace
- **Two crates go and one is new.** ti-report and ti-jwks go; ti-client is new; ti-idpd and ti-directory are renamed.
- **The ureq dependency leaves every product crate.** A browser or another host brings its own transport and nothing more.
- **ti-jwks's caching rules live in ti-client and are no longer reusable without it.** A second native host, such as a server, would copy them or bring them back as a small crate.
- **ti-pki carries a `model` module and an optional `serde` feature,** which ti-cli and ti-wasm enable.
- **ti-wasm compatibility depends on clients never assuming Send.** TASK-252 adds a test implementation that is not Send for every host trait.
- **The work:**
  - TASK-243: jwz resolver and closure clock
  - TASK-244: time as a function, ti-types
  - TASK-245: async ti-idpd transport
  - TASK-246: renames, directory without ti-idpd
  - TASK-247: offline check in ti-pki
  - TASK-248: `ti_pki::model`, ti-report removed
  - TASK-249: ti-client host library
  - TASK-250: commands in ti-client
  - TASK-251: RemoteJwks, ti-jwks removed
  - TASK-252: tests with hosts that are not Send
  - TASK-253: ti-app
