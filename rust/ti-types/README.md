# ti-types

Shared vocabulary types for the gematik Telematikinfrastruktur (TI), used by every `ti-*`
crate so that they agree on what an environment is and what time it is:
- `Env` and `Tier`;
- `Timestamp`, seconds since the Unix epoch, with RFC 3339 parsing and formatting.

Time enters the TI crates as a function, `impl Fn() -> Timestamp`: libraries never read
the system time directly, so tests pass a closure such as `|| Timestamp(1_700_000_000)`,
a host passes `Timestamp::now`, and a browser passes a function over `Date.now()`.

```rust
use ti_types::{Env, Tier};

let env: Env = "pu".parse()?;
assert_eq!(env, Env::Prod);
assert_eq!(env.tier(), Tier::Prod);
# Ok::<(), ti_types::EnvParseError>(())
```

## What belongs here

> If it compiles in `no_std` and has no I/O, it may go into `ti-types`; otherwise it doesn't.

No HTTP, no crypto, no async, no product constants (URLs, anchors), no helper functions.
The default build has no dependencies, and serde is the only optional one;
`just core-deps` fails on any other.

## Stability

`ti-types` goes to 1.0 soon and is additive only from then on. Every enum is
`#[non_exhaustive]`, so a new environment is not a breaking change; the one exception is
`Tier`, whose production/non-production split is binary by definition. A breaking
redesign gets a new type rather than a major version bump, because a major bump would
split consumers into incompatible `Env` types.

## Features

| Feature | Effect |
| --- | --- |
| `std` | Links `std`; adds `Timestamp::now`, the operating system's wall clock (not on wasm32-unknown-unknown, where std has none) |
| `serde` | `Serialize`/`Deserialize` for `Env` as lowercase names; also accepts `pu`, `ru`, `tu` |

## License

EUPL-1.2. Copyright, licence and gematik's notes: [repository README](https://github.com/gematik/zero-lab#license).
