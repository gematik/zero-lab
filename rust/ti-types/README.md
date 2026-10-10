# ti-types

Shared vocabulary types for the gematik Telematikinfrastruktur (TI), used by every `ti-*`
crate so that they agree on what an environment is and what time it is:
- `Env` and `Tier`;
- `Timestamp`, seconds since the Unix epoch, with RFC 3339 parsing and formatting;
- `Clock`, the injected time source: libraries never read the system time directly,
  so tests use a fixed clock and wasm32 builds need no system time.

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
The default build has no dependencies.

## Stability

`ti-types` goes to 1.0 soon and is additive only from then on. Every enum is
`#[non_exhaustive]`, so a new environment is not a breaking change; the one exception is
`Tier`, whose production/non-production split is binary by definition. A breaking
redesign gets a new type rather than a major version bump, because a major bump would
split consumers into incompatible `Env` types.

## Features

| Feature | Effect |
| --- | --- |
| `std` | Links `std`; adds `SystemClock`, the operating system's wall clock (not on wasm32-unknown-unknown, where std has none); required by `clap` |
| `serde` | `Serialize`/`Deserialize` for `Env` as lowercase names; also accepts `pu`, `ru`, `tu` |
| `clap` | `clap::ValueEnum` for `Env`, including the aliases (implies `std`) |

## License

Copyright 2026 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](https://github.com/gematik/zero-lab/blob/main/rust/LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
   1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
   2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
   3. The software is the result of research and development activities, therefore not necessarily quality assured and without the character of a liable product. For this reason, gematik does not provide any support or other user assistance (unless otherwise stated in individual cases and without justification of a legal obligation). Furthermore, there is no claim to further development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
