# ti-cache

HTTP-style caching for gematik Telematikinfrastruktur (TI) clients: whatever a client
downloads (roots.json, the TSL, a Konnektor's service directory) goes through one
`Cache`, which
- serves an entry without asking the origin while it is younger than `max_age`;
- then revalidates it with its `ETag`/`Last-Modified`, so an unchanged body is not
  downloaded again;
- keeps serving the stored copy for `stale_if_error` when the origin fails, and says so;
- in offline mode never asks the origin at all.

The store is a dumb key/value trait (`CacheStore`); the semantics live in `Cache`, so a
store is trivial to back with memory, files, Redis or a browser API. The origin is a
closure per call, so one cache serves any kind of artefact.

```rust
use ti_cache::{Cache, CacheEntry, CachePolicy, MemoryCacheStore, Meta, OriginResponse, Source};
use ti_types::{Clock, Timestamp};

struct Now;
impl Clock for Now {
    fn now(&self) -> Timestamp {
        Timestamp(1_700_000_000)
    }
}

# futures_lite::future::block_on(async {
let cache = Cache::new(MemoryCacheStore::new(), Now, CachePolicy::default());
let sds = cache
    .get("example/v1/sds", async |_validators| {
        Ok::<_, std::io::Error>(OriginResponse::Body(CacheEntry {
            body: b"<ConnectorServices/>".to_vec(),
            meta: Meta::new(Now.now(), Source::Http),
        }))
    })
    .await?;
assert_eq!(sds.meta.source, Source::Http);
# Ok::<(), ti_cache::CacheLookupError<std::io::Error>>(())
# }).unwrap();
```

The cache is as untrusted as the network: callers verify what it returns exactly as
they verify a download.

Traits carry no `Send` bounds and the crate has no I/O, so it builds for
`wasm32-unknown-unknown`.

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
