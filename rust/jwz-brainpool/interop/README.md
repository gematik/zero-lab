# Brainpool interop

jwz's brainpool tokens against two independent implementations, both directions, as
fixtures in `../tests/data/interop` (table: `COVERAGE.md` there).

| Oracle | Here | Makes | Checks |
| --- | --- | --- | --- |
| Go `go/brainpool/josebp` | `go/` | compact JWS: `BP256R1`, ePA's `ES256` on BP-256 | compact JWS |
| Python jwcrypto | `python/` (venv `.venv`, `requirements.txt`) | `BP256R1` JWS, compact and JSON | `BP256R1` JWS, JWE to BP-256 keys |

Brainpool JWE is encryption only: jwz encrypts, jwcrypto decrypts.

`just jwz-interop` (design time; needs Go and Python 3) regenerates jwz's tokens, has both
oracles make theirs and check jwz's, and rewrites the coverage table. `cargo test -p
jwz-brainpool --test interop` (build time, part of `just check`) needs neither: it fails
when jwz's tokens changed since the oracles checked them, when an oracle refused one, or
when jwz refuses an oracle's token. The keys (`keys.json`) are made once with
`cargo run -p jwz-brainpool --example interop -- keys`.
