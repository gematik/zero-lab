# Profiles, store and cache

A **profile** bundles a download cache (`cache.db`), a sealed state (`state.db`) and a
keyring. It is shared with the other TI tools (zero-epa, zeta-cli). Profile in effect:
`--profile NAME`, else `TI_PROFILE`, else the one `ti profile use` chose, else `default`.

## Commands

```sh
ti profile create                       # keyring + key file, once
ti profile list                         # profiles, the active one, keyrings, sizes
ti profile show
ti profile use work                     # writes the active-profile file every TI tool reads
ti profile delete work --yes
ti profile rotate                       # new sealing key; drops keys no live record uses
ti profile rewrap --kek-file PATH       # wrap keys with another key file (then set TI_STORE_KEK_PATH)

ti store doctor                         # key file, keyring, databases, records: ok / warn / fail
ti store doctor --deep                  # also opens every sealed record
ti store ls [NS]                        # records; never ids or contents
ti store show NS ID                     # add --reveal to see secrets (don't, unless asked)
ti store rm NS ID
ti store purge NS --yes
ti store cleanup                        # expired records (also done daily automatically)
ti store migrate --dry-run              # report format levels

ti cache clear                          # empties the profile's cache (trust material, OCSP, service directories)
ti --offline pki verify card.pem        # work from the cache only
```

## What lives where

| | Linux, macOS | Windows |
| --- | --- | --- |
| Keyring, state | `$XDG_STATE_HOME/telematik/profiles/NAME/{keyring.bin,state.db}` | `%LOCALAPPDATA%\state\telematik\profiles\NAME\…` |
| Cache | `~/.cache/telematik/profiles/NAME/cache.db` | `%LOCALAPPDATA%\telematik\profiles\NAME\cache.db` |
| Key file | `~/.config/telematik/profiles/NAME/store.kek` | `%APPDATA%\telematik\profiles\NAME\store.kek` |

- The **cache** is disposable: downloaded TSLs/roots, OCSP responses (good/revoked,
  kept ≤ 1 hour and never past `nextUpdate`, re-verified when read back), Konnektor
  service directories. Entries are used without asking for an hour, then revalidated;
  material older than 24 h (prod) / 7 days (other envs) is not used.
- The **state** is what must not be lost or must stay secret: the TSL seen last (so an
  older list stays rejected) and comfort-signature IDs, sealed with AES-256-GCM. Without
  a keyring `ti` keeps none of it and says so (`store_no_keyring`): run
  `ti profile create`. Losing the key file loses only the sealed records.
- Store errors have kinds `store_<code>` with a hint.

## Isolated store for tests or HITL sessions

Set all three together so nothing touches the user's real profile:

```sh
export TI_CACHE_DIR=$PWD/.ti/cache
export TI_STATE_DIR=$PWD/.ti/state
export TI_STORE_KEK_PATH=$PWD/.ti/store.kek
ti profile create
ti store doctor
```

Other switches: `TI_STORE_BACKEND=files` (one file per record, for inspecting),
`TI_STORE_TRACE=1` (one stderr line per store operation: operation, namespace, first 8
bytes of the name, code, duration; never a payload).

## Guidance

- `store doctor` is read-only and the right first step for any `store_*` error.
- Don't run `profile delete`, `store purge`, `store rm` or `profile rotate` without the
  user asking: they destroy or re-key sealed state (`delete` and `purge` need `--yes`
  for exactly that reason).
- Never paste `store show --reveal` output into chat or logs.
