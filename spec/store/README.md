# Shared sealed store: requirements

Language-neutral specification of the local store the command-line tools of the telematics
infrastructure share: tokens, discovery documents, cached trust material and small state, kept per
profile, readable and writable by every conformant implementation on the same files. It is the
binding basis for the Rust store (`ti_store::store` and the `ti` backends), the Go store (`go/store`)
and a later JVM implementation (`zeta-cli`). An implementation built from this document alone and
checked against the corpus of [CONFORMANCE.md](CONFORMANCE.md) is conformant.

Each rule has one identifier `STORE-nnn`. Tests and the corpus manifest cite these identifiers. The
key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Contents

- [Scope](#scope)
- [References](#references)
- [Model](#model)
- [Rules](#rules)
  - [A. Encoding](#a-encoding)
  - [B. Operations](#b-operations)
  - [C. Namespaces and record types](#c-namespaces-and-record-types)
  - [D. Names and tags](#d-names-and-tags)
  - [E. Key derivation](#e-key-derivation)
  - [F. Records](#f-records)
  - [G. Keyring](#g-keyring)
  - [H. SQLite backend](#h-sqlite-backend)
  - [I. Files backend](#i-files-backend)
  - [J. Profiles](#j-profiles)
  - [K. Format levels and migrations](#k-format-levels-and-migrations)
  - [L. Operation](#l-operation)
- [Format levels](#format-levels)
- [Namespace registry](#namespace-registry)
- [Wrapper registry](#wrapper-registry)
- [Result codes](#result-codes)
- [Algorithm](#algorithm)
- [Deviations](#deviations)
- [Security considerations](#security-considerations)

## Scope

In scope:
- the operations a backend offers and their semantics;
- the sealed record format, the derivation of its keys, and the hashing of names and metadata;
- the keyring file and the `key-file` wrapper;
- the on-disk layout of the SQLite and files backends;
- profiles and where their files live.

Out of scope:
- server storage (`go/kv` on Postgres, [docs/design/servers.md](../../docs/design/servers.md)),
  which follows this contract in a later step;
- platform key wrappers (Keychain, Secure Enclave, TPM, DPAPI, passphrase), each registered here
  when it is specified;
- the content of the records: each consumer defines its own payload;
- cache policy (freshness, revalidation), which sits above the store.

## References

| Short name | Document |
|---|---|
| RFC 2119 | Key words for use in RFCs to Indicate Requirement Levels |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| RFC 2104 | HMAC: Keyed-Hashing for Message Authentication |
| FIPS 180-4 | Secure Hash Standard (SHA-256) |
| NIST SP 800-38D | Galois/Counter Mode (GCM), §8 on IV uniqueness and invocation limits |
| RFC 4648 | Base16 and Base64 encodings |
| SQLite | File format (https://sqlite.org/fileformat2.html), version 3.35.0 or later for `RETURNING` |
| XDG | XDG Base Directory Specification 0.8 |
| keys | [docs/design/keys.md](../../docs/design/keys.md) |
| decision-7 | Tokens persisted only as sealed records under a profile keyring (`rust/docs/backlog/decisions`) |

## Model

```text
profile ─┬─ keyring.bin   data keys, wrapped; profile id; current and index kid
         ├─ state.db      records that must survive: tokens, TSL state, comfort IDs
         └─ cache.db      records that may be lost at any time: discovery, OCSP, TSL bytes

record  = namespace, name, value, expires_at, tags
          name   = hash of the caller's id     (the id never reaches disk)
          value  = sealed envelope or plain record
          tags   = hashes of indexed metadata  (equality search only)
```

A **backend** stores records and answers the operations of section B. It sees names, tags, expiry
and values as bytes and never holds a key. The **store** sits above it: it turns ids into names,
metadata into tags, and payloads into values, using keys from the **keyring**. A **wrapper**
protects the data keys inside the keyring. Time is a parameter: no operation reads a clock.

## Rules

### A. Encoding

| Rule | Requirement |
|---|---|
| STORE-001 | `lp(x)` is the length of `x` in bytes as a 32-bit unsigned big-endian integer, followed by `x`. `u8`, `u16`, `u64` are unsigned big-endian integers of 1, 2 and 8 bytes. |
| STORE-002 | Times are whole seconds since 1970-01-01T00:00:00Z as `u64`, at most 253402300799 (9999-12-31T23:59:59Z), so that every language's time type holds them. In `expires_at` and `not_after`, 0 means "does not expire". A parser rejects a larger time in a record, record file or keyring as `malformed`; a writer given one fails with `invalid_argument`. |
| STORE-003 | A record is live at time `now` if its expiry is 0 or greater than `now`. A record whose expiry is less than or equal to `now` is expired. |
| STORE-004 | Strings that the rules give a syntax (namespace, field, kid, profile name, wrapper id) are ASCII and compared byte for byte. |
| STORE-005 | A parser MUST reject a value with bytes left over after the last field, a length field that runs past the end of the input, or a count above its limit, as `malformed`, and MUST NOT allocate beyond the input size because of a length field. |

### B. Operations

A backend offers these operations. `now` is a parameter of every operation that depends on time.

| Rule | Requirement |
|---|---|
| STORE-010 | `get(ns, name, now)` returns the value and expiry of a live record, or `not_found`. An expired record is `not_found` even if it is still stored. |
| STORE-011 | `put(record)` stores the record and replaces any record with the same `(ns, name)`, including all of its tags. A name that is not 32 bytes, a tag that is not 32 bytes, or a field or namespace outside its syntax is `invalid_argument`; more than 16 tags is `limit_exceeded`. |
| STORE-012 | `take(ns, name, now)` returns a live record and removes it, as one atomic step: of any number of concurrent `take`s of the same record, from any process and any implementation, exactly one returns it and all others return `not_found`. A backend without the capability `atomic_take` MUST NOT offer `take`. |
| STORE-013 | `delete(ns, name)` removes the record and its tags. Removing a record that does not exist succeeds. |
| STORE-014 | `batch(ops)` applies a list of `put` and `delete` operations so that a concurrent reader sees either none or all of them, and after a failure none of them is applied. A backend without the capability `atomic_batch` MUST NOT offer `batch`. |
| STORE-015 | `query(ns, filters, expiry_range, limit, cursor, now)` returns live records of `ns` that carry every tag in `filters` (a conjunction of `(field, tag)` equalities) and whose expiry lies in `expiry_range` (`[from, to)`, either end open; a record that does not expire counts as later than any time), in ascending order of `name` compared as bytes. |
| STORE-016 | `query` returns at most `limit` records, with `1 ≤ limit ≤ 1000`. If it returns exactly `limit` records it also returns a cursor, the last name returned; the next call with that cursor returns names strictly greater, and a call that returns fewer than `limit` records ends the paging. A limit outside the range, or a cursor that is not 32 bytes, is `invalid_argument`. |
| STORE-017 | `cleanup(now, limit)` removes `min(limit, number of expired records)` expired records with their tags and returns that number; `limit` is at least 1. Expired records MAY also be removed at any other time. |
| STORE-018 | A backend declares its capabilities: `atomic_take`, `atomic_batch`, `indexed` (query cost does not grow with the number of records outside the result) and `multi_process` (operations from several processes on the same files keep these rules). |
| STORE-019 | A store MUST refuse, when it is opened, a backend that lacks a capability one of its record types requires (STORE-022), with `capability_missing`. It MUST NOT degrade to weaker semantics. |

### C. Namespaces and record types

| Rule | Requirement |
|---|---|
| STORE-020 | A namespace matches `[a-z0-9][a-z0-9.-]{0,63}`. Namespaces are registered in the [namespace registry](#namespace-registry); a store MUST NOT write to an unregistered namespace. |
| STORE-021 | Each namespace is either `sealed` or `plain`, and lives in either `state.db` or `cache.db`, as the registry says. |
| STORE-022 | A record type declares its namespace, its maximum lifetime (`max_ttl`, 0 for none), its indexed fields, and the capabilities it requires. A `put` whose expiry is 0 while `max_ttl` is not 0, or later than `now + max_ttl`, is `invalid_argument`. |
| STORE-023 | A store with no keyring MUST refuse to read or write a sealed namespace, with `no_keyring`. It MUST NOT fall back to a plain record. |
| STORE-024 | The store MUST NOT hold private key bytes, PINs or passwords, sealed or not (keys rule 1). A key appears only as a handle or reference to where the key lives. |
| STORE-025 | Plain namespaces hold only data whose disclosure is harmless and whose integrity the consumer checks again on every read (signed trust material, signed responses, public discovery documents). |

### D. Names and tags

| Rule | Requirement |
|---|---|
| STORE-030 | The caller identifies a record by an `id` of 0 to 4096 bytes. The backend receives only its `name`, 32 bytes; the `id` MUST NOT be stored. |
| STORE-031 | In a sealed namespace, `name = HMAC-SHA-256(k_name, lp(ns) ‖ lp(id))`, with `k_name` from the index kid (STORE-042). |
| STORE-032 | In a plain namespace, `name = SHA-256(lp("zl-store/1/plain-name") ‖ lp(ns) ‖ lp(id))`. |
| STORE-033 | An indexed field name matches `[a-z0-9_]{1,32}`; its value is 0 to 4096 bytes. A record has at most 16 tags. |
| STORE-034 | In a sealed namespace, `tag = HMAC-SHA-256(k_index, lp(ns) ‖ lp(field) ‖ lp(value))`; in a plain namespace, `tag = SHA-256(lp("zl-store/1/plain-tag") ‖ lp(ns) ‖ lp(field) ‖ lp(value))`. The field name is stored as is, next to the tag. |
| STORE-035 | A record MAY carry several tags of the same field (several values). A query filter `(field, tag)` matches a record that carries that pair. |
| STORE-036 | Personal identifiers (KVNR, Telematik-ID, ICCSN, names) and any secret MUST NOT appear in an id or tag value of a plain namespace, and MUST NOT appear anywhere on disk except inside a sealed value. |

### E. Key derivation

| Rule | Requirement |
|---|---|
| STORE-040 | Every kid has one data key `dk` of 32 bytes from a cryptographically secure random generator. |
| STORE-041 | From `dk`: `k_value = HKDF-SHA-256(ikm = dk, salt = "zl-store/1", info = "value", L = 32)`, `k_name` with `info = "name"`, `k_index` with `info = "index"`. |
| STORE-042 | Values are sealed with `k_value` of the keyring's current kid and opened with `k_value` of the kid in the record. Names and tags use `k_name` and `k_index` of the keyring's index kid, for every record of the profile. |
| STORE-043 | Changing the current kid needs no rewrite: records sealed under an older kid stay readable while that kid is in the keyring. The index kid is fixed for the life of the profile: names and tags cannot be computed again, because ids and tag values never reach disk (STORE-031, STORE-034). Replacing it means a new profile (STORE-096, STORE-121), which loses only the sealed records (STORE-132). |
| STORE-044 | A kid is removed from the keyring only when no live record is sealed under it, and never while it is the current or the index kid. The kid of a sealed record is read from its header (STORE-050) without opening it. |
| STORE-045 | Keys derived here and data keys MUST be held in memory that is overwritten when released, where the language allows it, and MUST NOT be logged. |

### F. Records

**Sealed record**, version 1:

```text
0x01 ‖ u8 kid_len ‖ kid ‖ u64 not_after ‖ nonce[12] ‖ ciphertext ‖ tag[16]

aad = lp("zl-store/1") ‖ lp(profile_id) ‖ lp(kid) ‖ lp(ns) ‖ lp(name) ‖ u64 not_after
ciphertext ‖ tag = AES-256-GCM(k_value, nonce, payload, aad)
```

**Plain record**, version 0:

```text
0x00 ‖ u64 not_after ‖ payload
```

| Rule | Requirement |
|---|---|
| STORE-050 | The first byte of a value is its version. Version 1 is a sealed record, version 0 a plain record. A sealed namespace accepts only version 1, a plain namespace only version 0; anything else is `unsupported_version`. |
| STORE-051 | `kid` is 1 to 64 bytes in `[!-~]` (printable ASCII without space). A kid of length 0 or outside the range is `malformed`. |
| STORE-052 | The nonce is 12 bytes from a cryptographically secure random generator, new for every seal. |
| STORE-053 | `not_after` equals the record's `expires_at` in the backend (STORE-002). A writer MUST set both to the same value. |
| STORE-054 | A sealed record is at least 39 bytes. The payload of either version is at most 16 MiB; a longer one is `limit_exceeded`. |
| STORE-055 | To open a sealed record, the reader parses it (STORE-005, 050, 051), looks up the kid (`unknown_kid` if absent), and decrypts with the AAD built from its own context: profile id, the namespace and name it asked for, and the `not_after` in the record. Failure is `auth_failed`. Only then it checks `not_after` against `now` (STORE-003): an expired record is `expired`. |
| STORE-056 | The tag MUST be checked before any byte of the payload is released. An implementation MUST NOT return partial plaintext. |
| STORE-057 | A plain record's `not_after` is checked against `now` as in STORE-055; its payload has no integrity of its own (STORE-025). |
| STORE-058 | A writer SHOULD switch to a new current kid at least once a year, and MUST do so before 2^32 records are sealed under one kid (NIST SP 800-38D §8.3). |

### G. Keyring

`keyring.bin`, version 1:

```text
"ZLKR" ‖ u8 1 ‖ profile_id[16] ‖ lp(current_kid) ‖ lp(index_kid) ‖ u16 count ‖ entry{count}

entry = lp(kid) ‖ u64 created ‖ lp(wrapper_id) ‖ lp(wrapped)
```

| Rule | Requirement |
|---|---|
| STORE-060 | A keyring file starts with the magic `ZLKR` and the version 1. Another magic is `malformed`, another version `unsupported_version`. |
| STORE-061 | `profile_id` is 16 bytes from a cryptographically secure random generator, created with the keyring and never changed. |
| STORE-062 | `count` is 1 to 256. Kids are unique within the file. `current_kid` and `index_kid` MUST name entries of the file. A violation is `malformed`. |
| STORE-063 | `wrapper_id` names an entry of the [wrapper registry](#wrapper-registry). `wrapped` holds `dk` as that wrapper protects it, bound to `profile_id` and `kid`. An unknown wrapper is `unsupported_version`. |
| STORE-064 | A reader unwraps each data key it needs and MUST fail with `auth_failed` if a wrapper reports that `wrapped` was altered or bound to another profile or kid. |
| STORE-065 | A keyring file is written to a new file in the same directory, flushed to disk, and renamed over the old one; the directory is flushed after the rename. On POSIX systems it is created with mode 0600 in a directory of mode 0700. |
| STORE-066 | Removing a profile (STORE-096) or a keyring makes every sealed record of the profile unreadable; this is how a profile's data is destroyed. |

### H. SQLite backend

The schema is [schema.sql](schema.sql). `state.db` and `cache.db` share it.

| Rule | Requirement |
|---|---|
| STORE-070 | A database has `PRAGMA application_id = 1514951508` (`0x5A4C5354`, "ZLST"); another application id is `malformed`. `PRAGMA user_version` is the database's format level, and the table `meta` holds it with its compatibility level (section K). |
| STORE-071 | A new database is created by running `schema.sql` as it stands: `auto_vacuum = INCREMENTAL`, then `journal_mode = WAL`, both outside a transaction and before anything else is written, then the tables and `user_version` in one transaction. A database whose `auto_vacuum` is not incremental or whose journal mode is not WAL is still readable; an implementation SHOULD repair it. |
| STORE-072 | Every connection sets `foreign_keys = ON` and `busy_timeout` of at least 5000 ms. `state.db` uses `synchronous = FULL` and `secure_delete = ON`; `cache.db` MAY use `synchronous = NORMAL`. |
| STORE-073 | A write transaction starts with `BEGIN IMMEDIATE`. A transaction that still finds the database locked after the busy timeout fails with `busy`. |
| STORE-074 | `take` is one statement, `DELETE … WHERE ns = ? AND name = ? AND (expires_at IS NULL OR expires_at > ?) RETURNING value, expires_at`, which makes it atomic across processes (STORE-012). |
| STORE-075 | `expires_at` is `NULL` when the record does not expire, otherwise the record's `not_after`. Tags are stored in the table `tags` and removed with their record (STORE-011, STORE-013). |
| STORE-076 | Schema changes are migrations as in section K; `schema.sql` always creates the newest level. |
| STORE-077 | The database file and its `-wal` and `-shm` files are created with mode 0600 on POSIX systems. |
| STORE-078 | The SQLite backend has all capabilities of STORE-018. |

### I. Files backend

A fallback without a database library, for small stores.

```text
<root>/v1/<ns>/<h[0..2]>/<h[2..4]>/<h>.rec      h = lowercase hex of name

file = "ZLRF" ‖ u8 1 ‖ u64 expires_at ‖ u8 tag_count ‖ (lp(field) ‖ tag[32]){tag_count} ‖ value
```

| Rule | Requirement |
|---|---|
| STORE-080 | A record is one file at the path above, with the layout above. `tag_count` is at most 16 (STORE-033). |
| STORE-081 | A write goes to `<h>.tmp.<random>` in the target directory, is flushed, and is renamed to `<h>.rec`; the directory is flushed after the rename. |
| STORE-082 | `take` renames `<h>.rec` to `<h>.take.<random>` in the same directory. The process whose rename succeeds owns the record: it reads it, removes the file, and returns the record if it is live, `not_found` otherwise. A failed rename because the file is gone is `not_found`. |
| STORE-083 | `query` reads every file of the namespace; `cleanup` also removes `.tmp.` and `.take.` files older than one hour. |
| STORE-084 | The files backend has `atomic_take` and `multi_process`, and neither `atomic_batch` nor `indexed`. It holds all records of a profile on one file system. |
| STORE-085 | Files are created with mode 0600, directories with 0700, on POSIX systems. |
| STORE-086 | `<root>/meta` holds the format level of the tree: `"ZLFM" ‖ u16 level ‖ u16 min_compatible`, written as in STORE-081. A tree without it is created at the newest level the implementation writes. |

### J. Profiles

| Rule | Requirement |
|---|---|
| STORE-090 | A profile name matches `[a-z0-9][a-z0-9-]{0,31}`. |
| STORE-091 | The profile in effect is the first of: the command-line option `--profile`; the environment variable `TI_PROFILE`; the first line of the file `<config>/telematik/profiles/active`; `default`. An empty `TI_PROFILE` and an empty or missing first line count as not given; a trailing carriage return of the line is removed. A name that breaks STORE-090 from any of these is `invalid_argument`, never a fall-through to the next. |
| STORE-092 | `<state>` is `TI_STATE_DIR` if set, else `$XDG_STATE_HOME/telematik`, else `~/.local/state/telematik`; on Windows `%LOCALAPPDATA%\state\telematik`. `<cache>` is `TI_CACHE_DIR` if set, else `$XDG_CACHE_HOME/telematik`, else `~/.cache/telematik`; on Windows `%LOCALAPPDATA%\telematik`. `<config>` is `$XDG_CONFIG_HOME`, else `~/.config`; on Windows `%APPDATA%`. A relative XDG path is ignored. A relative or empty `TI_STATE_DIR` or `TI_CACHE_DIR`, or a missing home directory where one is needed, is `invalid_argument`. These apply on macOS too. |
| STORE-093 | A profile's files are `<state>/profiles/<name>/keyring.bin`, `<state>/profiles/<name>/state.db` and `<cache>/profiles/<name>/cache.db`; the files backend uses the directories `<state>/profiles/<name>/state` and `<cache>/profiles/<name>/cache` as `<root>`. |
| STORE-094 | The key-encryption key of the `key-file` wrapper is read from the file named by `TI_STORE_KEK_PATH`, or, if that variable is not set, from `<config>/telematik/profiles/<name>/store.kek`. A relative or empty `TI_STORE_KEK_PATH` is `invalid_argument`. Its content, after removing one trailing line feed, is 44 characters of standard base64 with padding (RFC 4648 §4) that decode to 32 bytes; anything else is `malformed`. On POSIX systems a file readable by group or others is `insecure_permissions`. |
| STORE-095 | A tool MUST NOT create a key-encryption key, a data key or a keyring on its own. Only `profile create` (STORE-121) creates them, on the user's request: the keyring (STORE-061) with one kid that is both current and index kid, and, unless the key file of STORE-094 already exists, that file with a new random key. Until then the profile has no keyring (STORE-023): its plain namespaces work, its sealed namespaces are refused with `no_keyring`. |
| STORE-096 | Removing a profile removes `keyring.bin` first and flushes its directory, then removes the databases and directories. |

### K. Format levels and migrations

Several tools in several languages, updated at different times, open the same profile. A format
level names everything an implementation reads and writes on disk together: the SQLite schema,
the files layout, the record versions and the keyring version ([format levels](#format-levels)).
Every database and files tree records two numbers: `level`, the level its contents are at, and
`min_compatible`, the lowest level an implementation must support to read and write it.

| Rule | Requirement |
|---|---|
| STORE-100 | An implementation supports a contiguous range of levels and knows the highest one, `max`. It opens a database or files tree if `min_compatible ≤ max`, even when `level > max`, and then reads and writes only what its own `max` level defines. If `min_compatible > max`, it is `unsupported_version` and MUST NOT write. |
| STORE-101 | The SQLite backend keeps `level` in `PRAGMA user_version` and both numbers in the table `meta` (`level`, `min_compatible`). The two `level` values MUST agree; if they do not, the database is `malformed`. The files backend keeps them in `<root>/meta` (STORE-086). |
| STORE-102 | Migrations are numbered and forward only: migration `n` takes a database from level `n − 1` to `n` and is specified in `migrations/<n>.sql` (SQLite) and in this section (files backend, records, keyring). There is no downgrade. |
| STORE-103 | Each migration runs in one `BEGIN IMMEDIATE` transaction that first reads `level` again and does nothing if another process has already migrated. It then applies the change and sets `user_version` and `meta` in the same transaction. A failed migration leaves the database at its old level. |
| STORE-104 | A change follows expand, migrate, contract. An expand migration adds tables, columns, indexes or record versions that older implementations ignore, and keeps `min_compatible`. Only a contract migration, which removes or changes what older implementations rely on, raises `min_compatible`, and only after implementations of the new level have been released for at least one release cycle. |
| STORE-105 | An implementation migrates a database only up to its own `max`, and only when it opens the database for writing. It MUST NOT raise `min_compatible` above what the migration specifies. |
| STORE-106 | A writer writes record and keyring versions that every implementation at `min_compatible` reads. A new record version (STORE-050) or keyring version (STORE-060) therefore arrives in two steps: a level that reads it, then a later level, raising `min_compatible`, that writes it. |
| STORE-107 | Records are migrated lazily: a reader that meets an older record version opens it and MAY re-seal it at the current version; no migration rewrites all records unless its level requires it, which is then stated with the level. |
| STORE-108 | `cache.db` and the cache files tree MAY be deleted and created anew instead of migrated, at any level; consumers already treat the cache as lost at any time. `state.db` MUST be migrated. |
| STORE-109 | A namespace never changes its kind (sealed or plain), its database, or the meaning of its payload. Such a change is a new namespace; the old one is no longer written and empties as its records expire, then leaves the registry. |
| STORE-110 | Payloads are the consumer's format; each consumer SHOULD version its payload so that it can read the payloads it wrote before. |

### L. Operation

How the tools that share a store are installed, checked, debugged and maintained, so that a user who
knows one of them knows all of them. `<tool>` is `ti`, `zero-epa` or `zeta-cli`.

| Rule | Requirement |
|---|---|
| STORE-120 | Every tool offers the commands of this section with these names, options and outputs: `<tool> profile …` and `<tool> store …`. A tool MAY leave out commands for namespaces it does not use, but not `profile create`, `profile list`, `profile use`, `profile delete` and `store doctor`. |
| STORE-121 | `profile create [<name>] [--kek-file <path>]` creates the profile's directories, its keyring and, if needed, the key file (STORE-095), and prints the paths of the key file, the keyring and the databases. With `--kek-file` it uses an existing key file and records nothing about it: the user sets `TI_STORE_KEK_PATH` or places the file at the default path. Creating a profile that already has a keyring is an error that names the keyring. |
| STORE-122 | `profile list` shows each profile under `<state>/profiles` with: active or not, keyring present, key file found, format level, and the size of each database. `profile use <name>` writes the active file (STORE-091). `profile delete <name>` follows STORE-096 after a confirmation that `--yes` skips, and removes the default key file of STORE-094 too. |
| STORE-123 | `store doctor` checks the profile in effect without changing it and reports each check as `ok`, `warn` or `fail`, with exit status 0, 0 and 1: profile name and where it came from; paths; key file found, mode, parses; keyring parses and every data key unwraps; format level and `min_compatible` of each database against the tool's own range; `PRAGMA quick_check`; number of records and of expired records per namespace; age of the current kid (warn after one year, STORE-058). `--deep` also opens every sealed record and counts those that do not open, by result code. `--json` prints the same as one JSON object, with the field names of this rule in snake case. |
| STORE-124 | `store ls [<ns>]` lists records with namespace, name (first 8 bytes in hex), expiry, payload size, kid and tag field names, never ids, tag values or payloads. `store show <ns> <id>` prints the payload of one record only with `--reveal`, and otherwise its metadata. `store rm <ns> <id>` removes one record, `store purge <ns>` all records of a namespace after a confirmation. |
| STORE-125 | `store cleanup` runs `cleanup` until nothing is left to remove and then `PRAGMA incremental_vacuum`. A tool that opens `state.db` or `cache.db` for writing also cleans up on its own, at most once a day per database, with a limit of 1000, recording the time in `meta` under `last_cleanup` (SQLite) or as the modification time of `<root>/last_cleanup` (files backend). |
| STORE-126 | `store migrate [--dry-run]` migrates both databases to the tool's highest level (section K) and reports each step; `--dry-run` reports what would be done. Migration also happens on open (STORE-105); the command exists to do it at a chosen time and to see it. |
| STORE-127 | `profile rotate` adds a new kid, makes it current (STORE-043) and removes the kids no live record uses any more (STORE-044), writing the keyring once (STORE-065). `profile rewrap --kek-file <path>` unwraps every data key with the current key file and wraps it with the new one, writing the keyring once; the records are not touched. Neither changes the index kid. |
| STORE-128 | `cache.db` that does not open (`malformed`, `unsupported_version`, failed `quick_check`) is moved aside to `cache.db.broken-<time>` and created anew, with a warning; at most the newest such file is kept. `state.db` that does not open is never moved, deleted or recreated by a tool on its own: the tool fails, names the file and the code, and points to `store doctor` and to `profile delete`. |
| STORE-129 | Error messages name the profile, the file concerned, the result code, and the next step from the [hint table](#hints). Tokens and other secret payloads never appear in messages, logs or traces. |
| STORE-130 | With `TI_STORE_TRACE=1` a tool writes one line per store operation to standard error: time, operation, namespace, the first 8 bytes of the name in hex, result code and duration. It writes nothing else of a record. The trace is produced at the tool's edge, around the backend; libraries do not log. |
| STORE-131 | For tests and HITL sessions, `TI_STATE_DIR`, `TI_CACHE_DIR` and `TI_STORE_KEK_PATH` (STORE-092, STORE-094) together give a complete, separate store in any directory, which `profile delete` or removing the directories cleans up. `TI_STORE_BACKEND=files` selects the files backend instead of SQLite, so records can be inspected as files; a tool rejects any other value than `sqlite` and `files`. |
| STORE-132 | Losing the key file or the keyring loses the sealed records and nothing else: tokens are obtained again by logging in, TSL state is built again from a verified TSL. `profile create` and `store doctor` say so where they mention the key file. |

#### Hints

| Code | Hint |
|---|---|
| `no_keyring` | the profile has no keyring: run `<tool> profile create [<name>]` |
| `malformed` (key file) | the key file is not a store key: check `TI_STORE_KEK_PATH`, or run `<tool> profile rewrap` from a working key file |
| `insecure_permissions` | run `chmod 600 <path>` |
| `auth_failed` (keyring) | the key file does not belong to this profile's keyring: check `TI_STORE_KEK_PATH`; without the right key file, `<tool> profile delete <name>` and log in again |
| `auth_failed` (record) | the record was altered or copied: run `<tool> store doctor --deep`, then `<tool> store rm` |
| `unsupported_version` | written by a newer tool: update `<tool>`, or use the newest tool installed |
| `busy` | another tool holds the database: wait for it, or find it with `<tool> store doctor` |
| `capability_missing` | the namespace needs the SQLite backend: unset `TI_STORE_BACKEND` |

## Format levels

| Level | `min_compatible` | Defines | Migration |
|---|---|---|---|
| 1 | 1 | schema.sql with `meta`; records versions 0 and 1; keyring version 1; files layout `v1` with `meta`; wrapper `key-file` | none (creation) |

A new level is added here with its migration and the levels it stays compatible with.

## Namespace registry

| Namespace | Kind | Database | `max_ttl` | Indexed fields | Content |
|---|---|---|---|---|---|
| `oauth.access` | sealed | state | 1 day | `issuer`, `audience`, `subject` | access tokens with their DPoP binding reference |
| `oauth.refresh` | sealed | state | 90 days | `issuer`, `subject` | refresh tokens |
| `popp` | sealed | state | 1 day | `kvnr`, `iccsn` | PoPP tokens |
| `comfort` | sealed | state | 0 | `konnektor` | comfort-signature user IDs |
| `tsl.state` | sealed | state | 0 | none | TSL rollback state (sequence numbers); sealed for integrity |
| `well-known` | plain | cache | 7 days | `issuer` | discovery documents and entity statements |
| `pki.tsl` | plain | cache | 30 days | none | TSL bytes as downloaded |
| `pki.roots` | plain | cache | 30 days | none | root certificate bundles as downloaded |
| `pki.ocsp` | plain | cache | 7 days | `issuer` | OCSP responses |
| `connector.sds` | plain | cache | 1 day | none | Konnektor service directories |

A new namespace is added here, with its kind and lifetime, before any implementation writes it.

## Wrapper registry

| Wrapper id | `wrapped` | Status |
|---|---|---|
| `key-file` | `nonce[12] ‖ AES-256-GCM(kek, nonce, dk, aad)` with `aad = lp("zl-keyring/1") ‖ lp(profile_id) ‖ lp(kid)` and `kek` from STORE-094; 60 bytes | specified |
| `passphrase`, `macos-keychain`, `secure-enclave`, `tpm2`, `dpapi` | — | reserved, TASK-104 |

## Result codes

| Code | Meaning |
|---|---|
| `ok` | the operation succeeded |
| `not_found` | no live record under that name |
| `expired` | a record was opened whose `not_after` has passed |
| `malformed` | a value, record, keyring, key file or database does not parse |
| `unsupported_version` | a version, wrapper or schema this implementation does not know |
| `unknown_kid` | a record names a kid that is not in the keyring |
| `auth_failed` | a record or wrapped key does not authenticate under its context |
| `limit_exceeded` | a size or count above its limit |
| `invalid_argument` | a namespace, field, profile name, limit or lifetime outside its rule |
| `capability_missing` | the backend lacks a capability a record type requires |
| `no_keyring` | a sealed namespace was used without a keyring |
| `insecure_permissions` | a key file readable by others |
| `busy` | the database stayed locked past the busy timeout |
| `backend_error` | an I/O or database error outside these rules |

The mapping of each code to the errors of each implementation is listed in
[CONFORMANCE.md](CONFORMANCE.md#result-code-mapping) as the implementations land.

## Algorithm

```text
put(type, id, payload, metadata, expires_at, now):
 1. check type.ns registered (STORE-020), lifetime (STORE-022), tag limits (STORE-033)
 2. sealed: keyring present (STORE-023), else no_keyring
 3. name := name(ns, id) (STORE-031/032); tags := tag(ns, f, v) for each indexed (f, v) (STORE-034)
 4. value := sealed: seal(current kid, nonce, payload, aad(ns, name, expires_at)) (STORE-041, F)
             plain:  0x00 ‖ u64 expires_at ‖ payload
 5. backend.put(ns, name, value, expires_at, tags)

get(type, id, now):
 1. name := name(ns, id); (value, expires_at) := backend.get(ns, name, now), else not_found
 2. version byte must match the namespace kind (STORE-050)
 3. sealed: parse, kid lookup, AES-GCM open with aad from (profile, ns, name, not_after) (STORE-055)
 4. not_after ≤ now → expired; return payload

query(type, filters, range, limit, cursor, now):
 1. tags := tag(ns, f, v) for each filter (STORE-034)
 2. backend.query(ns, tags, range, limit, cursor, now); open each value as in get, steps 2-4
```

## Deviations

None yet. Implementations that depart from a rule are listed here with the version that fixes them.

## Security considerations

What the rules protect:
- **Confidentiality of sealed payloads, ids and indexed metadata** against anyone who reads the
  files, backups or swap of the disk, as long as the data keys stay protected by their wrapper.
- **Integrity and binding.** A sealed record cannot be altered, moved to another name or namespace,
  copied into another profile, or given a later expiry without `auth_failed` (STORE-055). Raising
  `expires_at` in the database does not revive a record: the sealed `not_after` decides.
- **Single use.** `take` hands a record to exactly one caller across processes and languages
  (STORE-012, STORE-074, STORE-082).
- **Destruction.** Removing the keyring destroys a profile's sealed data, including copies in
  backups of the databases (STORE-066).

What they do not protect:
- **Rollback of a whole file.** Restoring an older `state.db` brings back records that were
  deleted or taken, each within its own `not_after`. A refresh token restored that way stays
  bounded by its server-side lifetime and rotation. Detecting this needs a monotonic counter
  outside the file, which no wrapper offers yet.
- **Rollback of the keyring's current kid.** Whoever can write `keyring.bin` can set the current kid
  to an older entry; this changes which key seals new records, not who can read them.
- **Traffic analysis.** Namespaces, record counts, sizes, expiry times and which records share a tag
  are visible in the database. Equal tags reveal equal metadata values within a profile.
- **The default key file.** Without `TI_STORE_KEK_PATH`, the key file lies in the user's configuration
  directory, beside the state directory, protected by the file system like the plain files the tools
  used before. A copy of the state directory alone, such as a backup, does not open; the user's
  account does. A platform wrapper (TASK-104) replaces the file with a key the hardware holds, by
  `profile rewrap`, without touching the records.
- **A process that holds the keyring.** Once unwrapped, the data keys are in that process's memory
  for its lifetime, together with every record it can open.
- **Format level downgrade.** Whoever can write the database can lower `min_compatible` and let an
  older implementation write to it. This gives no access to sealed data; it can only make an
  older, possibly flawed writer active again.
- **Plain namespaces** offer neither confidentiality nor integrity; their consumers verify what
  they read (STORE-025).
