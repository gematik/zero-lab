---
id: doc-7
title: 'kv: durable store, cache and reliable pub/sub over Postgres and MariaDB (plan for review)'
type: specification
created_date: '2026-11-22 15:27'
---


# kv: durable store, cache and reliable pub/sub over Postgres and MariaDB

Status: plan for review (2026-11-22, revised 2026-11-25). Nothing of it is built and no tasks exist yet; each step
below becomes a task once agreed.

Decided by the maintainer on 2026-11-25: MariaDB is a required backend, not an option for later, and
`github.com/go-sql-driver/mysql` is approved as its driver. The interfaces are therefore designed for both
databases from the start, and the modules are cut so that no consumer carries a driver it does not use
([module structure](#module-structure)). Also decided that day:

- This repository builds the libraries; hosts are implemented elsewhere. The plan therefore ends at what a
  library offers: no migrate command, no image, no Job, no configuration variable, no rotation tool. What a host
  has to do with the libraries is collected in [what a host does](#what-a-host-does).
- A host ships as one image that holds both drivers; the database is chosen by the DSN.
- Every MariaDB topology must be expected: a single node, a primary with replicas, Galera with one or with several
  writing nodes. Nothing in the design may depend on a lock or an order that holds on one node only.
- Whether a server applies the schema itself is configurable; without the setting it runs no DDL
  ([schema](#schema-creation-and-migrations-a-server-without-ddl-rights)).

## Why

go/kv began as "the single persistence primitive" (kv.go). It now serves two different needs:

1. **ACID store**: single-use values (authorization codes, nonces, DPoP replays, login states since TASK-390),
   sessions, registrations. Losing or duplicating a write is a security defect (servers.md rule 11).
2. **Shared cache with fan-out for horizontal scaling**: verified federation documents (oidf), the
   revocation mirror of zero-pep-proxy and, with TASK-313, zaddy. A lost entry costs a refetch; what matters is
   that every replica learns a change quickly.

A deployment brings its database: Postgres or MariaDB. Both needs must be met on both, with the same interfaces
and the same contract tests; where MariaDB cannot do what Postgres can, the contract is the weaker of the two and
the difference is stated ([MariaDB](#mariadb-the-second-backend)).

Both run today through one `kv.Store` on one Postgres table, plus a best-effort `kv.Bus` (LISTEN/NOTIFY).
The second need is built around the gaps: kv/revoked (TASK-313) and zero-pep-proxy's kvRevocations keep a
local set, subscribe to the bus, and rescan all keys every 30 s because a notification can be lost.

## What exists

| Piece | What it does | Gaps |
|---|---|---|
| `kv.Store` | Get, Set, SetIfAbsent, SetMany (one tx), Take, Delete, Keys(prefix), Cleanup, Close; TTL per key | one durability for everything; no way to say "this may be lost" |
| `kv.Swapper`, `kv.Marker` | compare-and-swap; marks for re-keying (rule 22) | fine |
| `kv.NewSealed` | AES-GCM values bound to their key, keyring/keychain, keys stay clear (rule 10: callers hash secret key parts) | nothing for bus payloads |
| `kv.Bus` (memBus, pgBus) | Publish/Subscribe of strings, best effort | no resume after a gap, no tie to a write, payload in clear through the database |
| `kv/postgres` | one logged table `kv(key text PK, value bytea, expires_at, mark, ...)`, database/sql over pgx, schema applied on Open under an advisory lock (TASK-423, go/kv v0.7.0) | see below; a package of module go/kv, so every consumer of kv has pgx in its module graph |
| kv/revoked (TASK-313) | revoked-ID set over Store + Bus, reconcile by full key scan | the scan is what a reliable feed would replace |

Users: zero-pep-proxy (sessions, revocations, oidf documents, login states), zaddy (revocations, TASK-313),
zeta-authserver-go (pdp/kvstore: sessions, clients, registrations, seen-once, SetMany indexes, Swap), go/pdp (frozen).

What kv/postgres leaves on the table today:

- `key LIKE 'prefix%'` on a `text` primary key with the database's default collation cannot use the index: every
  `Keys` and `Marker` query scans the table (pdp/kvstore scans by prefix on hot paths).
- Every write is a synchronously committed, WAL-logged row, cache entries included.
- `Cleanup` deletes all expired rows in one statement; every replica runs it.
- `pg_notify` runs in its own statement, never in the transaction of the write it announces.
- database/sql instead of pgx's native pool: no pipelining or batches, no prepared statement cache control.

## Proposal

### 1. Say the class of data, not one store for all

Three capabilities, each a small interface in kv (no driver), each with a memory, a Postgres and a MariaDB
backend:

```go
// Store stays as it is: ACID, durable, the default.
type Store interface { /* unchanged */ }

// Durability tells what a store promises; a consumer that relies on a write surviving a crash checks it at start
// (single-use values must: a replay set lost in a crash re-admits every value still in its window).
type Durability int
const (
    Durable   Durability = iota // committed and replicated before the call returns
    Ephemeral                   // atomic, but may be lost on a crash or failover; for caches and mirrors
)
func DurabilityOf(s Store) Durability // via an optional method; wrappers pass it through

// Feed is a reliable, ordered stream of small events per topic: at least once, resumable from a cursor, with
// an optional retention. It replaces "Bus + full rescan".
type Feed interface {
    Publish(ctx context.Context, topic string, event []byte) (Cursor, error)
    Follow(ctx context.Context, topic string, from Cursor) (<-chan Event, error) // closes when ctx ends
    Latest(ctx context.Context, topic string) (Cursor, error)
}
type Event struct { Cursor Cursor; Payload []byte; At time.Time }

// Writer couples state and events: what it writes and what it announces commit together or not at all, so a
// subscriber never hears of a change that did not happen, nor misses one that did.
type Writer interface {
    Apply(ctx context.Context, w Write) error
}
type Write struct {
    Set     []Entry
    Delete  []string
    Publish []Publication // {Topic, Payload}
}
```

The contract of `Feed` is what both databases can keep: at least once, in order per topic, resumable. How fast an
event arrives is a property of the backend, not of the contract: Postgres pushes, MariaDB polls
([MariaDB](#mariadb-the-second-backend)). A consumer must not depend on push.

`Bus` stays for what it is (best-effort signals inside one deployment) and is documented as such; new code uses
`Feed`. MariaDB gets no `Bus`. Revocations become: `Apply(Write{Set: revoked key, Publish: revoked id})`, and every replica keeps a local
set from `Follow(topic, cursor)`; after a restart it reads the durable keys once and follows from `Latest`. No
periodic rescan.

### 2. Postgres: two table classes and an event log

| Table | Kind | Holds |
|---|---|---|
| `kv` (existing) | logged | durable records, as today |
| `kv_cache` | `UNLOGGED` | ephemeral records: no WAL, several times faster writes, truncated after a crash and absent on streaming replicas, which is exactly the Ephemeral promise |
| `kv_feed` | logged, `id bigint GENERATED ALWAYS AS IDENTITY`, `topic`, `payload bytea`, `created_at` | the event log behind Feed; retention by time per topic |

Features used, each for a reason:

- **Index for prefixes**: `key text COLLATE "C"` (or a `text_pattern_ops` index) so `Keys`/`Marker` are range
  scans. Added without rewriting the table: a second index first, the column change in a later release (rule 22).
- **Atomic single statements** (as today, kept): `INSERT … ON CONFLICT DO NOTHING RETURNING` (SetIfAbsent),
  `DELETE … RETURNING` (Take), `UPDATE … WHERE value = $old` (Swap), `SetMany`/`Apply` in one transaction.
- **Asynchronous commit for the ephemeral class only**: `SET LOCAL synchronous_commit = off` inside the
  transactions that touch only `kv_cache`; durable writes keep synchronous commit. This is the "Redis-like" mode:
  writes return without waiting for the WAL flush; a crash loses at most the last few hundred milliseconds,
  which the Ephemeral class allows anyway.
- **Transactional NOTIFY**: `Apply` inserts into `kv_feed` and calls `pg_notify(topic, id)` in the same
  transaction; Postgres delivers notifications only on commit. The notification carries the event id only (well
  under the 8000-byte payload limit, nothing secret); a follower that wakes up reads `kv_feed WHERE topic = $1 AND
  id > $cursor ORDER BY id`. A missed notification costs latency until the next one or a slow poll (e.g. 30 s), not
  correctness.
- **Ordered commits per topic**: ids from an identity column become visible in commit order, not id order, so a
  follower reading `id > cursor` could step over an event that commits later with a smaller id. `Apply` therefore
  takes `pg_advisory_xact_lock(hashtext(topic))` before it inserts into `kv_feed`: publishes to one topic commit one
  after another, and their ids rise in commit order. The topics here see few events (revocations, invalidations),
  so serialising them per topic costs nothing measurable; a busy topic would need another scheme and is out of scope.
  MariaDB cannot use such a lock across a Galera cluster and orders events by a counter row per topic
  ([MariaDB](#mariadb-the-second-backend)); whether Postgres uses the same counter row, for one design in both
  backends, is open question 6.
- **One cleaner, not every replica**: `pg_try_advisory_lock` around `Cleanup` and feed retention; deletes in
  batches (`DELETE … WHERE ctid IN (SELECT ctid … LIMIT 1000)`) so a backlog of expired rows never takes long locks.
- **pgx native pool** (`pgxpool`) instead of database/sql: prepared statements, batches for `SetMany`, and
  `LISTEN` on a dedicated connection with reconnect.
- **Counters** (for the rate limiter of TASK-301, later): `INSERT … ON CONFLICT DO UPDATE SET n = kv_counter.n + 1
  RETURNING n` on an unlogged table.

Not used, on purpose: logical replication and triggers (more moving parts than the gain), partitioned tables
(retention by batched deletes is enough at our volumes; revisit with measurements), extensions such as pg_cron
(not available on every managed Postgres).

### 3. Encryption

Today: `NewSealed` seals values with the key as associated data; keys stay clear, callers hash secret key parts
(rule 10). The plan keeps that and closes the new paths:

- **Ephemeral store**: `NewSealed` works unchanged over `kv_cache`; the same keyring or keychain, the purpose names
  the class, so a sealed durable record cannot be replayed into the cache table or back.
- **Feed payloads**: `NewSealedFeed(feed, keys, purpose)` seals each payload with AAD = purpose ‖ topic, and the
  event id where the backend assigns it before the write (`nextval` in the same transaction). Payloads never pass
  through `pg_notify`, which only carries the id, so the database's notification queue and logs see no content.
- **Topic names** are clear like keys: a topic carries no secret; a per-subject topic uses the hashed subject.
- **Re-keying** (rule 22): kv keeps offering the parts and no more: `Marker` in every backend and over both record
  tables, MariaDB included, and `Resealer` (`Others`, `Reseal`, `Rename`, `SealedByKeys`) above them; the contract
  tests cover them in each backend. Feed events are short-lived: a key rotation waits out the retention of the
  topics sealed under the old key. The walk that takes records along, its schedule, the command that adds a
  keychain entry and the signal that an old key may go belong to the host, which knows its kinds of records;
  zeta-authserver-go has them (`Rekey`, `keychain-add`).

### 4. Memory backend

`NewMemory` gets an ephemeral twin (same code, Durability Ephemeral) and `NewMemoryFeed` (a slice per topic with
cursors, retention, a broadcast to followers), so every consumer's tests run the same contract. One shared
contract test suite (`kv/kvtest`) runs against memory and, gated by `TEST_DATABASE_URL` and `TEST_MARIADB_DSN`,
against Postgres and MariaDB.

## Schema creation and migrations: a server without DDL rights

Today `postgres.Open` runs the schema (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE`, a `DO` block) on every start:
every replica's database role must own the tables, and a compromised server can drop or alter them. zaddy now
inherits the same need (TASK-313). Replicas that started together on an empty database raced on it until
go/kv v0.7.0 put the statements under an advisory lock (TASK-423); that lock is the stopgap, and it goes with the
DDL when `Open` runs none. The plan separates the two roles:

- **Migrations are code of their own.** Each backend keeps numbered, embedded SQL steps and a table
  `kv_schema(version, applied_at)`. `Migrate(ctx, db, to)` applies the steps up to `to` with one migrator at a
  time: under `pg_advisory_lock` on Postgres, a row of `kv_schema` locked `FOR UPDATE` on MariaDB. On Postgres each step is one transaction.
  MariaDB commits implicitly at every DDL statement, so a step there is one statement that can be repeated
  (`IF NOT EXISTS`, `IF EXISTS`), and the version is recorded after it: a migrator that died in a step repeats it.
- **`Migrate` is a function, not a program.** Each backend exports `Migrate(ctx, db, to, opts)` over a connection
  the caller opened with whatever credentials it has. The program that calls it with admin credentials, its image
  and the Job that runs it before a rollout are the host's ([what a host does](#what-a-host-does)).
- **Rights are documented, not granted.** Each backend's documentation lists what a server role needs: `SELECT,
  INSERT, UPDATE, DELETE` on the tables, on Postgres also `USAGE` on the sequence of `kv_feed`. Whoever runs the
  database grants them, with the tools roles are managed with there. A role that lacks a right for a table a new
  release added fails at its first statement on it; `Open` cannot tell beforehand.
- **The server runs no DDL unless told to.** By default `Open` reads `kv_schema` and refuses to start when the
  version is below what it needs or above what it knows how to read (servers.md rule 17), naming both. With the
  option `WithMigrate()`, which a host sets from a setting of its own (off unless set), `Open` first applies the
  missing expand steps itself, under the same lock as `Migrate`, and reports through the logger it was given that
  it did; it never runs a contract step. This is for deployments without a migration job (docker compose, a first
  installation by hand); the server's role then needs DDL rights, which the default exists to take away. Without
  the option its role
  has DML rights only, so it cannot change the schema even if compromised. LISTEN/NOTIFY and advisory locks on
  Postgres need no extra rights.
- **Expand, migrate, contract** (rule 22) map onto the migrator's steps: release N+1's migrator adds (expand)
  before N+1 rolls out; a later step that removes (contract, e.g. the `metadata` column) is marked so and runs only
  when `Migrate` is called with `Contract()`, after no replica of N is left.
- **Development and tests**: the memory backend needs nothing; the gated Postgres and MariaDB tests run `Migrate`
  first.

This becomes a rule of its own: proposed for servers.md rule 8 or 23, "a server's database role has no DDL rights;
schema changes run in a separate job with their own credentials". To be decided with the review.

## MariaDB, the second backend

Required (maintainer, 2026-11-25). The durable store and the cache map onto MariaDB; the feed has no push and
polls. The facts below are from the documentation and are verified against the required version by the contract
tests before anything is claimed. The target is not one system: any maintained MariaDB in any topology must be
expected (maintainer, 2026-11-25). The contract tests therefore run against the oldest and the newest LTS release
maintained when the backend is built, and against a Galera cluster of three writing nodes.

| Need | Postgres | MariaDB |
|---|---|---|
| Atomic get-and-delete (Take) | `DELETE … RETURNING` | `DELETE … RETURNING` (since 10.0.5) |
| Set if absent or expired | `INSERT … ON CONFLICT DO UPDATE … WHERE expired RETURNING` | `INSERT … ON DUPLICATE KEY UPDATE` with `IF(expires_at <= NOW(6), …)` and `ROW_COUNT()` (1 inserted, 2 replaced, 0 kept) |
| Compare-and-swap | `UPDATE … WHERE value = $old` | the same, `ROW_COUNT()`; no `UPDATE … RETURNING` needed |
| Prefix scans on an index | `COLLATE "C"` / `text_pattern_ops` | `VARBINARY` key or a `_bin` collation; `LIKE 'p%'` then uses the index |
| Expiry from the database clock (TASK-107) | `now() + interval` | `NOW(6) + INTERVAL ? MICROSECOND` |
| Ephemeral table | `UNLOGGED` | no per-table equivalent: InnoDB is always logged; `MEMORY` holds no BLOB/TEXT; Aria with `TRANSACTIONAL=0` is not crash-safe and not transactional with InnoDB. The cache table stays InnoDB, and the Ephemeral promise is kept by semantics, not speed |
| Asynchronous commit | `SET LOCAL synchronous_commit = off` per transaction | `innodb_flush_log_at_trx_commit` is global only; no per-transaction switch |
| Push for the feed | `LISTEN`/`NOTIFY`, transactional | none. Followers poll `kv_feed WHERE topic = ? AND id > ?` on an index (e.g. every second), which is cheap, or MaxScale/binlog CDC, which we do not want |
| Ordered events per topic | advisory transaction lock, ids of an identity column | a counter row per topic, `UPDATE kv_topic SET seq = seq + 1 WHERE topic = ?`, in the transaction that inserts the event with that `seq`; no `GET_LOCK`, no `AUTO_INCREMENT` (see Galera below) |
| One migrator | `pg_advisory_lock` | a row of `kv_schema` taken with `SELECT … FOR UPDATE`; DDL itself is replicated in total order by Galera |
| One cleaner | `pg_try_advisory_lock` | none needed: several cleaners deleting expired rows in batches only cost a retry |
| Schema steps | transactional DDL | every DDL statement commits implicitly: steps are single, repeatable statements |
| Marks for re-keying (rule 22) | two nullable columns | the same |
| Expiry | batched `DELETE` | batched `DELETE … LIMIT`; the event scheduler is not used (needs rights the server should not have) |

Consequences for a deployment on MariaDB:

- Revocations reach other replicas within the poll interval (about a second), not at once. That is still far
  better than today's 30-second rescan, and it is what the `Feed` contract promises.
- The ephemeral class is as durable and as slow as the durable one. At our volumes (sessions, federation
  documents) InnoDB is expected to suffice; to be confirmed by measurement before it is claimed.
- No session-scoped lock is used, so no connection is pinned and a broken connection leaves nothing held.

**No Redis/Valkey needed for MariaDB.** A one-second poll per replica and topic on the indexed `kv_feed` is a
negligible load (ten replicas: ten small queries a second per topic). Valkey becomes worth its extra component
only when sign-outs must arrive everywhere well under a second or the cache's write rate measurably exceeds
InnoDB; then it backs the Ephemeral class and the Feed only (`SET NX PX`, `GETDEL`, a Lua script for Swap, Streams
with their ids as cursors), never single-use values, which a Valkey failover can lose. It would be a module of
its own like the other backends.

**Galera with several writing nodes is in scope.** Three things that hold on one node do not hold across a
cluster, and the design avoids each:

- `GET_LOCK` is local to a node. Nothing uses it; where one writer at a time is needed, it is a row lock, which
  Galera settles at commit.
- `AUTO_INCREMENT` interleaves ids per node (`auto_increment_increment`), so ids do not rise in commit order and a
  follower reading `id > cursor` can step over an event. The cursor is therefore the per-topic `seq` from the
  counter row: two transactions that raise the same counter on two nodes conflict at certification, one is rolled
  back with a deadlock error and repeated by the backend, and the `seq` values that commit are gapless and in
  commit order on every node. The same scheme is correct on a single node and on Postgres (where the row lock
  serialises), so the Feed has one design, and Postgres' advisory lock per topic becomes an optimisation to
  decide on, not a second mechanism.
- A write on one node is not at once visible on another. A single-use value set through node A and taken through
  node B a moment later may not be found: for an authorization code that is a failed login, not a replay, but it
  is a defect all the same. The backend sets `wsrep_sync_wait` for its sessions so that a read waits until the
  node has applied what the cluster committed; the cost is latency per read, to be measured. Atomicity is not at
  stake: of two `Take`s of one record on two nodes one fails certification, is repeated, and finds nothing.

Every statement of the MariaDB backend is written to be repeated on a deadlock or certification failure (errors
1213 and 1205), a bounded number of times; the contract tests run each single-use operation concurrently through
different nodes. All of this is to be proven by those tests against a real cluster before it is claimed; if
`wsrep_sync_wait` or the counter row do not hold what is written here, the plan comes back for review.

**The driver.** `github.com/go-sql-driver/mysql` v1.10.2 (approved 2026-11-25), looked at on that day: pure Go, no
cgo, no `unsafe`; it requires one module, `filippo.io/edwards25519` v1.2.0 (for the `client_ed25519`
authentication plugin), which is pure Go without `unsafe`, with assembly for amd64 field arithmetic and no
requirements of its own. zaddy already has both in its module graph through Caddy. The evaluation under
[dependencies](../../docs/conventions/dependencies.md) is recorded with the task that adds it.

## Module structure

Aim: a consumer's module graph and binary hold the driver of the database it uses and no other; a library that
only needs a store holds none.

Today go/kv is one module with three packages: `kv` and `kv/revoked` import the standard library only,
`kv/postgres` imports pgx. A consumer that imports only `kv` links no pgx, but pgx and its five requirements
(puddle, pgpassfile, pgservicefile, x/sync, x/text) are requirements of go/kv's `go.mod` and so part of every
consumer's module graph: they take part in version selection, appear in `go.sum` and in what a scanner reads from
`go.mod`. Adding the MariaDB backend as a third package would add its driver to all of them, Postgres-only
deployments included.

Proposed: one module per backend, the core without any requirement.

| Module | Packages | Requires | Tag |
|---|---|---|---|
| `go/kv` | `kv` (Store, Durability, Feed, Writer, memory backends, Sealed, Keyring, Keychain), `kv/revoked`, `kv/kvtest` (the contract tests, importing `testing` only), `kv/schema` (numbered steps, version check; no SQL dialect, no driver) | nothing outside the standard library | `go/kv/vX` |
| `go/kv/postgres` | `postgres` (Open, the steps, `Migrate`) | go/kv, pgx | `go/kv/postgres/vX` |
| `go/kv/mariadb` | `mariadb` (Open, the steps, `Migrate`) | go/kv, go-sql-driver/mysql | `go/kv/mariadb/vX` |

What follows from it:

- **Libraries** (pep, oidf, dpop, nonce and what comes) take `kv.Store`, `kv.Feed` as parameters and require at
  most go/kv: no driver in their graph. This is already how they are written; pep does not require kv at all.
- **Hosts choose.** Only programs import a backend, each in one file: zeta-authserver-go, and in this repository
  zero-pep-proxy, zaddy and the frozen zero-pdp. A host imports both backend modules and links both drivers, in
  one image (decided 2026-11-25); which one runs is chosen by the DSN's scheme.
- **A migration program holds one driver.** Because `Migrate` lives in the backend's module, a host can build a
  migrator for one database that imports that module alone, so the image that holds admin credentials holds one
  driver and no server code.
- **The import path of the Postgres backend does not change** (`…/go/kv/postgres`): consumers add one requirement
  and change no code. Carving a nested module out of a released module has one trap: a build that sees an old
  go/kv (which still contains the package) and the new go/kv/postgres finds the package twice and fails as
  ambiguous. The first go/kv/postgres therefore requires the go/kv release that no longer contains the package,
  so version selection can never pair them; both are tagged from the same commit, go/kv first.
- **Contract tests travel with the core.** Each backend module's tests call `kvtest.Store(t, open)`,
  `kvtest.Feed(t, open)`; `kvtest` imports `testing`, which only test binaries link.
- **A later backend** (Valkey for the Ephemeral class and the Feed) is one more module beside these, with no
  effect on consumers that do not use it.
- go/kv keeps its 0.x versions; the two backends start at the version of the go/kv they are cut
  from and move on their own afterwards. `go.work`, the Justfile's module lists and `AGENTS.md` get the two rows.

Considered and not proposed:

- *One module, build tags per driver*: the binary is clean, the module graph is not, and `go vet`, linters and
  editors see only the tagged half.
- *A registry in kv (`kv.Register(scheme, opener)`, blank imports, like database/sql)*: hides which backends a
  binary holds behind init-time global state; an explicit switch in the command's one wiring file says it.
- *A migrate command in this repository*: it is a host (credentials from files, an image, a release of its own),
  and hosts are built elsewhere; the library exports what such a command calls.

## What a host does

The libraries leave these to the program that uses them. They are listed so that a host's plan can be checked
against them, and they are not tasks of this repository.

| Matter | The library gives | The host does |
|---|---|---|
| Choosing the database | `postgres.Open`, `mariadb.Open` returning the same interfaces | reads the DSN from a file, picks the backend by its scheme, one wiring file per backend |
| Schema | `Migrate`, the version check in `Open`, `WithMigrate()` | a migration program per database with admin credentials, its image, the Job before a rollout, `Contract()` when no old replica is left; or the setting that turns `WithMigrate()` on |
| Roles | the list of rights a server role needs, in the backend's documentation | creates the roles, grants the rights again when a release adds a table, keeps the admin credentials out of the server |
| Class of data | `Durability`, `DurabilityOf` | puts each kind of record into the class it needs and refuses at start a store that promises less |
| Events | `Feed`, `Writer.Apply`, `NewSealedFeed` | topics, retention, the local state built from `Follow`, what happens while the feed cannot be read |
| Keys | `Keyring`, `Keychain`, `Unwrapper`, `Sealed`, `Marker`, `Resealer` | where the files and the key-encryption key come from, adding a keychain entry, the walk that reseals, when an old key goes |
| Cleaning | `Cleanup`, feed retention as calls | when and how often they run |
| Health and metrics | errors, and counts such as `SealedByKeys` | probes, metrics, logs |

zero-pep-proxy and zaddy are hosts that live in this repository and use kv today. Whether they follow this plan
here or are replaced by hosts elsewhere is open question 8.

## Migration (servers.md rule 22: mixed versions work)

0. The modules are cut ([module structure](#module-structure)): go/kv without the Postgres package, go/kv/postgres
   as a module, unchanged in behaviour; the programs that import it add the requirement. Nothing else changes in this step,
   so that a mistake in the cut shows alone.
1. Release N: migrations, `Migrate` and `WithMigrate()`; a host either runs `Migrate` before its rollout
   or sets the option before it takes this release, and the release notes say so as a breaking change; new tables
   and indexes are additive, nothing reads them yet. kv/postgres moves to pgxpool behind the same `kv.Store`. go/kv/mariadb appears with
   `kv.Store` and the contract tests; it never applies a schema itself.
2. Release N+1: `Feed`, `Writer`, `Durability` in kv and both backends; revocations of zero-pep-proxy and zaddy
   write both the old way (key + Bus) and the Feed; followers read the Feed. oidf documents move to the ephemeral
   store.
3. Release N+2: the Bus path of revocations and kv/revoked's rescan go; the old `metadata` column goes.

Consumers that need durability (`kv.DurabilityOf(store) == kv.Durable`) refuse an ephemeral store at start:
zero-pep-proxy's login states and replay sets, zeta-authserver-go's seen-once and codes.

## Open questions for review

1. **Names**: `Feed` and `Writer.Apply`, or one `Tx(ctx, func(Tx) error)`? Apply is declarative and keeps
   backends simple (memory, and a future one); a callback transaction is more flexible but leaks backend
   semantics. Recommendation: Apply.
2. **Sessions**: durable (survive a database crash; today's behaviour) or ephemeral (faster; a crash signs
   everyone out)? Recommendation: durable for zero-pep-proxy's sessions, ephemeral for the oidf documents and the
   revocation mirror.
3. **Feed retention**: per topic by time (revocations: the snapshot TTL, 8 h) or by count? Recommendation: by
   time, set by the publisher.
4. **zeta-authserver-go**: does it adopt Feed for its revocations (its Revocations(since) iterator maps onto Follow) in
   the same step, or later? It is the largest user.
5. **Scope of pgxpool**: kv/postgres already requires pgx; switching from database/sql to pgxpool adds no module
   but uses more of pgx. To confirm under the dependency rules.
6. **One ordering scheme or two**: MariaDB orders events by a counter row per topic. Does Postgres use the same
   (one design, one set of tests, a row update per publish) or keep the advisory lock with identity ids (no extra
   row, a second mechanism)? Recommendation: the counter row in both.
7. **`wsrep_sync_wait`** costs latency on every read of the MariaDB backend, also on a single node where it does
   nothing useful. Always on, or only when the server reports it is part of a cluster (`wsrep_on`)?
   Recommendation: only in a cluster, decided at `Open`.
8. **The hosts in this repository**: zero-pep-proxy and zaddy import kv/postgres. With hosts built elsewhere, do
   they adopt the new libraries (the module cut forces at least a changed requirement), stay on Postgres only, or
   go the way of zero-pdp?

## Tasks this would become

Not created yet (maintainer, 2026-11-25): the plan is reviewed first.

- kv: cut the modules: go/kv without requirements, go/kv/postgres as a module at the same import path; `go.work`,
  Justfile, `AGENTS.md`, the requirements of the programs here that import it.
- kv: `kv/schema` and `kv/kvtest`; numbered migrations and `kv_schema` in kv/postgres, `Migrate`,
  `Open` that checks the version and applies steps only with `WithMigrate()`; the rights of a server role
  documented (and the servers.md rule, if agreed).
- kv/mariadb: the module with the driver's evaluation, `kv.Store`, `Swapper`, `Marker` over MariaDB, its
  migrations and `Migrate`, the contract tests gated by `TEST_MARIADB_DSN` against the oldest and newest
  LTS and a Galera cluster, the gated suite listed in the development guide.
- kv/postgres: prefix index (`COLLATE "C"` / `text_pattern_ops`), batched and advisory-locked Cleanup, pgxpool.
- kv: `Durability`, ephemeral memory store, `kv_cache` in both backends (unlogged and asynchronous commit on
  Postgres, InnoDB on MariaDB).
- kv: `Feed` + `Writer.Apply` with memory, Postgres (`kv_feed`, transactional notify) and MariaDB (`kv_feed`,
  polling, a counter row per topic) backends, contract tests, also against a Galera cluster of three writing nodes.
- kv: `NewSealedFeed`; purposes per class.
- kv: a guide for hosts from the table in "what a host does".
- zero-pep-proxy and zaddy: by the answer to open question 8.
- zeta-authserver-go: adoption, by its own team (external).
