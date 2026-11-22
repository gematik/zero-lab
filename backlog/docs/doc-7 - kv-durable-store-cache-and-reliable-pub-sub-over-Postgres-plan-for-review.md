---
id: doc-7
title: 'kv: durable store, cache and reliable pub/sub over Postgres (plan for review)'
type: specification
created_date: '2026-11-22 15:27'
---


# kv: durable store, cache and reliable pub/sub over Postgres

Status: plan for review (2026-11-22). Nothing is built; each step below becomes a task once agreed.

## Why

go/kv began as "the single persistence primitive" (kv.go). It now serves two different needs:

1. **ACID store**: single-use values (authorization codes, nonces, DPoP replays, login states since TASK-390),
   sessions, registrations. Losing or duplicating a write is a security defect (servers.md rule 11).
2. **Shared cache with fan-out for horizontal scaling**: verified federation documents (oidf), the
   revocation mirror of zero-pep-proxy and, with TASK-313, zaddy. A lost entry costs a refetch; what matters is
   that every replica learns a change quickly.

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
| `kv/postgres` | one logged table `kv(key text PK, value bytea, expires_at, mark, ...)`, database/sql over pgx, schema applied on Open | see below |
| kv/revoked (TASK-313) | revoked-ID set over Store + Bus, reconcile by full key scan | the scan is what a reliable feed would replace |

Users: zero-pep-proxy (sessions, revocations, oidf documents, login states), zaddy (revocations, TASK-313),
zeta-pdp-go (pdp/kvstore: sessions, clients, registrations, seen-once, SetMany indexes, Swap), go/pdp (frozen).

What kv/postgres leaves on the table today:

- `key LIKE 'prefix%'` on a `text` primary key with the database's default collation cannot use the index: every
  `Keys` and `Marker` query scans the table (pdp/kvstore scans by prefix on hot paths).
- Every write is a synchronously committed, WAL-logged row, cache entries included.
- `Cleanup` deletes all expired rows in one statement; every replica runs it.
- `pg_notify` runs in its own statement, never in the transaction of the write it announces.
- database/sql instead of pgx's native pool: no pipelining or batches, no prepared statement cache control.

## Proposal

### 1. Say the class of data, not one store for all

Three capabilities, each a small interface in kv (no driver), each with a memory and a Postgres backend:

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

`Bus` stays for what it is (best-effort signals inside one deployment) and is documented as such; new code uses
`Feed`. Revocations become: `Apply(Write{Set: revoked key, Publish: revoked id})`, and every replica keeps a local
set from `Follow(topic, cursor)`; after a restart it reads the durable keys once and follows from `Latest`. No
periodic rescan.

### 2. Postgres: one backend, two tables classes and an event log

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
- **Re-keying** (rule 22): Marker covers both record tables; feed events are short-lived, a key rotation waits out
  the retention of the topics sealed under the old key.

### 4. Memory backend

`NewMemory` gets an ephemeral twin (same code, Durability Ephemeral) and `NewMemoryFeed` (a slice per topic with
cursors, retention, a broadcast to followers), so every consumer's tests run the same contract. One shared
contract test suite runs against memory and, gated by `TEST_DATABASE_URL`, Postgres.

## Schema creation and migrations: a separate image, a server without DDL rights

Today `postgres.Open` runs the schema (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE`, a `DO` block) on every start:
every replica's database role must own the tables, and a compromised server can drop or alter them. zaddy now
inherits the same need (TASK-313). The plan separates the two roles:

- **Migrations are code of their own.** kv/postgres (and a MariaDB backend, below) keep numbered, embedded SQL
  steps and a table `kv_schema(version, applied_at)`. `Migrate(ctx, db, to)` applies the steps up to `to` under an
  advisory lock (one migrator at a time), each step in its own transaction where the database allows.
- **A separate image runs them.** `kv-migrate` (go/kv/cmd/kv-migrate, its own image, distroless, by digest) takes
  an admin DSN from a file (`*_PATH`), applies the steps, and grants the server role `SELECT, INSERT, UPDATE,
  DELETE` on the tables (and `USAGE` on the sequence of `kv_feed`). In Kubernetes it runs as a Job before the
  rollout (a Helm pre-upgrade hook or an Argo sync wave), with the admin secret mounted into that Job only.
- **The server image has no admin path.** `Open` runs no DDL: it reads `kv_schema`, and refuses to start when the
  version is below what it needs or above what it knows how to read (servers.md rule 17), naming both. Its role
  has DML rights only, so it cannot change the schema even if compromised. LISTEN/NOTIFY and advisory locks need
  no extra rights.
- **Expand, migrate, contract** (rule 22) map onto the migrator's steps: release N+1's migrator adds (expand)
  before N+1 rolls out; a later step that removes (contract, e.g. the `metadata` column) is marked so and runs only
  with `kv-migrate --contract`, after no replica of N is left.
- **Development and tests**: the memory backend needs nothing; the gated Postgres tests run `Migrate` first.
  A `kv-migrate` step in the e2e compose files replaces today's implicit schema.

This becomes a rule of its own: proposed for servers.md rule 8 or 23, "a server's database role has no DDL rights;
schema changes run in a separate job with their own credentials". To be decided with the review.

## MariaDB as a second backend

Feasible for the durable store and the cache; the feed has no push and falls back to polling. Facts to verify
against the MariaDB version we would require (11.4 LTS) before building:

| Need | Postgres | MariaDB |
|---|---|---|
| Atomic get-and-delete (Take) | `DELETE … RETURNING` | `DELETE … RETURNING` (since 10.0.5) |
| Set if absent or expired | `INSERT … ON CONFLICT DO UPDATE … WHERE expired RETURNING` | `INSERT … ON DUPLICATE KEY UPDATE` with `IF(expires_at <= NOW(6), …)` and `ROW_COUNT()` (1 inserted, 2 replaced, 0 kept) |
| Compare-and-swap | `UPDATE … WHERE value = $old` | the same, `ROW_COUNT()`; no `UPDATE … RETURNING` needed |
| Prefix scans on an index | `COLLATE "C"` / `text_pattern_ops` | `VARBINARY` key or a `_bin` collation; `LIKE 'p%'` then uses the index |
| Ephemeral table | `UNLOGGED` | no per-table equivalent: InnoDB is always logged; `MEMORY` holds no BLOB/TEXT; Aria with `TRANSACTIONAL=0` is not crash-safe and not transactional with InnoDB. Plan: the cache table stays InnoDB, and the Ephemeral promise is kept by semantics, not speed |
| Asynchronous commit | `SET LOCAL synchronous_commit = off` per transaction | `innodb_flush_log_at_trx_commit` is global only; no per-transaction switch |
| Push for the feed | `LISTEN`/`NOTIFY`, transactional | none. Followers poll `kv_feed WHERE topic = ? AND id > ?` on an index (e.g. every second), which is cheap, or MaxScale/binlog CDC, which we do not want |
| Ordered ids per topic | advisory transaction lock | `GET_LOCK('kv_feed:<topic>', …)` around the insert; released explicitly (session-scoped, not transaction-scoped) |
| One cleaner | `pg_try_advisory_lock` | `GET_LOCK(…, 0)` |
| Expiry | batched `DELETE` | batched `DELETE … LIMIT`; the event scheduler is not used (needs rights the server should not have) |

Consequences: revocations over MariaDB reach other replicas within the poll interval, not at once; a deployment
that needs instant fan-out uses Postgres. The Go driver (`github.com/go-sql-driver/mysql`) is a new dependency
and needs the maintainer's approval under the dependency rules; its contract tests would run gated by a
`TEST_MARIADB_DSN`. Recommendation: plan the interfaces so that MariaDB fits (polling Feed, no Postgres-only
semantics in kv), build it only when a deployment asks for it.

## Migration (servers.md rule 22: mixed versions work)

1. Release N: new tables and indexes created additively by `Open`; nothing reads them yet. kv/postgres moves to
   pgxpool behind the same `kv.Store`.
2. Release N+1: `Feed`, `Writer`, `Durability` in kv; revocations of zero-pep-proxy and zaddy write both the old
   way (key + Bus) and the Feed; followers read the Feed. oidf documents move to the ephemeral store.
3. Release N+2: the Bus path of revocations and kv/revoked's rescan go; the old `metadata` column goes.

Consumers that need durability (`kv.DurabilityOf(store) == kv.Durable`) refuse an ephemeral store at start:
zero-pep-proxy's login states and replay sets, zeta-pdp-go's seen-once and codes.

## Open questions for review

1. **Names**: `Feed` and `Writer.Apply`, or one `Tx(ctx, func(Tx) error)`? Apply is declarative and keeps
   backends simple (memory, and a future one); a callback transaction is more flexible but leaks backend
   semantics. Recommendation: Apply.
2. **Sessions**: durable (survive a database crash; today's behaviour) or ephemeral (faster; a crash signs
   everyone out)? Recommendation: durable for zero-pep-proxy's sessions, ephemeral for the oidf documents and the
   revocation mirror.
3. **Feed retention**: per topic by time (revocations: the snapshot TTL, 8 h) or by count? Recommendation: by
   time, set by the publisher.
4. **zeta-pdp-go**: does it adopt Feed for its revocations (its Revocations(since) iterator maps onto Follow) in
   the same step, or later? It is the largest user.
5. **Scope of pgxpool**: kv/postgres already requires pgx; switching from database/sql to pgxpool adds no module
   but uses more of pgx. To confirm under the dependency rules.

## Tasks this would become

- kv: numbered migrations and `kv_schema`, `Open` without DDL that checks the version; `kv-migrate` command and
  image; e2e compose and zero-lab-k8s Jobs; the DML-only role documented (and the servers.md rule, if agreed).

- kv/postgres: prefix index (`COLLATE "C"` / `text_pattern_ops`), batched and advisory-locked Cleanup, pgxpool.
- kv: `Durability`, ephemeral memory store, `kv_cache` (unlogged, async commit) in kv/postgres.
- kv: `Feed` + `Writer.Apply` with memory and Postgres backends (`kv_feed`, transactional notify), contract tests.
- kv: `NewSealedFeed`; purposes per class.
- zero-pep-proxy and zaddy: revocations on Feed (replacing kv/revoked's rescan); oidf documents on the ephemeral store.
- zeta-pdp-go: adoption, by its own team (external).
