# kv for hosts

`go/kv` and its backends are libraries. A host is the program that opens a store and runs
as a server: it owns the configuration, the credentials, the schema's rollout and the
schedule of everything that runs in the background. This guide says what the libraries
give and what they leave to the host. The rules behind it are in
[servers.md](../../../docs/design/servers.md) (rules 5, 8, 10 to 12, 17, 19 and 22); the
plan the libraries were built to is backlog doc-7.

Every statement about a backend below is proven by a test, named in
[what proves it](#what-proves-it).

## The modules

| Module | Holds | Requires |
|---|---|---|
| `go/kv` | the interfaces, the memory store, sealing, key rings and keychains, `kv/revoked`, `kv/schema`, the contract tests `kv/kvtest` | the standard library |
| `go/kv/postgres` | the PostgreSQL backend | `go/kv`, pgx |
| `go/kv/mariadb` | the MariaDB backend | `go/kv`, go-sql-driver/mysql |

A library of the host takes `kv.Store`, `kv.Transactor` and `kv.Feed` as parameters and
requires `go/kv` alone. Only the file that wires a database imports a backend, so only a
program that uses a database has its driver in the module graph.

## Choosing the database

The DSN is the address and nothing else; user and password are parameters beside it. A
DSN that carries either is refused.

```go
switch scheme(dsn) {
case "postgres", "postgresql":
	store, err = postgres.Open(ctx, dsn, user, password, opts...)
case "mariadb", "mysql":
	store, err = mariadb.Open(ctx, dsn, user, password, opts...)
}
```

| | PostgreSQL | MariaDB |
|---|---|---|
| DSN | `postgres://host:port/database` | `mariadb://host:port/database` |
| Topologies | a primary, with or without replicas | one node, a primary with replicas, Galera with one or several writing nodes |

The connection is protected as every other connection of a server (rule 29), alike in both
backends:

- **TLS by default**, with the server's certificate verified for the host of the DSN under
  the system's roots. `WithTLS` gives a CA of the deployment's own, another name to verify,
  or a client certificate; a configuration that skips verification is refused.
- **Plaintext only by the operator's acceptance**: `WithPlaintextAccepted()`, which the host
  sets from a setting of its own beside the DSN (`…_PLAINTEXT_ACCEPTED=true`, read as one
  exact value) and the backend logs at `Open`. There is no trying TLS and carrying on
  without it.
- **The DSN says nothing of it.** One that names `sslmode`, `tls` or another parameter of
  the transport is refused, so nothing in an address can weaken the connection, and the
  driver's own settings in the environment (`PGSSLMODE`) are not used.

`OpenDB` and `OpenBus` take the same two options.

The host reads the address from its configuration and the user and password from files
(rule 6 and [naming and configuration](../../../docs/conventions/naming-and-config.md)).
A host that still holds one URL with everything in it takes it apart with
`postgres.SplitURL`.

On MariaDB a key is at most 1024 bytes (`mariadb.MaxKeyLen`); a longer one is refused,
never cut short. PostgreSQL has no such bound. A host that is to run on both keeps its
keys within it.

## The schema

A server does not change its schema (rule 22). The backends keep numbered steps and
record the applied ones in `kv_schema`.

- **Before a rollout** a migration job calls `Migrate` over connections from `OpenDB`,
  opened as a user that may change the schema. Any number of jobs may run at once. The
  job is the host's: a small program that imports one backend, in an image of its own,
  with credentials no server holds.
- **`Open` runs no DDL.** It fails with an error that is a `schema.ErrVersion` when a
  step it needs is missing, or when a contract step it does not know was applied. It
  starts on expand steps of a newer release, so a replica of release N restarts while
  N+1's steps are already applied.
- **A contract step**, which removes what release N uses, is applied only by
  `Migrate(…, Contract())`, after the last replica of N is gone.
- **Without a job** (a compose file, a first installation by hand) the host passes
  `WithMigrate()`, and `Open` applies the missing expand steps itself. The server's user
  then has the rights the rule takes away; the host makes this a setting that is off
  unless set.

What the server's user needs:

| | PostgreSQL | MariaDB |
|---|---|---|
| Records, events | `SELECT, INSERT, UPDATE, DELETE` on `kv`, `kv_cache`, `kv_feed`, `kv_topic` | the same |
| Schema version | `SELECT` on `kv_schema` | the same |
| With `WithMigrate()` | also to create and alter tables in the schema | also `CREATE` and `ALTER` on the database |

The host grants them, and grants them again when a release adds a table: `Open` checks
the schema's version, not the rights, and a missing right shows at the first statement on
the table.

## Two classes of records

| Class | For | Opened with |
|---|---|---|
| durable | what must not be lost or doubled: single-use values, sessions, registrations (rule 11) | `Open` |
| ephemeral | what a loss only costs a fetch: verified documents, mirrors of state kept elsewhere (rule 12) | `Open(…, WithEphemeral())` |

The host puts each kind of record into its class, and a consumer of the first kind
refuses the other at start:

```go
if kv.DurabilityOf(store) != kv.Durable {
	return errors.New("sessions need a durable store")
}
```

An ephemeral store has its own table, runs transactions over its own records and
publishes no events. On PostgreSQL its writes are about twice as fast as durable ones
(an unlogged table, no wait for the flush) and are lost in a crash or a failover. On
MariaDB they cost what durable ones cost; the class is there so that a host runs alike on
both. A store that does not say its class counts as durable, so a wrapper the host
writes around a store passes `Durability()` on.

## Sealing

A database sees ciphertext only (rule 5): the host wraps each store in
`kv.NewSealed(store, keys, purpose)`. Keys stay in the clear, and so do topics: neither
carries a secret; a host that needs a subject in a key puts an HMAC of it there.

- A record opens only under its key, its purpose and the class it was sealed for.
- `WithSealedExpiry` seals the time a record ends, which resealing and moving need.
- The store below is opened with `WithMark(kv.SealedMarker(nil))`, so that the records
  of a key of before are found without reading every record.

Keys come from a file read once at start (rule 8): a `kv.Keyring`, or a `kv.Keychain`
whose keys are wrapped under a key-encryption key a key service holds (rule 19).

### When the keys change

The libraries give the parts; the walk is the host's, because the host knows its kinds of
records.

1. A new key becomes known to every replica (a second line of the ring; an entry of the
   keychain with a time from which it is in force), by a rollout.
2. It becomes the key that seals, by a rollout or by its time.
3. Each replica walks `Resealer.Others(prefix, after, limit)` and calls `Reseal` for each
   key, or `Rename` where the key itself changes. Two replicas that meet do the same
   thing twice without harm.
4. When `CountOthers` is zero for every kind that outlives the old key, the old key goes,
   by a rollout. `SealedByKeys` says which keys still seal something.

Events are short-lived: the old key stays for the longest retention of an event sealed
under it.

## Records that belong together

`kv.Transactor` runs a function in one transaction. What the host has to hold to:

- **The function may run more than once**, whenever the database says the transaction
  lost against another. It has no effect outside the transaction.
- **Records are named, not searched.** A transaction lists no keys.
- **At most `kv.MaxTxOps` calls**, and no call of the store itself inside the function.
- **One class per transaction.**

Two patterns carry the rest.

**A root record.** Records that change together hang under one record. Every transaction
that changes any of them calls `Get` of the root first and `Set` of it last. The `Get`
makes transactions of one root wait for each other on one node. The `Set` is what a
Galera cluster checks between its writing nodes: there, a record a transaction only read
is not protected, and two transactions that each read what the other writes both commit.

**An index in a related record.** What would be found by a prefix is listed in a record
the transaction reads anyway, with the end of each member, and pruned when it is written.
A list inside a sealed record cannot be added to or cut by someone who writes to the
database; what the database lists under a prefix can.

### Worked case: users, clients, sessions

An authorization server keeps, for each user, the user's record, the set of the user's
clients, a record per client and a record per session, each under a key that holds an
HMAC of the user's identifier. A login of a new client that has to make room for it:

```go
err := store.Tx(ctx, func(tx kv.Tx) error {
	user, _, err := tx.Get(ctx, "user:"+u) // the root: read first
	if err != nil {
		return err
	}
	set, _, err := tx.Get(ctx, "clients:"+u) // the index of the user's clients
	if err != nil {
		return err
	}
	clients := decode(set)
	for len(clients) >= limit {
		oldest := longestInactive(clients)
		record, _, err := tx.Get(ctx, "client:"+u+":"+oldest)
		if err != nil {
			return err
		}
		for _, sid := range sessionsOf(record) { // the index of the client's sessions
			if err := tx.Delete(ctx, "session:"+u+":"+oldest+":"+sid); err != nil {
				return err
			}
			if err := tx.Publish(ctx, "revocations", []byte(sid), retention); err != nil {
				return err
			}
		}
		if err := tx.Delete(ctx, "client:"+u+":"+oldest); err != nil {
			return err
		}
		delete(clients, oldest)
	}
	clients[client] = now
	if err := tx.Set(ctx, "client:"+u+":"+client, encodeClient(client, session), inactivity); err != nil {
		return err
	}
	if err := tx.Set(ctx, "session:"+u+":"+client+":"+session, encodeSession(), untilEnd); err != nil {
		return err
	}
	if err := tx.Set(ctx, "clients:"+u, encode(clients), inactivity); err != nil {
		return err
	}
	return tx.Set(ctx, "user:"+u, touch(user), inactivity) // the root: written last
})
```

Two logins of one user wait for each other or, across nodes, one of them runs again;
logins of different users do not meet. A refresh that replaces one session record needs
no transaction: `Swap` is the cheaper tool for one record.

## Events

`kv.Feed` is an ordered stream of small events per topic.

- **Publish with the change.** An event is published in the transaction that makes the
  change it tells of (`tx.Publish`), so a follower never hears of a change that did not
  happen.
- **Numbers have no gap.** A follower keeps the cursor of the last event it handled and
  calls `Follow(topic, cursor)` again after a restart or when its channel closes. An event
  whose number is not the next one means that events before it are gone: their retention
  is over, or one did not open. The follower then reads its state anew from where it is
  kept, the durable records.
- **Retention** is given with each event and must be positive. It is at least as long as
  a follower may be away and still catch up by the feed alone.
- **Delivery is as fast as the backend can make it**: PostgreSQL tells followers by a
  notification and looks every 30 seconds without one, MariaDB looks every second
  (`WithFeedPoll` in both). A host does not depend on which.
- **A topic with many publishers on several writing nodes of a Galera cluster is slow**:
  all but one lose at each commit and run again. Topics here see few events.
- **Sealed.** A sealed store publishes sealed events. A program that only follows, with
  no records of its own, wraps the feed in `kv.NewSealedFeed(feed, keys, purpose)`; the
  publisher then seals its events under those keys with `kv.WithSealedEvents`.

What the host does while the feed cannot be read is its own decision and belongs to its
health: a mirror that is no longer current is a reason to be not ready.

`kv.Bus` and `kv/revoked` stay for the hosts that use them. New code uses the feed.

## What runs in the background

| What | The library gives | The host decides |
|---|---|---|
| Expired records and events | `Cleanup`, safe to call from every replica: on PostgreSQL one replica at a time deletes, in batches; `kv.Reap` calls it on an interval | the interval |
| Resealing | `Others`, `Reseal`, `Rename`, `CountOthers` | the walk, its schedule, the signal that an old key may go |
| Followers | `Follow` | the cursor, the local state, what a gap triggers |

## Health and metrics

The libraries return errors and counts; probes and metrics are the host's (rules 14 and
31). A background check asks the store on an interval (a `Get` of a key that need not be
there is enough) and keeps the answer; a probe reads it. A store that does not answer
makes a replica not ready, never not live. Worth a metric: the age of the last check, the
age of each follower's last event, `CountOthers` per kind while keys change.

## Testing

A host's tests run on `kv.NewMemory()` and `kv.NewMemory(kv.WithMemoryEphemeral())`,
which keep the same contract as the databases: the suites of `kv/kvtest` run against all
three. The memory store holds its lock while a transaction's function runs, so a call of
the store itself inside the function, which the contract forbids, waits forever there
and is found by the test that makes it.

## What proves it

`kvtest.X` is a suite of `kv/kvtest` that memory, PostgreSQL and MariaDB all run; the
others are tests of one backend. The Galera tests send every call through another of
three writing nodes (`just kv-mariadb-test`). The suites that take pods run several
stores, each with connections of its own, against one database, and through the nodes of
the cluster as `TestGalera_Pods` (`just kv-e2e-test`); in `kvtest.StartTogether` and
`kvtest.RollingMigration` each pod is a process, so they run on the databases alone.

| Statement | Test |
|---|---|
| The stores behave alike: values, expiry, one winner for `Take`, `SetIfAbsent` and `Swap`, keys by a literal prefix in the order of their bytes | `kvtest.Store`; through Galera nodes `TestGalera_Task429TheContractHoldsThroughDifferentWritingNodes` |
| A DSN with a user or a password, or one the backend does not understand in full, is refused | `TestConfig_ADSNWithAUserOrAPasswordIsRefused`, `TestConfig_Rule17RefusesWhatItDoesNotKnow`; on PostgreSQL `TestConfig_Rule17ADSNThatSetsTheSessionOrNamesAnotherHostIsRefused`, `TestPostgres_Rule11AnAddressCannotTakeTheFlushFromTheDurableClass` |
| The connection is TLS without a fallback; plaintext only when accepted; no transport parameter in the DSN | `TestConfig_Rule29TheConnectionIsTLSWithoutAFallback`, `TestConfig_Rule29PlaintextOnlyWhenAccepted`, `TestOpen_Rule29ADatabaseWithoutTLSIsRefusedUnlessPlaintextIsAccepted`, `TestOpen_Rule29ADatabaseIsNotReachedInPlaintextUnlessAccepted` |
| The server's certificate is verified for its CA and its name, and a client certificate is presented | `TestOpen_Rule29TheServersCertificateIsVerifiedForItsCAAndItsName`, `TestOpen_Rule29AClientCertificateIsPresentedWhenTheConfigurationHasOne` (`just kv-postgres-test`, `just kv-mariadb-test`) |
| A key over 1024 bytes is refused on MariaDB | `TestMariaDB_AKeyLongerThanTheBoundIsRefusedNotCutShort` |
| Many migrators at once all succeed | `TestMigrate_Task428ByManyAtOnceAppliesEachStepOnce`, `TestMigrate_Task429ByManyAtOnceSucceedsForAll`, `TestGalera_Task429MigratorsThroughDifferentNodesAtOnceSucceedForAll`; a step of one that arrives after another applied the contract step that undoes it: `TestMigrate_AStepThatArrivesAfterTheContractStepThatUndoesItDoesNotPutBackWhatWasRemoved` |
| `Open` runs no DDL and works with a user without schema rights | `TestOpen_Task428RunsNoDDLAndWorksWithARoleThatMayNotChangeTheSchema`, `TestOpen_Task429RunsNoDDLAndWorksWithAUserThatMayNotChangeTheSchema` |
| `Open` refuses a missing step and an unknown contract step, and starts on a newer release's expand steps | `TestOpen_Rule17RefusesADatabaseThatLacksAStepItNeeds`, `TestOpen_Rule17RefusesADatabaseWithAContractStepItDoesNotKnow`, `TestOpen_Rule22StartsOnExpandStepsOfANewerRelease` |
| `WithMigrate()` never applies a contract step; `Migrate` only when asked | `TestOpen_Task428WithMigrateAppliesExpandStepsAndNeverAContractStep`, `TestMigrate_Task428AppliesAContractStepOnlyWhenAsked`, `TestOpen_Task429WithMigrateAppliesExpandStepsAndNeverAContractStep`, `TestMigrate_Task429AppliesAContractStepOnlyWhenAsked` |
| The classes keep their records apart and say which they are | `kvtest.Ephemeral`, `TestPostgres_Task431TheClassesKeepTheirRecordsApart`, `TestMariaDB_Task431TheClassesKeepTheirRecordsApart` |
| PostgreSQL's ephemeral writes are unlogged and do not wait for the flush; what each class costs | `TestPostgres_Task431EphemeralWritesAreUnloggedAndDoNotWaitForTheFlush`, `TestPostgres_Rule11EveryWriteOfTheDurableClassWaitsForTheFlushAndNoneOfTheEphemeral`, `TestPostgres_Task431WhatAWriteCostsInEachClass`, `TestMariaDB_Task431WhatAWriteCostsInEachClass` |
| A sealed record of one class does not open in the other | `TestSealed_ARecordOfOneClassDoesNotOpenInTheOther` |
| The database holds no record and no event in the clear, and the notification carries the topic alone | `TestPostgres_Rule5TheDatabaseHoldsNoRecordAndNoEventInTheClear`, `TestMariaDB_Rule5TheDatabaseHoldsNoRecordAndNoEventInTheClear` |
| The records of a key of before are found and taken along, in each class | `kvtest.Marker`, `kvtest.Resealer` |
| A transaction takes effect as a whole or not at all, holds what it read, also against writers outside it, and is bounded | `kvtest.Tx`, `kvtest.TxOutside`; through Galera nodes `TestGalera_Task432TheTxContractHoldsThroughDifferentWritingNodes` |
| A record only read is not protected across writing nodes | `TestGalera_Task432ARecordOnlyReadIsNotProtectedAcrossNodes` |
| Events are numbered without a gap, in order, resumable, and gone after their retention | `kvtest.Feed`; through Galera nodes `TestGalera_Task432TheFeedContractHoldsThroughDifferentWritingNodes` |
| On PostgreSQL an event arrives by its notification, and without it by the look | `TestPostgres_Task432AnEventArrivesByItsNotification`, `TestPostgres_Task432AnEventWithoutItsNotificationStillArrives`, `TestPostgres_Task432AnEventWrittenWhileTheFollowerWaitsUntoldArrivesByItsLook` |
| A sealed event opens only where and as what it was sealed | `kvtest.SealedFeed`; through Galera nodes `TestGalera_Task433TheSealedFeedContractHoldsThroughDifferentWritingNodes` |
| In a cluster a value written through one node is found through another at once | `TestGalera_Task429AValueWrittenThroughOneNodeIsFoundThroughAnotherAtOnce` |
| The pods of a first installation start at once, after a migration job or each applying the schema itself, and refuse without either | `kvtest.StartTogether` |
| A deployment goes to the next release while its pods serve: expand steps under running pods, restarts, pods of both releases side by side, the contract step after the last old pod, and the refusal of an old pod after it | `kvtest.RollingMigration` |
| Sealed records open only under their key, purpose and class, by every way of reading, and end when their seal says | `kvtest.Sealing` |
| Unsealed records of a release before sealing are never taken for sealed ones, and are found and taken along by the host, which seals only what it knows as such a record | `kvtest.Unsealed`; a database of before the steps with its sealed records: `TestPods_Rule22ADatabaseOfBeforeTheStepsIsAdoptedWithItsSealedRecords` |
| The keys change by the four steps of "When the keys change", with a keyring and with a keychain, while pods hold different files; a pod a stage too far fails closed | `kvtest.Rotation` |
| Sealed events across a change of the feed's keys, for a follower that holds the feed's keys alone | `kvtest.SealedEvents` |
| A revocation published with its change reaches the followers of other pods; a follower restarts at its cursor, and sees a gap after the retention | `kvtest.Revocations`; on PostgreSQL by notification alone and with the listeners cut off: `TestPods_Rule11ARevocationReachesTheFollowersOfOtherPodsByItsNotification`, `TestPods_Rule11ARevocationReachesTheFollowersWhoseListenersAreCutOff` |
| The worked case: logins of one user through several pods | `kvtest.Logins` |
| `Cleanup` removes the events whose retention is over | `TestPostgres_CleanupRemovesTheEventsWhoseRetentionIsOver`, `TestMariaDB_CleanupRemovesTheEventsWhoseRetentionIsOver` |
| A transaction that lost against another runs again | `TestPostgres_ATransactionThatLosesAgainstAnotherRunsAgain`, `TestMariaDB_ATransactionThatLosesAgainstAnotherRunsAgain` |
| On PostgreSQL `Cleanup` deletes in batches, one replica at a time, and prefixes read a range of an index | `TestPostgres_Task430CleanupDeletesABacklogInBatches`, `TestPostgres_Task430NoStatementOfCleanupDeletesMoreThanABatch`, `TestPostgres_Task430OnlyOneReplicaCleansAtATime`, `TestPostgres_Task430KeysAndMarksByPrefixReadARangeOfAnIndex` |
