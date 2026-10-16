# sqlitestore

The SQLite backend of the TI tools' sealed store ([spec/store](../../spec/store/README.md)
section H): a profile's `state.db` and `cache.db`, which `ti`, the Go tools and later the
JVM tools open together. It implements `store.Backend` of [go/store](../store) with every
capability: atomic take and batch across processes, indexed queries.

The driver is [ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3), SQLite compiled
to Go without cgo; it is a module of its own so that `go/store` stays free of dependencies.

```go
b, err := sqlitestore.Open(ctx, statePath, sqlitestore.State)
```

- A new database is created from `schema.sql`, a copy of `spec/store/schema.sql` that a test
  keeps identical. A file of another application or a newer, incompatible format level is
  refused (`malformed`, `unsupported_version`); see section K.
- `state.db` writes with `synchronous = FULL` and `secure_delete`; `cache.db` with
  `synchronous = NORMAL`. Every transaction begins with `BEGIN IMMEDIATE`; a lock held past
  five seconds is `busy`.
- The database, its WAL and its shared-memory file are created with mode 0600.

```sh
go test ./...          # spec/store's SQLite scenarios, levels, modes, concurrent take, 100,000 records
go test -short ./...   # without the load check
```
