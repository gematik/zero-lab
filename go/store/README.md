# store

The sealed store the TI command-line tools share per profile, as specified in
[spec/store](../../spec/store/README.md): tokens, discovery documents, cached trust material
and small state, readable and writable by the Go tools, `ti` and later the JVM tools on the
same files. Standard library only.

| Package | Content |
|---|---|
| [`store`](.) | `Store`, `Backend`, `MemoryBackend`, `Keyring` with `KeyFileWrapper`, `Sealer`, `KeyWrapper`, records, names and tags, the namespace registry, profile resolution, format levels, the files backend's formats, result codes |
| [`store/filestore`](filestore) | The files backend: one file per record below an `os.Root`; atomic take, no atomic batch, no index |
| [`store/cmd/store-conformance`](cmd/store-conformance) | The conformance adapter for `spec/store/tool` |

Records of sealed namespaces are AES-256-GCM per record, bound to profile, namespace, name
and expiry; ids and indexed metadata reach the backend only as HMACs. Without a keyring,
sealed namespaces are refused and plain ones keep working. The package reads no clock,
environment variable or file: commands resolve the profile (`ResolveProfile`), read the key
file (`ParseKEKFile`) and pass time and randomness in.

```sh
go test ./...                                   # the spec/store corpus and the facade
go test -run '^$' -fuzz FuzzKeyringFile .       # fuzz targets: FuzzOpenRecord, FuzzKeyringFile, FuzzRecordFile, FuzzKEKFile
```

The SQLite backend is a module of its own (TASK-103.7), so that this one stays free of
dependencies.
