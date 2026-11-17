# Caddy based Zero Trust PEP (Zaddy)

## Development

```bash
go run ./cmd/zero-caddy run
```

```bash
curlie -k https://localhost:2019/
curlie -k https://localhost:2019/public
# This should fail
curlie -k https://localhost:2019/protected
```

## DPoP nonces

`authorization_dpop nonce_required` in an `enforce_policy` block requires the server's nonce in every
DPoP proof (RFC 9449 Section 9): a proof without it is answered 401 `use_dpop_nonce` with a
`DPoP-Nonce`, and every accepted request gets the next one. The nonces seal themselves, so the
replicas share no store, only keys: set `dpop_nonce_keyring_path` in the global `pep` block to a key
file every replica reads, in the format of kv's keyring: one key per line, `<id> <base64 of 32
bytes>`, the first one current, `#` comments; or one bare base64 key. zaddy reads it when Caddy
provisions the app, so a rotated file takes effect with a config reload, and refuses to start on a
file that does not parse. Without it, each process uses a key of its own, which holds for a single
replica only.

To rotate, change the file in three steps (the new key second, then first, then the old key
removed) and run `caddy reload --force` on every replica after each step; without `--force` Caddy
skips a reload whose configuration did not change. Like Caddy's own certificate files, the key file
is not watched.

```caddyfile
{
	pep {
		resource https://api.example.com
		dpop_nonce_keyring_path /run/secrets/dpop-nonce-keyring
	}
}
```

## DPoP replays

zaddy accepts a DPoP proof once (RFC 9449 Section 11.1). By default it remembers the proofs it
accepted in the memory of its process, so a proof replayed at another replica within its lifetime is
accepted there; zaddy logs a warning that replay detection holds for this replica only. With
`dpop_replays storage` in the global `pep` block, it keeps them in Caddy's storage instead, which
every replica configured with the same storage shares, the way a Caddy cluster shares its
certificates and locks: Caddy's default file system storage on a volume every replica mounts, or a
storage module such as Redis, Consul or Postgres set with the global `storage` option.

Each accepted proof is one key under `zaddy/dpop_replays/`, named by a SHA-256 hash and holding its
expiry; it is checked and written under the storage's lock of that key, so two replicas cannot both
accept the proof. A storage error, or a lock not obtained within 5 seconds, refuses the proof. Expired
records are replaced when the same proof comes again and removed by a sweep every minute, at most
1000 per replica and sweep. The storage must be reachable by the replicas only, as for Caddy's
certificates: whoever can delete a record can replay that proof.

```caddyfile
{
	storage file_system /mnt/shared/caddy
	pep {
		resource https://api.example.com
		dpop_replays storage
	}
}
```
