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

## ZETA headers for the resource

`enforce_policy` forwards the request with all its headers, the client's `Authorization` and `DPoP`
included, as gemSpec_ZETA A_25669-01 has the PEP HTTP proxy do (gemSpec_ZETA 2.0.0 CC and the schemas of
ZETA release 2.0.0-1): the resource may check the token and the proof again. The headers of A_25669-01
come only from zaddy: `zeta-user-info`, `zeta-client-data` and `zeta-popp-token-content` that the client
sent are removed from every request, with or without the subdirectives below.

- `zeta_user_info` puts `zeta-user-info` into the forwarded request (A_26589-01): `identifier` from the
  token's `sub`, `professionOID` from `profession_oid`, `commonName` from `common_name` and, when the token
  has them, `organizationName` from `organization_name` and `birthdate` (A_26973-02; left out unless it is a
  `YYYY-MM-DD` date), as Base64-URL encoded JSON.
- `zeta_client_data` puts `zeta-client-data` in as well (A_26590-02): `client_id`, `product_id`,
  `product_version` and `platform` when it is one the schema knows. It is off unless the endpoint asks for
  it (A_26492-02).

A request whose token lacks a claim a configured header needs is refused with 403 `access_denied`. PoPP is
not supported, so `zeta-popp-token-content` is only removed.

```caddyfile
handle /api/* {
	enforce_policy {
		authorization_dpop
		zeta_user_info
		zeta_client_data
	}
	reverse_proxy resource:8080
}
```

## Access tokens

`resource` is required: an access token is taken only if its `aud` names it (RFC 9700 Section
4.10.2), and a configuration without it is refused. A token must say it is one by its `typ`,
`at+jwt` or `application/at+jwt` (RFC 9068 Section 4), so that another JWT the authorization server
signs with the same key, an ID token among them, is not taken for an access token. For an
authorization server known to omit the `typ`, the global `pep` block takes
`accept_untyped_access_tokens`.

```caddyfile
{
	pep {
		resource https://api.example.com
		accept_untyped_access_tokens
	}
}
```

## Keys of the authorization server

Access tokens are verified with the keys of the authorization server. With `jwks_path` in the global `pep`
block they come from that file, read once at start; a changed file is taken by a rollout or a reload, like
every other file zaddy reads. Without `jwks_path`, `authorization_server` is required, as the issuer
identifier: an https URL without query or fragment (RFC 8414 Section 2). zaddy then reads the server's
metadata from `/.well-known/oauth-authorization-server` inserted after the host (RFC 8414 Section 3.1), or
from `<authorization_server>/.well-known/openid-configuration` when the first answers 404, checks that it
names exactly the configured issuer (RFC 8414 Section 3.3) and an https `jwks_uri`, and reads the key set
from there. All of it goes through the egress client (servers.md rule 30): https only, verified against the
system's roots, a forward proxy from `HTTPS_PROXY`, no redirects, bounded responses. The fetching is
`pep.AuthorizationServerKeys`, which zero-pep-proxy's gateway can use as well; zaddy hands it the egress
client and runs the background refresh.

zaddy does not start when it cannot read the keys. It reads them again every 15 minutes in the background,
never on the request path (servers.md rule 8): a token signed with a key the set does not hold yet is refused
until the next read brings that key. A set that is read and parses replaces the one in force as a whole; a
failed read keeps it and is logged.

```caddyfile
{
	pep {
		resource https://api.example.com
		authorization_server https://as.example.com
	}
}
```

## Protected resource metadata

A 401 of `enforce_policy` names the resource's metadata in the `resource_metadata` parameter of its
`WWW-Authenticate` challenge (RFC 9728 Section 5.1), Bearer and DPoP alike, so a client that starts at the
resource learns where to find the authorization server. The URL is the one RFC 9728 Section 3.1 derives
from `resource`: `/.well-known/oauth-protected-resource` inserted between the host and the resource's path.

The `protected_resource_metadata` handler, pep's `NewProtectedResourceMetadataHandler`, serves that
document (RFC 9728 Section 3) from the global `pep` block: `resource`, `authorization_servers` with `authorization_server`, `bearer_methods_supported`
`["header"]`, `scopes_supported` from the subdirective of that name, and the members a deployment adds
with `metadata_member <name> <JSON value>`, such as gematik's `zeta_asl_use`. A value is one JSON text,
so a string is quoted inside backticks; a name zaddy sets itself, or another typed member of RFC 9728, is
refused. It answers GET and HEAD with `application/json`, any other method with 405.

```caddyfile
{
	pep {
		resource https://api.example.com
		authorization_server https://as.example.com
		scopes_supported epa.read epa.write
		metadata_member zeta_asl_use `"required"`
	}
}

https://api.example.com {
	handle /.well-known/oauth-protected-resource {
		protected_resource_metadata
	}
}
```

For a resource with a path, such as `https://api.example.com/fhir`, the handler belongs at
`/.well-known/oauth-protected-resource/fhir`.

## Forward proxy

zaddy's requests to the internet (the authorization server's metadata and keys) go through the forward proxy of
`HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` in its environment, https by CONNECT only, so TLS ends at the
authorization server and a TLS-intercepting proxy is not supported (servers.md rule 30). A proxy URL with user
information is refused; credentials come from the file `egress_proxy_credentials_path` names in the global `pep`
block, one line `user:password`. The proxy in effect is logged at start.

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

## Session cookies and revocations

A `SessionCookie` enforcer (JSON `{"type": "SessionCookie", "cookie_name": …, "key_path": …}`) admits a
request on zero-pep-proxy's session snapshot. A snapshot stays valid until it expires (8 hours by default),
also after its session was signed out or rotated, so the enforcer asks zero-pep-proxy's revocations too and
refuses a snapshot whose session is revoked. Set `revocations_database_url` in the global `pep` block to the
Postgres DSN of the kv store zero-pep-proxy keeps them in (its `PEP_DATABASE_URL`):

```caddyfile
{
	pep {
		resource https://api.example.com
		revocations_database_url {file./run/secrets/pep-database-url}
	}
}
```

The DSN carries a password, so give it from a mounted file through Caddy's `{file.…}` placeholder rather than in
the Caddyfile. When the app starts, zaddy connects to the store, loads the revocations stored under
`pep:revoked:` and follows new ones on the `pep_revoked` channel (Postgres `LISTEN`/`NOTIFY`), reading the store
again every 30 seconds for what the channel dropped. It reads keys only, so it needs no share of
zero-pep-proxy's store keys; it opens the store as zero-pep-proxy does, which creates the kv table if it is
missing. Requests are judged against the set in memory, without a database read.

zaddy fails closed. It does not start when it cannot connect or read the revocations, and a configuration whose
`enforce_policy` uses a `SessionCookie` enforcer at any depth is refused without `revocations_database_url`. If
the store cannot be read for 90 seconds while zaddy runs, every snapshot whose session it does not already know
to be revoked is refused until a read succeeds again.
