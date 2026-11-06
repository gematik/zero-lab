# zero-pdp — configuration

Three sources, the same split pep uses:

- **`openid-providers.yaml`** — the IdPs the PDP authenticates users against (shared flat format with pep:
  `oidc` / `idpd` / `oidf`). Loaded from `PDP_OPENID_PROVIDERS_PATH` (default `openid-providers.yaml`, next
  to the config file). An unknown key stops the start, in this file and in `pdp.yaml`.
- **`pdp.yaml`** — the PDP domain config (issuer, scopes, clients, products, policies, endpoints,
  `non_prod_mode`, `mock_idp`). Selected with `-f` / `PDP_CONFIG_FILE` (default `pdp.yaml`), resolved against
  the workdir.
- **Environment** — runtime + secrets via `*_PATH` files.

Requests to the providers, the federation and the IDP-Dienst's trust material are verified under the `web`
profile of [`spec/pki-validation`](../../../../spec/pki-validation/README.md) against the system's roots (the
image's `ca-certificates`); there is no setting that turns it off.

| Var | Purpose | Default |
| --- | --- | --- |
| `PDP_CONFIG_FILE` (`-f`) | the domain config file | `pdp.yaml` |
| `PDP_OPENID_PROVIDERS_PATH` | the providers file | `openid-providers.yaml` |
| `PDP_OIDF_DEV_API_KEY` | key of gematik's development federation, sent only to `*.dev.gematik.solutions`; a value, not a file, as it opens only that environment ([naming and configuration](../../../../docs/conventions/naming-and-config.md)) | — |
| `PDP_WORKDIR` (`-w`) | chdir before loading config | — |
| `PDP_NON_PROD` | `true` → NonProdMode (enables the mock IdP) | `false` |
| `DATABASE_URL` | Postgres kv store; requires `PDP_STORE_KEY_PATH`. Unset → in-memory, for a single replica | in-memory |
| `PDP_STORE_KEY_PATH` | key file sealing the kv store and the replay nonces, the same on all replicas. **Required with `DATABASE_URL`**: the server refuses to start without it. Without `DATABASE_URL` and without it, nonces use a key of this process alone, with a warning at start | — |

`sign_jwk_path` is required: without a readable EC P-256 private key the server does not start
(`zero-pdp jose generate-jwk` makes one). Secrets (`sign_jwk_path`, `clients_policy_path`, …) are files referenced by path — never env values, never in
the kv store.

## The store's key file

Nothing makes a key at start. Make the file once, and hand the same file to every replica:

```sh
printf 'k1 %s\n' "$(openssl rand -base64 32)" > store.key
```

One key per line, `<id> <base64 of 32 bytes>`, `#` comments and blank lines ignored; the first key seals, all of them
open. A file holding one bare base64 key is the single key `default`. A replica looks at the file at most every 30 s and
re-reads it when it changed, so rotating needs no restart, in this order: add the new key second on all pods, then make
it first, then drop the old key after the longest TTL of a record it sealed. A broken file keeps the keys in force and
logs at error level.

## Upgrading to sealed records

Records of earlier releases do not open any more, so authorization sessions and refresh tokens end once, and clients
authenticate again. Replicas of the old and the new release cannot read each other's session records or nonces during
the rollout. Such a record counts as an invalid session and is logged at error level (`record failed its integrity
check`), which outside an upgrade can mean tampering with the store. After the last replica is upgraded, an operator
should clear the old rows. If zero-pep-proxy shares the table, keep its revocation records:

```sql
DELETE FROM kv WHERE key NOT LIKE 'pep:revoked:%';
```

Expired rows leave the table every 10 minutes. A `GET` of the nonce endpoint writes nothing; a nonce and a DPoP proof
leave one row each when accepted, until they expire, so that neither is accepted twice by any replica.

## Mock IdP (NonProdMode only)

For airgapped tests, set `PDP_NON_PROD=true` (or `non_prod_mode: true`) and a `mock_idp` block in `pdp.yaml`:

```yaml
authorization_server:
  non_prod_mode: true
  mock_idp:
    subject: X110000001
    claims:
      name: Test User
      email: test@example.com
```

The authorization endpoint then auto-completes login with this canned identity instead of redirecting to a
real OpenID Provider — `browser → PDP → (mock) → code → token`, no external network. The mock IdP is honored
**only** when NonProdMode is on; it cannot be enabled in a production config.

## Docker

`scratch` image; the binary is at `/app/zero-pdp`; mount your config dir (`pdp.yaml` +
`openid-providers.yaml` + `sign.jwk`) at the WORKDIR **`/etc/pdp`** — it does not shadow the binary. Build /
push with `just docker-build pdp` / `just docker-push pdp`. See [`../../docker-compose.yaml`](../../docker-compose.yaml)
for the airgapped NonProd stack.
