# zero-pdp — configuration

Three sources, the same split pep uses:

- **`openid-providers.yaml`** — the IdPs the PDP authenticates users against (shared flat format with pep:
  `oidc` / `gemidp` / `oidf`). Loaded from `PDP_OPENID_PROVIDERS_PATH` (default `openid-providers.yaml`, next
  to the config file). Present → it is the source of providers; absent → any inline providers in `pdp.yaml`
  are kept (back-compat).
- **`pdp.yaml`** — the PDP domain config (issuer, scopes, clients, products, policies, endpoints,
  `non_prod_mode`, `mock_idp`). Selected with `-f` / `PDP_CONFIG_FILE` (default `pdp.yaml`), resolved against
  the workdir.
- **Environment** — runtime + secrets via `*_PATH` files.

| Var | Purpose | Default |
| --- | --- | --- |
| `PDP_CONFIG_FILE` (`-f`) | the domain config file | `pdp.yaml` |
| `PDP_OPENID_PROVIDERS_PATH` | the providers file | `openid-providers.yaml` |
| `PDP_WORKDIR` (`-w`) | chdir before loading config | — |
| `PDP_NON_PROD` | `true` → NonProdMode (enables the mock IdP) | `false` |
| `DATABASE_URL` | Postgres kv store; unset → in-memory | in-memory |

Secrets (`sign_jwk_path`, `clients_policy_path`, …) are files referenced by path — never env values, never in
the kv store.

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
push with `just docker-build-pdp` / `just docker-push-pdp`. See [`../../docker-compose.yaml`](../../docker-compose.yaml)
for the airgapped NonProd stack.
