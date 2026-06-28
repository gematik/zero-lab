# zero-pep-proxy — configuration

pep is configured from two sources:

- `openid-providers.yaml` holds the identity providers (who can log in).
- Environment variables hold everything else — the server, the session/persistence secrets, and the
  single-provider shortcuts (how the gateway runs and where its state lives).

The providers file holds only providers; it does not contain `PEP_PUBLIC_URL`, cookies, the session key,
`DATABASE_URL`, etc.

## 1. `openid-providers.yaml` — the providers

Loaded from `PEP_OPENID_PROVIDERS_PATH` (default `./openid-providers.yaml`). It is flat — the three provider
kinds at the top level, each reusing that provider's own package config type. The same format is what pdp
references by path, so the two stay in sync:

```yaml
oidc:   [ <oauth/oidc.Config>, … ]      # several direct OIDC providers
gemidp: [ <gemidp.ClientConfig>, … ]    # several gematik IDP-Dienst clients
oidf:   <oidf.RelyingPartyConfig>       # one OIDF relying party (brings its federation IdPs)
```

- Full example: [`openid-providers.example.yaml`](openid-providers.example.yaml).
- `${VAR}` placeholders expand from the environment (keep secrets in a `.env` / mounted file).
- Relative paths in the OIDF config (`key_pem_path`, `cert_pem_path`, …) resolve against the providers file's
  own directory — not the process working directory, and not `-w`.

## 2. Environment variables (everything that is not a provider)

### Config selection

| Var / Flag | Purpose | Default |
| --- | --- | --- |
| `PEP_OPENID_PROVIDERS_PATH` | the providers file. When set it must exist; the default is optional | `./openid-providers.yaml` |
| `-w <dir>` | working dir: `chdir` + load a `.env` from it (does **not** move the providers file's base path) | — |

Provider source: the providers file when it exists, else the **single-provider env shortcuts** below (so dev
needs no file). The file and the shortcuts are mutually exclusive (the file wins).

### Server / runtime

| Var | Purpose | Default |
| --- | --- | --- |
| `PEP_ADDR` | listen address | `:4180` |
| `PEP_PUBLIC_URL` | public origin the browser reaches pep at (the Caddy/ingress front, not pep directly) | `http://127.0.0.1:4180` |
| `PEP_COOKIE_NAME` | session cookie name | `ZERO-PEP-SID` |
| `PEP_INSECURE_COOKIE` | `"true"` drops the `__Host-` prefix + `Secure` for `http://localhost` dev; the cookie is **secure by default** | `false` |
| `PEP_TEMPLATE_DIR` | replace the embedded UI templates from this directory | embedded |
| `DEBUG` | any non-empty value → debug logging | off |

### Session & persistence (secrets are files, never values)

| Var | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | Postgres DSN for the session store (durable + shared across replicas). Unset → in-memory (dev; lost on restart, not shared) | in-memory |
| `PEP_SESSION_KEY_PATH` | file with a base64 256-bit key → enables the `/oauth2/auth` snapshot fast path (local decrypt, no DB per request). Unset → per-request DB validation | off |
| `PEP_SESSION_PREVIOUS_KEY_PATH` | optional second key file for rotation overlap | — |
| `PEP_SESSION_TTL` | session lifetime when the fast path is on (Go duration) | `8h` |

Keys are read from **files** (`*_PATH`), never from env values and never stored in the DB. See
[`../../proxy/docs/stateless-session-validation.md`](../../proxy/docs/stateless-session-validation.md).

### Single-provider shortcuts (the alternative to the providers file)

Used **only when no config file is given**, to configure one provider of each type from env. For several
providers, use openid-providers.yaml.

| Var | Provider | Notes |
| --- | --- | --- |
| `PEP_OIDC_ISSUER` | OIDC | enables a direct OIDC provider |
| `PEP_OIDC_CLIENT_ID` / `_CLIENT_SECRET` / `_SCOPES` / `_NAME` / `_LOGO_URI` / `_ACCEPTABLE_SKEW` | OIDC | client + chooser options; scopes space-separated; skew a Go duration (default 1m) |
| `PEP_OIDF_RP_CONFIG_PATH` | OIDF | path to the relying-party config (YAML) → enables federation login |
| `PEP_GEMIDP_CLIENT_ID` | gemidp | enables the gematik IDP-Dienst (always Authenticator deep-link flow) |
| `PEP_GEMIDP_ENV` | gemidp | `test` \| `ref` \| `prod` (or `PEP_GEMIDP_BASE_URL` to override) |
| `PEP_GEMIDP_REDIRECT_URI` | gemidp | redirect the client sends (default `<public>/oauth2/callback`) |
| `PEP_GEMIDP_REDIRECT_SCOPES` / `_NAME` / `_LOGO_URI` / `_USER_AGENT` | gemidp | scopes + chooser/UA options |

---

## Standalone gateway (reverse-proxy mode)

By default pep runs in forward_auth mode (behind Caddy). Configure routes to make pep **gate and
reverse-proxy** upstreams itself — an oauth2-proxy-style gateway, no Caddy needed. Gating runs as a
`pep.Enforcer` chain (`session_cookie` + optional `scope`); each route injects the user identity or a
DPoP-bound access token. This replaces the `zero-bff-pdp` all-in-one: run `zero-pdp` + `zero-pep-proxy`
(gateway mode) as two services.

| Var | Purpose |
| --- | --- |
| `PEP_ROUTES_PATH` | path to a routes YAML (authoritative when set) |
| `PEP_API_UPSTREAM` | shortcut → `{ /api, inject: dpop, gate: session, strip }` |
| `PEP_WEBAPP_UPSTREAM` | shortcut → `{ /, inject: identity, gate: snapshot }` |

A `routes.yaml`:

```yaml
routes:
  - path_prefix: /api          # longest-prefix wins; /oauth2/* always wins
    upstream: http://resource-server:8080
    inject: dpop               # Authorization: DPoP <token> + a fresh proof
    gate: session              # stateful kv lookup (required for dpop)
    strip_prefix: true         # /api/x → upstream /x
  - path_prefix: /
    upstream: http://webapp:8080
    inject: identity           # X-Auth-Request-* headers (incl. base64url-JSON)
    gate: snapshot             # stateless session cookie (needs PEP_SESSION_KEY_PATH)
    scope: protected           # optional: also require this scope claim
```

- `gate`: `none` (passthrough) · `snapshot` (stateless cookie, default for identity routes) · `session`
  (stateful kv). `gate: snapshot` requires the snapshot fast path (`PEP_SESSION_KEY_PATH`).
- `inject`: `none` · `identity` · `dpop`. `dpop` requires `gate: session` **and** the PDP backend (validated
  at startup).
- Unauthenticated requests: browsers (`Accept: text/html`) → `302 /oauth2/sign_in`; APIs → `401` JSON.

---

## Docker image

Built + published via the justfile (Docker Hub, version from the `go/pep/v*` tag):

```sh
just docker-build-pep    # spilikin/zero-pep-proxy:<modver> + :latest
just docker-push-pep     # build + push both tags
```

`scratch` image, runs as non-root (uid 65532), `PRETTY_LOGS=false` (structured logs). The version is stamped
into the binary (`pep.Version`) and logged at startup. Mount secrets (session key, OIDF keys) as files and
pass `DATABASE_URL`; see [`e2e/README.md`](../../proxy/e2e/README.md) for a runnable stack.
