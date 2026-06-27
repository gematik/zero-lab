# pep proxy — HITL / e2e harness

A local stack for running the pep oauth2-proxy end to end: OIDC / OIDF / gemidp login, forward_auth gating,
the snapshot fast path, and revocation. Caddy and the upstream run in compose; the proxy runs on the host so
it can read local secrets and you can iterate with `go run`.

## Ports

One front port — point your browser or rathole tunnel at it; the rest is internal or for the host proxy.

| Service       | Port | Used by                            |
| ------------- | ---- | ---------------------------------- |
| Caddy (front) | 8080 | browser / rathole                  |
| pep (host)    | 4180 | Caddy, via host.docker.internal    |
| metsubushi    | 8080 | Caddy, internal upstream           |
| Postgres      | 5432 | pep, via DATABASE_URL (optional)   |

## Run (simplest — in-memory, one OIDC provider, no database)

```sh
docker compose -f pep/proxy/e2e/docker-compose.yaml up --build

PEP_PUBLIC_URL=http://localhost:8080 PEP_INSECURE_COOKIE=true \
PEP_OIDC_ISSUER=https://accounts.google.com \
PEP_OIDC_CLIENT_ID=... PEP_OIDC_CLIENT_SECRET=... \
  go run ./pep/cmd/zero-pep-proxy
```

Open http://localhost:8080/ and log in; register `http://localhost:8080/oauth2/callback` at the provider.
`PEP_INSECURE_COOKIE=true` is required only here: the session cookie is `__Host-`/Secure by default, which
`http://localhost` can't carry — drop it behind HTTPS. Sessions are in memory (lost on restart) and
`/oauth2/auth` reads them per request — the database and the snapshot fast path are off until you set the
vars below.

## Config

All via environment; full reference in [`../../cmd/zero-pep-proxy/CONFIG.md`](../../cmd/zero-pep-proxy/CONFIG.md).

| Var                       | For                                          | Default                |
| ------------------------- | -------------------------------------------- | ---------------------- |
| PEP_PUBLIC_URL            | origin the browser uses (front / tunnel host)| http://127.0.0.1:4180  |
| PEP_OIDC_ISSUER (+ _CLIENT_ID/_CLIENT_SECRET) | one OIDC provider           | —                      |
| PEP_OIDF_RP_CONFIG_PATH   | a gematik OIDF relying party                 | —                      |
| PEP_GEMIDP_CLIENT_ID      | a gematik IDP-Dienst client                  | —                      |
| PEP_OPENID_PROVIDERS_PATH | several providers (openid-providers.yaml)    | ./openid-providers.yaml|
| DATABASE_URL              | durable + shared sessions (Postgres)         | in-memory              |
| PEP_SESSION_KEY_PATH      | snapshot fast path (no DB read per request)  | off                    |
| PEP_INSECURE_COOKIE       | drop `__Host-`/Secure for `http://localhost` (secure by default) | secure      |

## Variations

- OIDF (needs a public host): point rathole at :8080 and add `PEP_PUBLIC_URL=https://<rathole-host>`,
  `PEP_OIDF_RP_CONFIG_PATH=...` (drop `PEP_INSECURE_COOKIE` — the default secure cookie is what you want over HTTPS).
- Durable sessions + snapshot fast path: add `DATABASE_URL=postgres://zero:zero@127.0.0.1:5432/zero?sslmode=disable`,
  generate a key (`openssl rand -base64 32 > /tmp/pep-session.key`), and set `PEP_SESSION_KEY_PATH=/tmp/pep-session.key`.
- Several providers: set `PEP_OPENID_PROVIDERS_PATH` (see `../../cmd/zero-pep-proxy/openid-providers.example.yaml`).
- Containerized OIDC demo (pep in a container, no host go-run): `../../cmd/zero-pep-proxy/docker-compose.yaml`.

## Two-replica revocation check

With `DATABASE_URL` and `PEP_SESSION_KEY_PATH` set, run a second proxy on `PEP_ADDR=:4181` against the same DB
and key. A logout on one replica is honored on the other instantly (Postgres LISTEN/NOTIFY), and a freshly
started replica loads revocations from the durable `pep:revoked` set. See
[`../docs/stateless-session-validation.md`](../docs/stateless-session-validation.md).

## PDP backend (S4) — airgapped, DPoP end to end

pep as a confidential client of the PDP ([`../docs/pdp-backend.md`](../docs/pdp-backend.md)): login via the
PDP's NonProd mock IdP (no external IdP), then a DPoP-bound `/api` call that a `zaddy` resource server
**verifies**. The two backend services run in compose; pep runs on the host so the PDP issuer URL
(`http://localhost:8011`) is the same for the browser redirect and pep's backend calls.

```sh
# 1) PDP (NonProd mock IdP, pep registered as a client) + zaddy (enforce_policy authorization_dpop)
docker compose -f docker-compose.pdp.yaml up --build -d

# 2) pep on the host, PDP backend
PEP_BACKEND=pdp PEP_AS_ISSUER=http://localhost:8011 PEP_CLIENT_ID=pep-client \
PEP_CLIENT_SIGNING_KEY_PATH=pdp-config/pep-client.jwk \
PEP_PUBLIC_URL=http://localhost:8080 PEP_ADDR=:8080 PEP_INSECURE_COOKIE=true \
PEP_SCOPES=protected PEP_API_UPSTREAM=http://localhost:8010 \
  go run ../../cmd/zero-pep-proxy
```

Drive it (browser at `http://localhost:8080/`, or curl):

```sh
curl -s -c jar -b jar -L http://localhost:8080/oauth2/start -o /dev/null   # login via the mock IdP
curl -s -b jar http://localhost:8080/oauth2/userinfo                       # → the mock identity
curl -s -i -b jar http://localhost:8080/api/protected-dpop                 # → 200, zaddy verified the proof
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8010/protected-dpop  # → 401 (no token)
```

The `/api` call shows the whole chain: pep exchanges the code at `/token` with `private_key_jwt` + a DPoP
proof (so the AS issues a `cnf.jkt`-bound token), then injects `Authorization: DPoP <token>` + a fresh proof
bound to the upstream request; zaddy verifies token + proof + scope. No external network.

`pdp-config/` and `zaddy-config/` carry **non-production test keys** for this harness only.
