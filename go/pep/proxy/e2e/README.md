# pep proxy — HITL / e2e harness

A reproducible local stack for driving the pep oauth2-proxy end to end: OIDC / OIDF / gemidp login,
forward_auth gating, the snapshot fast path, and revocation.

## Ports — one front

Everything hangs off **one public port**. Point your (hand-run) rathole tunnel — or your browser — at it.

| Service | Port | Reached by |
| --- | --- | --- |
| **Caddy (front)** | **`:8080`** | your browser / rathole — the only public port |
| pep proxy (on the host) | `:4180` | Caddy (`host.docker.internal:4180`) |
| Postgres | `:5432` | pep (`DATABASE_URL`) |
| metsubushi (upstream) | `:8080` (internal) | Caddy (`upstream:8080`) |

`docker compose up` starts Caddy + Postgres + the upstream; **pep runs on the host** (so it can read local
OIDF secrets + the session key and you can iterate with `go run`). Caddy reaches it via `host.docker.internal`.

## Run

```sh
# 1) supporting stack — Caddy(:8080) + Postgres(:5432) + metsubushi
docker compose -f pep/proxy/e2e/docker-compose.yaml up --build

# 2) one-time — a session key file (enables the snapshot fast path; omit to use the per-request kv path)
openssl rand -base64 32 > /tmp/pep-session.key

# 3) the proxy, on the host. OIDF example — PEP_PUBLIC_URL is your rathole host:
DATABASE_URL="postgres://zero:zero@127.0.0.1:5432/zero?sslmode=disable" \
PEP_SESSION_KEY_PATH=/tmp/pep-session.key \
PEP_PUBLIC_URL=https://<your-rathole-host> PEP_PRODUCTION_COOKIE=true DEBUG=1 \
PEP_OIDF_RP_CONFIG_PATH="$HOME/.config/telematik/pdp/directory-ref/oidf_relying_party.yaml" \
  go run ./pep/cmd/zero-pep-proxy
```

Point rathole at **`localhost:8080`**, browse to your rathole host, and log in. The metsubushi page shows the
injected `X-Auth-Request-*` headers + a **Log out** button.

### Variants

- **Plain OIDC (no tunnel)** — drop the OIDF vars, set `PEP_OIDC_ISSUER` / `PEP_OIDC_CLIENT_ID` /
  `PEP_OIDC_CLIENT_SECRET`, and `PEP_PUBLIC_URL=http://localhost:8080`. Register
  `http://localhost:8080/oauth2/callback` at the provider. Browse `http://localhost:8080/`.
- **Several providers** — drop an `openid-providers.yaml` next to pep (or set `PEP_OPENID_PROVIDERS_PATH`); see `../../cmd/zero-pep-proxy/openid-providers.example.yaml`.
- **No DB / no snapshot** — omit `DATABASE_URL` and `PEP_SESSION_KEY_PATH` (in-memory store, per-request kv;
  sessions don't survive a restart and the fast path is off).
- **Fully containerized OIDC demo** (pep in a container, no host go-run, no Postgres) —
  `../../cmd/zero-pep-proxy/docker-compose.yaml` (`cp .env.example .env` first). Same `:8080` front.

## Two-replica / revocation check

Run a second proxy on `:4181` against the **same** `DATABASE_URL` + `PEP_SESSION_KEY_PATH` (any provider —
it only needs the shared key + DB to validate snapshots and honor revocations):

```sh
DATABASE_URL="postgres://zero:zero@127.0.0.1:5432/zero?sslmode=disable" \
PEP_SESSION_KEY_PATH=/tmp/pep-session.key PEP_ADDR=:4181 PEP_PRODUCTION_COOKIE=true \
PEP_OIDC_ISSUER=https://accounts.google.com PEP_OIDC_CLIENT_ID=dummy \
  go run ./pep/cmd/zero-pep-proxy
```

A logout on one replica is honored by the other instantly (Postgres `LISTEN/NOTIFY`); a freshly started
replica picks up revocations from the durable `pep:revoked` set on startup. See
`../docs/stateless-session-validation.md`.
