# zero-pdp — align to the pep standard (+ mock IdP, airgapped compose)

A precursor stage to the pep **S4 PDP backend** ([`../../pep/proxy/docs/pdp-backend.md`](../../pep/proxy/docs/pdp-backend.md)).
It brings `zero-pdp` up to the conventions pep established (config, secrets, Docker, docs), bakes in a **mock
IdP** so the PDP can authenticate without a real OP, and puts the PDP **in `docker compose`** — so S4's HITL is
**fully airgapped**. This stage stands on its own (the PDP reaches the standard regardless of S4) and ships as
its own PR with its own HITL.

## Why
- The PDP and pep configure the **same providers** (OIDC / gemidp / OIDF). pep now loads them from a flat
  `openid-providers.yaml`; the PDP should share that format (the original overlap goal).
- pep set the house style this session — env + `*_PATH` secrets, secure-by-default, `/app` binary + mountable
  `/etc/<svc>` workdir, `just docker-build/push-<svc>` + version stamp, `CONFIG.md` + `DOCKERHUB.md`. The PDP
  should match so the two read as one project.
- S4's e2e must run with **no network egress**; today the PDP needs a real upstream IdP. A baked-in mock IdP
  removes that dependency.

## Scope

### 1. Config: split into providers / domain / runtime
Today `pdp/authzserver/config.Config` is one big YAML. Realign along pep's lines:

- **Providers → shared `openid-providers.yaml`** (`PDP_OPENID_PROVIDERS_PATH`, default
  `openid-providers.yaml`). The `oidc_providers` / `gematik_idp` / `oidf_relying_party` fields move out of the
  PDP YAML into the flat file, **reusing the same leaf types** pep uses (`oauth/oidc.Config`,
  `gemidp.ClientConfig`, `oidf.RelyingPartyConfig`). A PDP-specific top-level struct binds them — no shared
  wrapper package, same as pep.
- **PDP-domain config stays YAML** (`pdp.yaml`): `issuer`, `scopes_supported`, `metadata_template`,
  `default_idp_iss`, `clients`, `products`, `clients_policy_path`, `endpoints`. Kept as a file because it's
  rich + relational, but every path it references uses `*_PATH` and resolves against the file's dir (pep's
  base-path rule).
- **Runtime → env**: `DATABASE_URL` (already), public URL / addr, `PDP_NON_PROD` (was `non_prod_mode`),
  secrets strictly via `*_PATH` files (`sign_jwk_path`, policy path, etc.) — never env values, never in `kv`.
- Provider source precedence + the `-w`/dotenv ergonomics mirror pep where they apply.

### 2. Docker → pep pattern
- Binary at `/app/zero-pdp`; `WORKDIR /etc/pdp` (mount config + secrets there without shadowing the binary);
  `ENTRYPOINT ["/app/zero-pdp"]`. Drop the bespoke `/etc/pdp` mkdir/`PDP_WORKDIR` dance in favor of the same
  shape pep uses.
- `scratch`, non-root, structured logs, secure-by-default.
- Version stamp already exists (`pdp.Version`); wire it the same way pep does in the Dockerfile.

### 3. Build + docs
- `just docker-build-pdp` / `docker-push-pdp` → `spilikin/zero-pdp:<go/pdp/v*>` + `:latest` (mirror the pep
  targets + `_modver`).
- `pdp/cmd/zero-pdp/CONFIG.md` (providers file vs `pdp.yaml` vs env — the same split pep documents) and
  `DOCKERHUB.md` (overview + run + config table + tags).

### 4. Mock IdP (baked in, `NonProdMode`)
The PDP already has `NonProdMode` + `NonProdStartSession` / `NonProdIssueTokens` (today a `nonprod_issue`
CLI). Extend it into a **browser-drivable mock OP**: when `PDP_NON_PROD` is on, the authorization /
OP-callback path **auto-completes with a canned mock identity** instead of redirecting to a real provider —
reusing the existing `NonProd*` session+token machinery. The mock user's claims are configurable (a small
`mock_idp` block, non-prod only). Strictly gated by `NonProdMode`; impossible to enable in prod config.

This is the minimum that makes `browser → pep → pdp → (mock) → token` work with **no external IdP**.

### 5. Compose (airgapped)
Today `pdp/docker-compose.yaml` runs only Postgres. Add the **PDP itself** (built image, `PDP_NON_PROD=true`,
mock IdP, `openid-providers.yaml` mounted at `/etc/pdp`). This is the building block S4's harness composes with
pep + zaddy — entirely local, zero egress.

## Non-goals
- No change to the PDP's authorization/token/introspection **logic** — this is config/docker/docs/test-harness
  alignment only.
- The mock IdP is **non-prod only** and not a real federation member.
- pep's `pdpBackend` (S4) is a separate doc; this stage just makes the PDP a clean, airgapped dependency.

## Verification
- `go build`/`vet`/`test ./pdp/...` green; config loads from the split sources; secrets only from `*_PATH`.
- `just docker-build-pdp` builds; `docker compose up` brings up PDP + Postgres with the mock IdP, no egress.
- **HITL (this stage):** with `PDP_NON_PROD=true`, a client (or `curl`/the existing demo) completes an
  authorization against the **mock IdP** and receives a token — proving the airgapped path the S4 harness
  relies on.
- Module graph unchanged: `zero-caddy` stays free of `oidf/gemidp/kv/pep-proxy`.

## Files (indicative)
- **New:** `openid-providers.yaml` loader for the PDP (PDP-specific top-level struct over the shared leaf
  types); mock-IdP handler under `pdp/authzserver` (gated by `NonProdMode`); `pdp/cmd/zero-pdp/CONFIG.md` +
  `DOCKERHUB.md`; `just` pdp docker targets.
- **Modify:** `pdp/authzserver/config.go` (split providers out; env/`*_PATH` conventions), the PDP
  cmd/config loader, `pdp/cmd/zero-pdp/Dockerfile` (`/app` + `/etc/pdp`), `pdp/docker-compose.yaml` (add the
  PDP service), `Justfile`.
