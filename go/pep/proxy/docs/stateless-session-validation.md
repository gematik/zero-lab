# Stateless session validation — signed snapshot + revocation bus

**Status:** Accepted, not yet implemented (planned, pre-S4).
**Scope:** `pep/proxy` session validation on the `/oauth2/auth` (forward_auth) hot path.
**Supersedes:** the per-request `kv.byID()` lookup described in `DESIGN.md` §2.

## Context

`/oauth2/auth` runs on **every** request to a protected upstream (Caddy `forward_auth`). Today it resolves
the session by doing a `kv` read (`currentSession` → `byID`) per request, so the database is hit once per
upstream request. At steady-state traffic that is the dominant load on `kv` and adds a round-trip to every
request.

Constraints that shape the solution:

- **Horizontally scaled** — multiple `pep` replicas behind a load balancer. Any per-replica state (caches,
  revocation lists) must converge across replicas; a per-replica in-memory cache alone is not coherent.
- **Instant revocation is a hard requirement** — logout / forced lockout must take effect immediately and
  fleet-wide (healthcare / zero-trust). A short TTL alone (eventual expiry) is not acceptable.
- Keep the **token-mediating BFF** property: IdP access/refresh tokens stay server-side in `kv`; they are
  never placed in the browser.

This is the well-known **"cookie caching" / hybrid session** pattern: keep the infrequent auth flow
server-side and revocable, make the hot per-request check verify a short-lived locally-signed credential.

## Decision

Validate the hot path locally from a **signed session-snapshot cookie**, and make revocation **instant and
fleet-wide** with an in-memory revoked-session set kept in sync over a **`kv` revocation bus** (pub/sub),
backed by a durable `kv` set so a missed message cannot leak access for long.

`kv` reads on the hot path drop from *per request* to *~once per snapshot-TTL per active session* (the
re-mint), with **no `kv` read at all** while a snapshot is valid.

## Design

### 1. Cookies

Two cookies (cookie-caching style — the opaque id stays canonical; the snapshot is the local-verify cache):

- **Session cookie** (existing): opaque session id, `HttpOnly`, `__Host-`+`Secure` in prod, `SameSite=Lax`.
  Resolves the server-side session in `kv` (tokens, identity, the revocation point). Drives the auth flow
  and the fast-path fallback. Unchanged.
- **Snapshot cookie** (new): a compact **JWE** (`dir` + `A256GCM` — authenticated encryption with the shared
  key below) carrying only what `/oauth2/auth` needs to answer locally — the same data it already emits as
  headers:

  ```
  { sid, sub, email, groups, iat, exp }      exp = iat + SNAPSHOT_TTL   (default 2–5 min)
  ```

  `HttpOnly`, `__Host-`+`Secure` in prod, `SameSite=Lax`. It is **not** an IdP token — it is pep's own
  identity assertion. It is **encrypted**, not just signed: the claims are PII (`email`), so the browser holds
  an opaque blob (data minimization + the BFF "nothing identity-bearing client-side" property), and AES-GCM
  gives integrity in the same primitive. Encryption is for confidentiality, **not** anti-replay — a stolen
  snapshot is replayable either way; that is handled by the cookie hardening, short TTL, and revoked-set.

Set/refreshed together at login, on rotation, and whenever the fast path re-mints (below).

### 2. Snapshot key

`PEP_SNAPSHOT_SECRET` — a 256-bit symmetric key (the `A256GCM` content-encryption key), **stable
configuration, shared across all replicas and stable across restarts** (not per-process random) — so any
replica decrypts any replica's snapshot and a restart does not invalidate outstanding snapshots.
**Rotation:** accept a primary + one previous key; encrypt with the primary, decrypt with either; drop the
previous after `SNAPSHOT_TTL`. If the key is unavailable/rotated out, snapshots simply fail to decrypt →
graceful fallback to the opaque cookie + `kv` (re-mint), never a lockout.

### 3. Fast path — `/oauth2/auth`

```
read snapshot cookie
  decrypt + authenticate (AES-256-GCM)
    invalid/absent → fall back (below)
  valid:
    if sid ∈ revokedSet            → 401            # instant revocation
    if exp in the past             → fall back (below)
    else → 202 + X-Auth-Request-* from claims       # no kv, no network

fall back (snapshot expired/absent, signature still readable for the sid, or via the opaque cookie):
  resolve session id (from the signed-but-expired snapshot, else the opaque session cookie)
  load from kv (this re-checks the idle + absolute TTLs and existence — the source of truth)
    not found / expired / revoked → 401
  re-mint the snapshot cookie (Set-Cookie on the /auth response)
  202 + X-Auth-Request-*
```

The fallback is the only place `kv` is touched, at most once per `SNAPSHOT_TTL` per active session, and it is
where the existing **idle/absolute TTL** hardening is re-enforced.

### 4. Revocation bus

A small new `kv` pub/sub seam, implemented per backend:

- **Redis:** `PUBLISH`/`SUBSCRIBE` on a `pep:revoked` channel.
- **Postgres:** `LISTEN`/`NOTIFY`.
- **In-memory** (single instance / tests): a Go channel fan-out.

Interface sketch (kept minimal, added to the `kv` module):

```go
type RevocationBus interface {
    Revoke(ctx, sid string) error        // publish + write durable backstop entry
    Subscribe(ctx) (<-chan string, error) // revoked sids, fan-out to all replicas
}
```

On the bus event each replica adds `sid` to its in-memory `revokedSet`, with an entry TTL = `SNAPSHOT_TTL`
(self-cleaning — once the snapshot is past `exp` it is rejected by the `exp` check anyway, so the entry can
be dropped).

**Durable backstop:** `Revoke` also writes `sid` to a `kv` set `pep:revoked` with TTL = `SNAPSHOT_TTL`. Each
replica **loads it on startup** (so a freshly-joined replica is not blind) and **reconciles** it on a short
interval. So a dropped pub/sub message bounds exposure to the reconcile interval, not the whole TTL.

### 5. Revocation, logout, and rotation are one mechanism

- **Logout / forced lockout:** delete the `kv` session, `Revoke(sid)`, clear both cookies. A stolen snapshot
  is rejected fleet-wide within pub/sub latency (ms), backstopped by `pep:revoked`.
- **Session-id rotation** (the anti-fixation change): on rotation, `Revoke(oldSid)` and mint a fresh snapshot
  for the new sid — so a lingering old snapshot is killed immediately rather than living until `exp`.

### 6. Interactions

- Token-mediating BFF preserved: tokens stay in `kv`; the snapshot carries only identity claims.
- Idle + absolute TTLs (existing) are re-checked on the fallback path (≤ `SNAPSHOT_TTL` lag); set
  `SNAPSHOT_TTL` ≤ the idle TTL.
- Single-use `state` (existing) is unaffected — it lives entirely in the auth flow.

## Durability & restart survival

Sessions must survive pep restarts and replica replacement. Nothing session-critical lives only in process:

- **Source of truth = persistent shared `kv`.** Sessions (tokens, identity, TTLs) live in Redis/Postgres, not
  in memory, so a restart loses no session. **Prerequisite:** the cmd must wire a persistent `kv` — today it
  uses `kv.NewMemory()`, which is dev-only and survives neither restarts nor scale-out. (This is required for
  *any* multi-replica / restart-surviving deployment, independent of this design.)
- **Snapshot = client-side cookie + stable key.** It is held by the browser, so it survives a restart on its
  own; with the stable configured key any replica still decrypts it after a restart and can answer
  `/oauth2/auth` *without touching `kv`* — so no thundering-herd of re-validation when a replica comes back.
- **Revoked-set rebuilt on startup** from the durable `pep:revoked` `kv` set (TTL = `SNAPSHOT_TTL`), then kept
  live over the bus — so revocations also survive restarts and a freshly-started replica is never blind.

Net: a restart (or a rolling deploy) is transparent — outstanding snapshots keep verifying locally, and the
worst case is the usual `kv` fallback + re-mint, never a forced re-login.

## Security properties & trade-offs

- **Hot path:** AES-256-GCM decrypt (µs) + set membership (O(1)). No DB, no network.
- **Revocation latency:** pub/sub propagation (ms); worst case (missed message) bounded by the backstop
  reconcile interval, not `SNAPSHOT_TTL`.
- **Snapshot confidentiality:** encrypted, so a cookie thief cannot read the embedded claims (`email` etc.)
  without the key; the browser holds an opaque blob. A *stolen* snapshot is still replayable (encryption is
  not anti-replay) — bounded by `HttpOnly`+`Secure`+`__Host-`, the short `SNAPSHOT_TTL`, and the revoked-set.
- **Key compromise:** a leaked `PEP_SNAPSHOT_SECRET` lets an attacker both forge and decrypt snapshots →
  treat as a security incident, rotate the key (two-key overlap makes rotation non-disruptive). The key never
  leaves the server.
- **Cookie size:** one extra small JWE (~300–400 B). Acceptable.

## Alternatives considered

- **Per-request `SISMEMBER pep:revoked <sid>` (Redis-only) + snapshot.** Truly instant, much simpler (no
  pub/sub), but still one Redis round-trip per request — does not meet the "no DB per request" goal. Kept as
  a documented lighter fallback if the bus proves too heavy.
- **Pure stateless JWT session (no server state).** No instant revocation without a denylist anyway, and it
  breaks token-mediating (tokens would have to live client-side). Rejected.
- **In-process TTL cache in front of `kv`.** Simplest, but per-replica caches are incoherent under scale and
  can serve a revoked session until the cache TTL. Rejected for the instant-revocation requirement.
- **JWT verified at the edge by Caddy (drop the forward_auth round-trip).** Most scalable — removes the
  Caddy→pep hop too — but a bigger blast radius (Caddy JWT plugin, JWKS, upstream reads claims, revocation
  via denylist push). Deferred as a later optimization (was "Option C").

## Test plan

- Snapshot mint → verify (valid sig, claims), `exp` rejection, tamper rejection, wrong-secret rejection,
  previous-secret accepted during rotation.
- Fast path: valid snapshot → 202 + headers, **no `kv` access** (assert via a counting `kv`); expired → falls
  back, re-mints, 202; absent → falls back via the opaque cookie.
- Revocation: `Revoke(sid)` → fast path returns 401 for that sid; entry self-expires after `SNAPSHOT_TTL`.
- Rotation: after rotate, the **old** sid is revoked (old snapshot → 401), the new snapshot → 202.
- Fleet sim: two stores sharing one in-mem bus — `Revoke` on one is seen by the other; startup backstop load;
  reconcile picks up a "missed" entry.

## Rollout (stages, each HITL-gated)

0. **Prerequisite — persistent shared `kv`.** Wire the cmd to a Redis/Postgres `kv` (the bff/pdp `openStore()`
   pattern: persistent when `DATABASE_URL`/Redis is configured, in-memory only for dev/tests) so sessions
   survive restarts and replicas. Required regardless of the rest of this design.
1. Snapshot cookie + `/oauth2/auth` fast path with fallback; in-mem bus; secret + rotation. Single instance.
2. `kv` revocation bus for Redis (PUB/SUB) and Postgres (LISTEN/NOTIFY); wire `Revoke` into logout + rotation.
3. Durable `pep:revoked` backstop: startup load + periodic reconcile.
4. HITL: on-device + QR login, instant logout across two replicas, missed-message backstop; then enable.
