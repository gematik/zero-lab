# Session storage integrity & at-rest encryption

How `pep/proxy` protects server-side sessions in the kv store against an adversary who can read — and write —
the store, without holding the encryption key.

## Threat model

The session record holds the crown jewels: refresh tokens, the per-session DPoP private key, and the
identity claims. The kv store (Redis / Postgres) is a separate trust domain from the pep process.

| Adversary | Capability |
| --- | --- |
| **T-storage** | Full read/write on the kv store. **No** host access — cannot read the key file or process memory. |
| **T-host** | Also reads the key file, environment, and process memory. Effectively a host compromise (T3). |

Everything below defends **T-storage**. T-host is out of reach of on-host keys and needs a KMS/HSM (see
*Residual risks*); the code is shaped so that upgrade is a drop-in.

## Risks and mitigations

| # | Risk (what the rogue admin does) | Mitigation | Status |
| --- | --- | --- | --- |
| 1 | **Disclosure** — read tokens / DPoP key / identity from a dump | AES-256-GCM on every value in the kv store; keys from a `*_PATH` file, never in the kv | ✅ |
| 2 | **Forgery** — craft a record for a chosen identity / scope | Authenticated encryption (GCM tag): cannot produce a valid record without the key. A plaintext record does not open either | ✅ |
| 3 | **Substitution** — copy session A's record onto session B's key | The associated data binds version, key ID, purpose and **the kv key**: a record opens only under its own key. Plus a post-decrypt `record.ID == id` assertion | ✅ |
| 4 | **Session switching** — set your own cookie to a victim's id learned from the kv keys | The cookie carries a random **token**; the kv key is `SHA-256(token)`. The kv holds only hashes — not usable cookies | ✅ |
| 5 | **Tamper / corruption** | A record that does not open surfaces as the distinct `kv.ErrIntegrity`, logged at error level (alertable), and the user gets an invalid session, not a server error | ✅ |
| 6 | **Rollback / replay** — restore a stale-but-valid record (pre-logout / pre-refresh) | Partial: durable revocation set (logout survives a record rollback) + refresh-token rotation + short access-token TTL | ⚠️ residual |
| 7 | **Deletion** — drop records (forced logout / DoS) | Not preventable at the kv layer — operational (RBAC, backups, audit) | ⚠️ residual |
| 8 | **Key exposure** (T-host) — read the key file, decrypt everything | Envelope encryption with a KMS/HSM-held KEK; key never on the host | 🔜 seam ready |

## Design

**One implementation.** The command wraps the store in `kv.NewSealed(store, ring, "pep/session")`, so the session
records, the `pep:state:` index and the `pep:revoked:` records all reach it as ciphertext. The record format and its
guarantees are in the doc comment of `kv.NewSealed`. A per-purpose key comes from the ring key by HKDF-SHA256, and each
record has a fresh random nonce.

**Id-binding** (#3). The kv key is part of the associated data, so a record copied to a different kv key fails
authentication. `byID` additionally rejects any record whose decoded `ID` ≠ the slot it was read from.

**Token hashing** (#4). The browser cookie carries a 256-bit random `token`; the kv record lives under
`ID = hashToken(token) = base64url(SHA-256(token))`. `token` is set on `create`/`rotate`, written to the
cookie, and **never persisted** (an unexported field, so `encoding/json` skips it). `currentSession` resolves
via `byToken` (hash, then `byID`). A T-storage admin enumerating `pep:session:*` keys sees only hashes and
cannot reconstruct a cookie. (Session rotation on login already gives anti-fixation; this closes the
distinct "kv key *is* the bearer token" gap.)

**Revocation set.** `revocation.go` recovers a sid from its key, and kv keys stay in the clear; the value is sealed
but nobody reads it. The sid is `hashToken(token)`, not a secret.

**Keys.** Two independent files, so the two domains share no key material:
- `PEP_SESSION_KEY_PATH` — the snapshot-cookie key (fast-path JWE), one bare base64 256-bit key.
- `PEP_SESSION_STORE_KEY_PATH` — the store's ring, **required** with `DATABASE_URL`: zero-pep-proxy refuses to
  start without it, and nothing makes a key at start. Without `DATABASE_URL` it is optional; the in-memory store
  is then sealed if it is given.

Make a key file, and hand the same file to every replica:

```sh
printf 'k1 %s\n' "$(openssl rand -base64 32)" > store.key
```

The format is one key per line, `<id> <base64 of 32 bytes>`, with `#` comments and blank lines ignored; the first key
seals, all of them open. A file holding one bare base64 key, the format this variable used before, still loads, as
the key `default`.

**Rotation** needs no restart: each replica looks at the file at most every 30 s (mtime and size) and re-reads it when
it changed. A broken file keeps the keys in force and logs at error level. The order, so that no replica meets a
record it cannot open:

1. Add the new key **second** on all pods, and wait until all of them have it.
2. Make it **first**: new records use it, old ones still open.
3. Drop the old key after the longest TTL of a record it sealed (the session lifetime, `PEP_SESSION_TTL` with the
   snapshot fast path).

## Upgrading to sealed records

Records of earlier releases, sealed or not, do not open any more, so every session ends once and the users log in
again. Replicas of the old and the new release cannot read each other's session records during the rollout. Such a
record counts as an invalid session and is logged at error level as `kv record failed its integrity check`, which
during an upgrade is expected.

After the last replica is upgraded, an operator should clear those records. **Keep the revocation records**, or a
session that was signed out before the upgrade could come back through its snapshot cookie:

```sql
DELETE FROM kv WHERE key NOT LIKE 'pep:revoked:%';
```

With the snapshot fast path, also replace the key in `PEP_SESSION_KEY_PATH`. A snapshot cookie is checked without the
kv, so it stays valid for its lifetime after its session record is gone, and signing out cannot revoke a session whose
record no longer opens.

## Residual risks (next tier)

- **#6 Rollback** — GCM does not prevent restoring an older *valid* ciphertext under the same key. Mitigated, not
  closed, by the durable revocation set + refresh-token rotation + short token TTLs. Full prevention needs an external
  monotonic anchor (versioned/append-only store) the admin cannot also roll back.
- **#7 Deletion / availability** — a write-capable admin can always delete; this is an operational control
  (least-privilege on the kv, audited access, backups), not a crypto one.
- **#8 T-host / key exposure** — on-host keys fall to a host compromise. `kv.Keys` is the migration path to a
  KMS/HSM-backed ring; a record names its key ID, so a migration can run old and new keys side by side.
- **Keys in the clear** — kv keys are not sealed. `pep:state:<state>` shows pending login states to a T-storage admin
  (TASK-106).
