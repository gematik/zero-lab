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
| 1 | **Disclosure** — read tokens / DPoP key / identity from a dump | AES-256-GCM at rest; key from a separate `*_PATH` file, never in the kv | ✅ |
| 2 | **Forgery** — craft a record for a chosen identity / scope | Authenticated encryption (GCM tag): cannot produce a valid record without the key | ✅ |
| 3 | **Substitution** — copy session A's record onto session B's key | GCM **AAD = the kv id**: a record opens only under its own key. Plus a post-decrypt `record.ID == id` assertion | ✅ |
| 4 | **Session switching** — set your own cookie to a victim's id learned from the kv keys | The cookie carries a random **token**; the kv key is `SHA-256(token)`. The kv holds only hashes — not usable cookies | ✅ |
| 5 | **Tamper / corruption** | GCM open-failure surfaces as a distinct `errRecordIntegrity` (alertable), not a generic decode error | ✅ |
| 6 | **Rollback / replay** — restore a stale-but-valid record (pre-logout / pre-refresh) | Partial: durable revocation set (logout survives a record rollback) + refresh-token rotation + short access-token TTL | ⚠️ residual |
| 7 | **Deletion** — drop records (forced logout / DoS) | Not preventable at the kv layer — operational (RBAC, backups, audit) | ⚠️ residual |
| 8 | **Key exposure** (T-host) — read the key file, decrypt everything | Envelope encryption with a KMS/HSM-held KEK; key never on the host | 🔜 seam ready |

## Design

**At-rest record cipher** (`at_rest.go`). `recordCrypter` is a pair of closures, `seal(plaintext, aad)` and
`open(ciphertext, aad)`. The key is consumed only inside `newAESRecordCrypter` to build the AES-256-GCM AEAD
and is captured by the closures — it is **never stored on a struct, returned, or referenced elsewhere**. That
is the KMS seam (#8): a `newKMSRecordCrypter` returning closures that call a KMS — key never on the host —
drops in with no change to call sites. `open` collapses every authentication failure to a single
`errRecordIntegrity` sentinel.

**Id-binding** (#3). `save` seals with `aad = []byte(session.ID)`; `byID` opens with `aad = []byte(id)`. A
record copied to a different kv key fails authentication. `byID` additionally rejects any record whose
decoded `ID` ≠ the slot it was read from.

**Token hashing** (#4). The browser cookie carries a 256-bit random `token`; the kv record lives under
`ID = hashToken(token) = base64url(SHA-256(token))`. `token` is set on `create`/`rotate`, written to the
cookie, and **never persisted** (an unexported field, so `encoding/json` skips it). `currentSession` resolves
via `byToken` (hash, then `byID`). A T-storage admin enumerating `pep:session:*` keys sees only hashes and
cannot reconstruct a cookie. (Session rotation on login already gives anti-fixation; this closes the
distinct "kv key *is* the bearer token" gap.)

**Keys.** Two independent files, each a base64 256-bit key (`loadBase64Key`):
- `PEP_SESSION_KEY_PATH` — the snapshot-cookie key (fast-path JWE).
- `PEP_SESSION_STORE_KEY_PATH` — the at-rest record key. **Separate** by request, so the two domains share no
  key material. When unset, records are stored as plaintext JSON (the cipher is simply absent).

## Residual risks (next tier)

- **#6 Rollback** — GCM does not prevent restoring an older *valid* ciphertext. Mitigated, not closed, by the
  durable revocation set + refresh-token rotation + short token TTLs. Full prevention needs an external
  monotonic anchor (versioned/append-only store) the admin cannot also roll back.
- **#7 Deletion / availability** — a write-capable admin can always delete; this is an operational control
  (least-privilege on the kv, audited access, backups), not a crypto one.
- **#8 T-host / key exposure** — on-host keys fall to a host compromise. The `recordCrypter` closure seam is
  the migration path to a KMS/HSM-backed KEK (envelope encryption) where the key never reaches the host. The
  kv carries a per-value **metadata** descriptor (`kv.Entry.Metadata`, read via `GetItem`) so a migration can
  run mixed schemes — tagging each record's codec (`aes256gcm`, `kms-envelope-v1`, …) and dispatching the
  right decryption per value instead of via a single global flag. In Postgres it is a `jsonb` column; a Redis
  backend would model each entry as a hash with `value`+`metadata` fields.
- **State index** — `pep:state:<state> → id` is stored unencrypted (the id is a hash, not a secret). A
  T-storage admin could repoint a login state to another session; the callback's own state/session checks
  bound the impact. Binding the index (AAD = state) is a possible future hardening.
