# ENCRYPTION_KEY rotation procedure

> **Status**: This document is the canonical operator runbook for rotating
> SBOMHub's `ENCRYPTION_KEY`. A turnkey `sbomhub migrate-encryption` subcommand
> is **not yet implemented** (tracked as a follow-up — see
> "Follow-up: automation" below). Until then, operators must follow the manual
> SQL procedure documented in this runbook.
>
> Japanese version: [`encryption-key-rotation.ja.md`](./encryption-key-rotation.ja.md).

`ENCRYPTION_KEY` is the AES-256 master key used by the API server to encrypt
sensitive credentials at rest in the database. Rotating it is a planned,
**short-downtime** maintenance operation: the API must be offline while
ciphertext is re-encrypted under the new key.

---

## 1. When to rotate

Rotate `ENCRYPTION_KEY` in any of the following situations:

- **Incident response** — the current key is known or suspected to be
  compromised (leaked from `.env`, exposed in a backup, committed to git, etc.).
  Rotate immediately and treat any data the key protected as potentially
  exposed.
- **Known default / placeholder key used in production** — if the API ever
  booted in production against a key that matches one of the placeholders
  enumerated in `apps/api/cmd/server/main.go` (`knownDefaultEncryptionKeys`),
  rotate to a fresh random key as soon as possible.
- **Routine rotation (recommended: every 90 days)** — operate on a
  calendar-driven schedule (Google Calendar / Outlook reminder is fine) so that
  rotation is exercised and the runbook is known to work *before* you need it
  in an incident.
- **Personnel / scope change** — anyone who previously had read access to the
  key but no longer needs it (offboarding, contractor rotation,
  re-organisation).

---

## 2. Before you begin

### 2.1 Data affected by `ENCRYPTION_KEY`

`ENCRYPTION_KEY` is currently used to encrypt the following data at rest. Verify
on your own checkout with:

```bash
grep -rn 'EncryptionKey\|encryptionKey\|GetEncryptionKey' apps/api/ --include='*.go' \
  | grep -v '_test.go'
```

| Table | Column | What it stores | Encryption | Re-encrypt needed? |
| --- | --- | --- | --- | --- |
| `issue_tracker_connections` | `auth_token_encrypted` | API token for the connected Jira / Backlog instance (per tenant) | AES-256-GCM (random 12-byte nonce, base64-encoded ciphertext) | **Yes** |
| `api_keys` | `key_hash` | SHA-256 hash of an issued SBOMHub API key | SHA-256 (one-way hash, **not** encrypted with `ENCRYPTION_KEY`) | No — hashes are unaffected by rotation |

> The exhaustive enumeration above is current as of this document's commit. If
> future work adds another encrypted column it **must** be added to this table
> and to the migration procedure in §3.

### 2.2 Mandatory pre-flight checklist

> **WARNING — do all of the following before touching `ENCRYPTION_KEY`. If you
> skip step 1 (database dump) and step 4 (verified old key) and the rotation
> fails, the affected ciphertext is unrecoverable.**

1. **Take a full database dump and verify it.**

   ```bash
   docker compose exec -T postgres \
     pg_dump -U sbomhub_app sbomhub > backup-pre-rotation-$(date +%Y%m%d).sql

   # Sanity-check that it is non-empty and parses.
   wc -l backup-pre-rotation-*.sql
   head -5 backup-pre-rotation-*.sql
   ```

   Store the dump on a host that is **not** the API server, and treat it as
   sensitive (it contains the old ciphertext).

2. **Snapshot `.env`** so the old key is recoverable for rollback.

   ```bash
   cp .env .env.bak.pre-rotation.$(date +%Y%m%d)
   chmod 600 .env.bak.pre-rotation.*
   ```

3. **Schedule a maintenance window** and notify users. The API is offline for
   the duration of the migration. For a fresh install with no issue tracker
   integrations the window is seconds; in environments with many connections it
   scales linearly with the row count of `issue_tracker_connections`.

4. **Confirm you actually have the current key.** Rotation requires both the
   *old* key (to decrypt) and the *new* key (to re-encrypt). If you no longer
   have the old key, you cannot re-encrypt ciphertext; you must instead drop
   the affected rows and have tenants re-enter their tokens after rotation —
   see §6 for that fallback.

---

## 3. Rotation procedure (short downtime)

The high-level flow is:

```
stop API → generate new key → re-encrypt ciphertext with new key
  → swap .env → start API → verify
```

### Step 1 — Stop the API

```bash
docker compose stop api
```

Leave `postgres` and `redis` running. The migration script needs database
access.

### Step 2 — Generate the new key and keep the old one

```bash
NEW_KEY="$(openssl rand -base64 32)"

# Save the old key into your shell session for the migration step.
# (Do not write it back to .env until step 4.)
OLD_KEY="$(grep ^ENCRYPTION_KEY= .env | cut -d= -f2-)"

echo "OLD: $OLD_KEY"
echo "NEW: $NEW_KEY"
```

Both values are sensitive. Keep them in the shell session only; do not echo
them into shared logs or chat.

### Step 3 — Re-encrypt the affected ciphertext

A turnkey subcommand is **not yet implemented**. Until it lands, run the
following manual procedure inside a single transaction so a partial failure
rolls back cleanly.

The encryption scheme is **AES-256-GCM** with a 12-byte random nonce, where
the on-disk format is `base64( nonce || ciphertext || gcm_tag )`. The cipher
implementation lives at
[`apps/api/internal/service/issue_tracker.go`](../apps/api/internal/service/issue_tracker.go)
(see `encrypt` / `decrypt`).

> **Why this needs a real program, not shell.** AES-256-GCM with a random
> nonce per record cannot be expressed safely in pure SQL. The recommended
> path is a small one-off Go program that imports the same cipher logic. A
> skeleton for this program is the planned follow-up (see "Follow-up:
> automation" below). The pseudocode is:

```text
for each row in issue_tracker_connections:
    plaintext  := AES-256-GCM-decrypt(old_key, base64_decode(row.auth_token_encrypted))
    new_cipher := AES-256-GCM-encrypt(new_key, plaintext)   # fresh random nonce
    UPDATE issue_tracker_connections
       SET auth_token_encrypted = base64_encode(new_cipher),
           updated_at = NOW()
     WHERE id = row.id
```

Operational guard rails:

- Run the loop inside one transaction (`BEGIN ... COMMIT`). On any error,
  `ROLLBACK` and abort the rotation. The DB snapshot from §2.2 is the safety
  net behind the transaction.
- Connect with the `sbomhub_migrator` role, not `sbomhub_app`. The migrator
  role owns the schema and is not subject to RLS (RLS is enforced on the
  application role only — see `apps/api/migrations/023_rls_security_hardening.up.sql`).
- Verify every row decrypts under the *old* key before encrypting *any* row
  under the new key. A single undecryptable row means the on-disk ciphertext
  was not produced by `old_key`, and silently skipping it would orphan the
  tenant's integration.
- Log row counts (`before` / `decrypted` / `re-encrypted`); they must all
  match. Do **not** log plaintext tokens or either key.

### Step 4 — Swap the key in `.env`

The most robust way is to re-run the installer with `--force`, which backs the
existing `.env` up to `.env.bak.YYYYMMDD` and issues a fresh
`ENCRYPTION_KEY` (and fresh DB passwords).

> **Caveat**: `install.sh --force` also rotates `sbomhub_app` and
> `sbomhub_migrator` passwords. That breaks an already-initialised database
> unless you also rotate the matching PostgreSQL roles. **For an
> `ENCRYPTION_KEY`-only rotation, edit `.env` in place rather than
> `--force`-installing.**

In-place edit:

```bash
# Replace the ENCRYPTION_KEY line in .env with the NEW_KEY from step 2.
# (Use your editor of choice; the example below uses awk to be POSIX-portable.)

awk -v new="$NEW_KEY" 'BEGIN{FS=OFS="="} /^ENCRYPTION_KEY=/{$2=new; print; next} 1' \
  .env > .env.tmp && mv .env.tmp .env
chmod 600 .env
```

### Step 5 — Start the API and verify

```bash
docker compose up -d api
docker compose logs -f api | head -50
```

`apps/api/cmd/server/main.go` runs `validateEncryptionKey` at startup; if the
new key is a known placeholder or shorter than 32 bytes the server refuses to
boot. A clean startup is the first confirmation that `.env` was edited
correctly.

Then run the verification checks in §4.

---

## 4. Verification

After rotation, confirm end-to-end that the new key is in effect and previously
encrypted records are still readable.

1. **`sbomhub doctor`** (CLI) — runs API reachability and auth probes against
   the configured endpoint.

   ```bash
   sbomhub doctor
   ```

   The `auth-verify` check must pass (it round-trips an authenticated request;
   any 401 means either the API key or the new `ENCRYPTION_KEY` startup is
   wrong).

2. **API keys list (web UI)** — open the web UI, sign in, navigate to the API
   keys page. Existing keys must list with their `key_prefix`. Because
   `api_keys` are SHA-256-hashed (not encrypted under `ENCRYPTION_KEY`),
   rotation must not affect them — if any key is now invalid, something else
   is broken; do not retry rotation.

3. **Issue tracker connections** — open the integrations page for any tenant
   that previously had a Jira or Backlog connection configured. The connection
   must list as active. Trigger a manual sync (or create a test ticket) to
   confirm the API token re-encrypted under the new key still authenticates
   against the upstream tracker. If the sync fails with `401 Unauthorized`
   from the upstream, the re-encryption step (§3 step 3) skipped or corrupted
   that row — restore from the §2.2 snapshot and re-run.

4. **Application logs** — `docker compose logs api` must show no
   `failed to decrypt`, `cipher: message authentication failed`, or
   `ciphertext too short` errors. Any of those indicates a row was *not*
   re-encrypted and is now unrecoverable under the new key.

5. **`verify-encryption.sh` smoke test** — run the dedicated decrypt
   round-trip CLI (M5-5, issue
   [#53](https://github.com/youichi-uda/sbomhub/issues/53)) to confirm the
   new key actually decrypts the re-encrypted ciphertext at the DB layer:

   ```bash
   ENCRYPTION_KEY="$(cat docker/secrets/encryption_key.txt)" \
   ./docker/scripts/verify-encryption.sh \
       --db-url "$DATABASE_URL"
   ```

   Equivalent file-based invocation:

   ```bash
   ./docker/scripts/verify-encryption.sh \
       --key-file docker/secrets/encryption_key.txt \
       --db-url "$DATABASE_URL"
   ```

   On success the script prints `ok ... sha256=<hex>`; on failure it exits
   non-zero with a classification:

   | exit | meaning |
   |---|---|
   | 0  | new key decrypts a sample row (rotation OK so far) |
   | 1  | key mismatch / ciphertext tampered — investigate before reopening traffic |
   | 2  | DB error (DSN, role permissions) |
   | 3  | no encrypted row to test (no BYOK / no integration configured yet) |

   To verify the round-trip across **the same secret** under both old and
   new keys (recommended sanity check), run the script twice with
   `ENCRYPTION_KEY=...` or `--key-file` pointing at the two keys; the SHA256
   hashes printed must match. The plaintext itself is never emitted. The legacy
   `--key` argv path is still accepted for compatibility but is deprecated
   because command-line arguments are easier to expose via `ps` / procfs.

   See [`security/self-host-deployment.md`](./security/self-host-deployment.md) §4.5
   for the full operator contract.

---

## 5. Rollback

Use this path only if §3 step 3 (re-encryption) failed mid-run or §4 detected
data loss after restart. Do **not** attempt to "patch up" a half-rotated
database in place.

1. Stop the API.

   ```bash
   docker compose stop api
   ```

2. Restore `.env` from the snapshot.

   ```bash
   cp .env.bak.pre-rotation.YYYYMMDD .env
   chmod 600 .env
   ```

3. Restore the database from the §2.2 dump.

   ```bash
   docker compose exec -T postgres \
     psql -U sbomhub_app -d sbomhub < backup-pre-rotation-YYYYMMDD.sql
   ```

   If the dump was taken with `pg_dump` against a running database, the
   restore replays the entire schema; for the no-data-loss case prefer
   `pg_restore --clean` with a custom-format dump in production.

4. Start the API and rerun the §4 verification.

   ```bash
   docker compose up -d api
   sbomhub doctor
   ```

5. Investigate why the rotation failed before retrying. The most common cause
   is a row whose ciphertext was not produced by the supposed "old" key (e.g.
   the row predates a previous, undocumented rotation).

---

## 6. Fallback when the old key is lost

If you reach §3 step 3 with no working "old" key — e.g. recovering from an
incident where the previous `.env` was destroyed — you cannot decrypt the
existing ciphertext. The pragmatic recovery is:

1. Set a fresh `ENCRYPTION_KEY` via §3 step 4.
2. `TRUNCATE issue_tracker_connections;` (or `DELETE` per-tenant if you can
   identify which tenants you actually want to wipe).
3. Notify affected tenants that their Jira / Backlog connection must be
   re-entered through the integrations page. They will paste their token
   again; the new key will encrypt it.

This costs the integration tokens but preserves every other tenant artefact
(SBOMs, vulnerabilities, VEX, audit log, etc.) because none of those use
`ENCRYPTION_KEY`.

---

## 7. Schedule recommendation

| Trigger | Cadence | Notes |
| --- | --- | --- |
| Routine rotation | Every 90 days | Calendar reminder is sufficient. Rehearse on a staging environment first if you have one. |
| Incident (key leak) | Immediately | Treat all `issue_tracker_connections` tokens as exposed; rotating the master key does not invalidate already-exfiltrated plaintext. After rotation, advise affected tenants to also rotate their *upstream* Jira / Backlog tokens. |
| Personnel change | Within 7 days of offboarding | If the leaver had operator access to `.env`, rotate. |
| First boot under a known default key | As soon as `apps/api/cmd/server/main.go` `validateEncryptionKey` is updated and you upgrade | The startup check blocks new boots, but already-encrypted rows under the default key are still readable until rotated. |

A simple Google Calendar reminder template:

```
Title: SBOMHub ENCRYPTION_KEY rotation due
Repeat: every 90 days
Notes: Follow docs/encryption-key-rotation.md.
       Take a DB snapshot before starting. Do NOT use install.sh --force
       for a key-only rotation.
```

---

## Follow-up: automation

A `sbomhub migrate-encryption` (or `apps/api/cmd/migrate-encryption`)
subcommand that wraps §3 step 3 is **not yet implemented**. Tracked as a
follow-up issue (operators or contributors should open one if missing).
Suggested design when the follow-up is picked up:

- Flags: `--old-key <base64>`, `--new-key <base64>`, `--dry-run`,
  `--table issue_tracker_connections` (extensible).
- Connects with the `sbomhub_migrator` role (bypasses RLS, owns the schema).
- Reuses the AES-GCM helper from `apps/api/internal/service/issue_tracker.go`
  so the cipher contract stays in one place.
- `--dry-run` reports the count of rows it *would* re-encrypt and verifies
  every row decrypts under `--old-key`, without writing.
- Wraps the rewrite in a single transaction.
- Refuses to run if `APP_ENV=production` and `--dry-run` was not passed at
  least once with a successful decrypt count matching the row count.

Until the subcommand exists, treat §3 step 3 as the source of truth.
