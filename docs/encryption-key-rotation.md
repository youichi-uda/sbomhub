# ENCRYPTION_KEY rotation procedure

> **Status**: This document is the canonical operator runbook for rotating
> SBOMHub's `ENCRYPTION_KEY`. The automation-first path is
> [`apps/api/cmd/migrate-encryption`](../apps/api/cmd/migrate-encryption),
> implemented for M6 issue
> [#56](https://github.com/youichi-uda/sbomhub/issues/56). The older manual
> seven-step flow is kept as an offline / emergency fallback in §3.1.
>
> Japanese version: [`encryption-key-rotation.ja.md`](./encryption-key-rotation.ja.md).

`ENCRYPTION_KEY` is the AES-256 master key used by the API server to encrypt
sensitive credentials at rest in the database. Rotating it is a planned,
**short-downtime** maintenance operation: the API must be offline while
ciphertext is re-encrypted under the new key.

Key semantics are defined in
[`docs/security/self-host-deployment.md` §4.2](./security/self-host-deployment.md#42-生成):
SBOMHub uses the first 32 raw bytes of the `ENCRYPTION_KEY` string verbatim and
does not base64-decode `openssl rand -base64 32` output before using it as the
AES key.

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

| Table | Column | Format | What it stores | Encryption path | Re-encrypt needed? |
| --- | --- | --- | --- | --- | --- |
| `tenant_llm_config` | `encrypted_api_key` | BYTEA `nonce \|\| sealed` | BYOK LLM API key (per tenant) | `internal/service/llm/crypto.go`; saved by `internal/handler/settings_llm.go`; decrypted by `cmd/server/llm_resolver.go` | **Yes** |
| `issue_tracker_connections` | `auth_token_encrypted` | TEXT base64 `nonce \|\| sealed` | API token for the connected Jira / Backlog instance (per tenant) | `internal/service/issue_tracker.go` | **Yes** |
| `api_keys` | `key_hash` | SHA-256 one-way hash | Issued SBOMHub API key verifier | `internal/service/apikey.go` verification path only | No — hashes are not encrypted with `ENCRYPTION_KEY` and are unaffected by rotation |

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
   the duration of the migration. For a fresh install with no BYOK LLM keys or
   issue tracker integrations the window is seconds; in environments with many
   connections it scales linearly with the encrypted row count across
   `tenant_llm_config` and `issue_tracker_connections`.

4. **Confirm you actually have the current key.** Rotation requires both the
   *old* key (to decrypt) and the *new* key (to re-encrypt). If you no longer
   have the old key, you cannot re-encrypt ciphertext; you must instead drop
   the affected rows and have tenants re-enter their tokens after rotation —
   see §6 for that fallback.

---

## 3. Rotation procedure (automation-first, short downtime)

Stop the API and prepare both keys:

```bash
docker compose stop api
NEW_KEY="$(openssl rand -base64 32)"

# Source shared env helpers (M7-2 #58)
. docker/scripts/_env_helpers.sh

OLD_KEY="$(read_env_var ENCRYPTION_KEY)"
export OLD_ENCRYPTION_KEY="$OLD_KEY"
export NEW_ENCRYPTION_KEY="$NEW_KEY"
```

Leave `postgres` and `redis` running. The migration binary needs database
access. Both key values are sensitive: pass them through environment variables
only, do not put them in argv, shared logs, shell history, or tickets.

Recommended execution path for Docker Compose is to start a one-shot migration
container with `docker compose run --rm`. Do not use `docker compose exec`
after stopping the API service: `exec` requires a running service container.
Use the service name that matches the compose file you operate.

```bash
# standard compose (root docker-compose.yml service: api)
export DATABASE_URL="$(docker compose -f docker-compose.yml config | awk -F': ' '/DATABASE_URL:/ {print $2; exit}')"
docker compose -f docker-compose.yml run --rm \
  --entrypoint /usr/local/bin/migrate-encryption \
  -e OLD_ENCRYPTION_KEY \
  -e NEW_ENCRYPTION_KEY \
  -e DATABASE_URL \
  api \
  --dry-run --report /tmp/dry-run.json

# enterprise compose (docker/docker-compose.enterprise.yml service: sbomhub-api)
urlenc() {
  printf '%s' "$1" | sed -e 's/+/%2B/g' -e 's|/|%2F|g' -e 's/=/%3D/g' -e 's/@/%40/g' -e 's/:/%3A/g' -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/&/%26/g'
}

APP_PW="$(cat docker/secrets/postgres_app_password.txt)"
APP_PW_ENC="$(urlenc "$APP_PW")"
export DATABASE_URL="postgres://sbomhub_app:${APP_PW_ENC}@postgres:5432/sbomhub?sslmode=disable"
docker compose -f docker/docker-compose.enterprise.yml run --rm \
  --entrypoint /usr/local/bin/migrate-encryption \
  -e OLD_ENCRYPTION_KEY \
  -e NEW_ENCRYPTION_KEY \
  -e DATABASE_URL \
  sbomhub-api \
  --dry-run --report /tmp/dry-run.json
```

Use `-e VAR` (name only), after exporting the value in the host shell. Avoid
`-e VAR=value`, because the expanded secret appears in the host `docker compose`
process argv. The enterprise compose service normally builds `DATABASE_URL`
inside its entrypoint wrapper from Docker secrets, but `--entrypoint
/usr/local/bin/migrate-encryption` intentionally bypasses that wrapper so the
host caller must provide `DATABASE_URL` explicitly. The `--db-url` flag remains
available for backwards compatibility, but this runbook avoids it so the DSN
does not appear in container argv.

> **Warning:** Docker secrets passwords generated with base64 can contain
> characters such as `/`, `+`, `=`, `@`, and `:`. URL-encode the password before
> embedding it in a `postgres://` DSN, otherwise the connection can fail.

If you run the Go command from the host shell instead, first populate
`DATABASE_URL` explicitly. Prefer building the DSN from Docker secrets when the
compose file keeps production credentials out of static environment output:

```bash
# recommended: build the host-run DSN from Docker secrets
urlenc() {
  printf '%s' "$1" | sed -e 's/+/%2B/g' -e 's|/|%2F|g' -e 's/=/%3D/g' -e 's/@/%40/g' -e 's/:/%3A/g' -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/&/%26/g'
}

APP_PW="$(cat docker/secrets/postgres_app_password.txt)"
APP_PW_ENC="$(urlenc "$APP_PW")"
export DATABASE_URL="postgres://sbomhub_app:${APP_PW_ENC}@127.0.0.1:5432/sbomhub?sslmode=disable"

# alternative for standard compose only: read the static DSN from compose config
export DATABASE_URL="$(docker compose -f docker-compose.yml config | awk -F': ' '/DATABASE_URL:/ {print $2; exit}')"
```

Build or run the CLI from `apps/api`:

```bash
cd apps/api
export PATH=$PATH:/usr/local/go/bin
go run ./cmd/migrate-encryption \
  --dry-run \
  --report ../../migrate-encryption-dry-run.json
```

The dry run decrypts every encrypted row with `OLD_ENCRYPTION_KEY`, writes no
database changes, and stores only per-row `SHA256(plaintext)` digests in the
report. Review the summary and keep the report for the apply and verify steps.

Apply the rotation:

```bash
go run ./cmd/migrate-encryption \
  --apply \
  --report-input ../../migrate-encryption-dry-run.json \
  --report ../../migrate-encryption-apply.json
```

The tool loops tenants with `SELECT set_config('app.current_tenant_id', ..., true)`
inside each transaction so `tenant_llm_config` and
`issue_tracker_connections` stay under the same FORCE RLS posture as the
runtime app. Use a `DATABASE_URL` for `sbomhub_app` when possible; it is
`NOBYPASSRLS` and matches production runtime behavior. `sbomhub_migrator` is
also `NOBYPASSRLS` and acceptable when operational policy reserves data
maintenance for that role. In both cases the per-tenant GUC is mandatory.

After apply succeeds, swap `ENCRYPTION_KEY` to `NEW_KEY` in `.env`, Docker
Secrets, or KMS, restart the API, then verify every row against the dry-run
digests:

```bash
go run ./cmd/migrate-encryption \
  --verify \
  --report-input ../../migrate-encryption-dry-run.json \
  --report ../../migrate-encryption-verify.json
```

`--verify` replaces the old Step 2.5 / Step 6 sample-hash comparison. It
decrypts every target row with `NEW_ENCRYPTION_KEY` and compares the per-row
digest with the dry-run report, so verification is not limited to the legacy
`LIMIT 1` smoke sample.

Operational notes:

- Default targets are `tenant_llm_config.encrypted_api_key` (BYTEA) and
  `issue_tracker_connections.auth_token_encrypted` (TEXT base64).
- `--batch-size` defaults to 1000 rows per tenant transaction. Large tenants
  are split into multiple transactions, reducing lock duration and rollback
  scope. ※要確認: rehearse tenants above 10k encrypted rows in staging to size
  lock impact for your DB hardware.
- `--apply` is idempotent. Rows that already decrypt with `NEW_ENCRYPTION_KEY`
  are reported as `already-new` and skipped; rows that decrypt with neither key
  fail.
- If interrupted, rerun with the same dry-run report. For precise resume, pass
  `--resume-from <resume_token>` from the last processed report row. Resume is
  intentionally limited to a single `--table` / `--column` target and a single
  tenant encoded in the token. The token includes an HMAC signature derived from
  the dry-run report file content, so use it with the same `--report-input`.
  Do not use it with the default multi-target run.
- `--continue-on-error` records row failures and continues the current batch.
  Without it, the current transaction rolls back and the command exits.

Resume token example:

```bash
RESUME_TOKEN="$(jq -r '.rows[-1].resume_token' migrate-encryption-apply.json)"
go run ./cmd/migrate-encryption \
  --apply \
  --table tenant_llm_config \
  --column encrypted_api_key \
  --report-input ../../migrate-encryption-dry-run.json \
  --resume-from "$RESUME_TOKEN" \
  --report ../../migrate-encryption-apply-resume.json
```

### 3.1 Manual fallback (offline / emergency only)

Use this fallback only when the Go binary cannot be built or run. The high-level
manual flow is:

1. Decrypt every encrypted row with the old key in a per-tenant loop:
   `tenant_llm_config.encrypted_api_key` and
   `issue_tracker_connections.auth_token_encrypted`.
2. Keep plaintext only in memory; never write it to disk.
   The automation path's `--dry-run` report is the preferred digest record; if
   you are fully manual, use the old Step 2.5 sample check below only as a
   limited fallback.
3. Switch `ENCRYPTION_KEY` to the new key (`.env`, Docker Secrets, or KMS).
4. Restart the server so it boots with the new key.
5. Re-encrypt every plaintext value with the new key and update the DB in a
   per-tenant loop.
6. Run `verify-encryption.sh --key-file <new-key>` and compare its SHA256
   digest with the recorded old-key digest.
7. Destroy the old key after the agreed retention period.

### Manual Step 1 — Decrypt all encrypted rows with the old key

Run the manual procedure in tenant-scoped transactions so a partial failure
rolls back cleanly.

The encryption scheme is **AES-256-GCM** with a 12-byte random nonce.
`tenant_llm_config.encrypted_api_key` stores raw BYTEA `nonce || sealed` via
[`apps/api/internal/service/llm/crypto.go`](../apps/api/internal/service/llm/crypto.go).
`issue_tracker_connections.auth_token_encrypted` stores base64-encoded
`nonce || sealed` via
[`apps/api/internal/service/issue_tracker.go`](../apps/api/internal/service/issue_tracker.go).

> **Why this needs a real program, not shell.** AES-256-GCM with a random
> nonce per record cannot be expressed safely in pure SQL. The recommended
> path is a small one-off Go program that imports the same cipher logic. A
> skeleton for this program is the planned follow-up (see "Follow-up:
> automation" below). The pseudocode is:

```text
for each tenant:
    BEGIN
    SET LOCAL app.current_tenant_id = tenant.id

    for each row in tenant_llm_config where encrypted_api_key is not null:
        plaintext := llm.Decrypt(row.encrypted_api_key, old_key)
        keep plaintext in memory, keyed by row.tenant_id

    for each row in issue_tracker_connections:
        plaintext := issueTrackerDecrypt(base64_decode(row.auth_token_encrypted), old_key)
        keep plaintext in memory, keyed by row.id

    COMMIT
```

Operational guard rails:

- Run each tenant loop inside a transaction (`BEGIN ... COMMIT`). On any
  error, `ROLLBACK` and abort the rotation. The DB snapshot from §2.2 is the
  safety net behind the transaction.
- The `sbomhub_migrator` role is `NOBYPASSRLS`, the same RLS posture as
  `sbomhub_app`. Because `tenant_llm_config` and
  `issue_tracker_connections` use `FORCE ROW LEVEL SECURITY`, a migrator
  SELECT without `app.current_tenant_id` returns zero tenant rows instead of
  bypassing the policy.
- To read every tenant row manually, use one of these RLS-aware options:
  option A (recommended), loop tenants and run
  `SET LOCAL app.current_tenant_id = '<tenant uuid>'` before each SELECT /
  UPDATE; option B, temporarily `DISABLE ROW LEVEL SECURITY` only during the
  rotation and restore `ENABLE` + `FORCE` before reopening traffic, matching
  the migration 045 maintenance pattern; option C, re-encrypt through the API
  per tenant so `sbomhub_app` and the normal tenant context enforce RLS.
- Verify every row decrypts under the *old* key before encrypting *any* row
  under the new key. A single undecryptable row means the on-disk ciphertext
  was not produced by `old_key`, and silently skipping it would orphan the
  tenant's integration or BYOK LLM provider.
- Log row counts (`before` / `decrypted` / `re-encrypted`); they must all
  match. Do **not** log plaintext tokens or either key.

### Manual Step 2 — Keep plaintext in memory only

The plaintext values from Step 1 must stay in process memory only. Do not write
them to temporary files, SQL dumps, shell history, application logs, chat, or
ticketing systems. If the rotation program cannot keep all plaintext in memory,
process one tenant at a time and commit only after that tenant has been
re-encrypted and verified.

### Manual Step 2.5 — Record the old-key plaintext hash before overwriting ciphertext

Before any DB row is re-encrypted with `NEW_KEY`, run the decrypt smoke test
against the still-old-key ciphertext and save only the emitted SHA256 plaintext
hash. Prefer the environment path so the old master key is not written to disk:

```bash
# Recommended (env path, no disk persistence):
export DATABASE_URL="${DATABASE_URL:?set DATABASE_URL}"
ENCRYPTION_KEY="$OLD_KEY" ./docker/scripts/verify-encryption.sh > before-rotation-hash.txt
# $OLD_KEY shell variable lives only in this shell session.
```

If a shell variable is impractical, use a managed temporary file only for the
duration of the command:

```bash
# Alternative (file path, if shell variable is impractical):
# CAREFUL: writes the old master key to disk. Use the lifecycle pattern below.
old_key_file="$(mktemp)"
chmod 600 "$old_key_file"
trap 'shred -u "$old_key_file" 2>/dev/null || rm -f "$old_key_file"' EXIT
echo "$OLD_KEY" > "$old_key_file"
export DATABASE_URL="${DATABASE_URL:?set DATABASE_URL}"
./docker/scripts/verify-encryption.sh --key-file "$old_key_file" > before-rotation-hash.txt
```

The saved file must contain the `ok ... sha256=<hex>` line only; it must not
contain the old key or plaintext. This is the only point in the rotation where
the DB still contains ciphertext decryptable by `OLD_KEY`. After Step 5 updates
the DB, `OLD_KEY` is expected to fail against the rewritten rows, so do not use
an old-key rerun as the post-rotation comparison. The temporary-file lifecycle
is still manual. Prefer the `migrate-encryption --dry-run` report whenever the
automation binary is available.

### Manual Step 3 — Swap the key in `.env`, Docker Secrets, or KMS

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
# Replace the ENCRYPTION_KEY line in .env with the prepared NEW_KEY.
# Precondition: read_env_var ENCRYPTION_KEY already passed (single match, non-empty).
write_env_var ENCRYPTION_KEY "$NEW_KEY"
chmod 600 .env
```

If `docker/scripts/_env_helpers.sh` is unavailable in a copied runbook, paste
this inline fallback before the `OLD_KEY=...` and `write_env_var ...` lines:

```bash
read_env_var() {
  key="$1"
  count="$(grep -c "^${key}=" .env || true)"
  if [ "$count" -eq 0 ]; then
    echo "[FATAL] ${key} is missing in .env" >&2
    exit 1
  fi
  if [ "$count" -gt 1 ]; then
    echo "[FATAL] ${key} is duplicated in .env (${count} occurrences); resolve manually" >&2
    exit 1
  fi
  raw="$(grep "^${key}=" .env | cut -d= -f2-)"
  raw="${raw#\"}"
  raw="${raw%\"}"
  raw="${raw#\'}"
  raw="${raw%\'}"
  if [ -z "$raw" ]; then
    echo "[FATAL] ${key} is empty (or only whitespace/quotes) in .env" >&2
    exit 1
  fi
  printf '%s' "$raw"
}

write_env_var() {
  key="$1"
  value="$2"
  tmp="$(mktemp)"
  WRITE_ENV_VALUE="$value" awk -v key="${key}=" '
    BEGIN { val = ENVIRON["WRITE_ENV_VALUE"] }
    $0 ~ "^" key { print key val; next }
    { print }
  ' .env > "$tmp"
  count="$(grep -c "^${key}=" "$tmp" || true)"
  if [ "$count" -ne 1 ]; then
    rm -f "$tmp"
    echo "[FATAL] write_env_var: ${key} count after update is ${count}, expected 1" >&2
    exit 1
  fi
  mv "$tmp" .env
}
```

For enterprise Docker Secrets, replace `docker/secrets/encryption_key.txt` with
`NEW_KEY` and keep permissions at `0600`. For a KMS-backed deployment, update
the KMS secret version or alias used by the API before the restart. Keep the
maintenance window closed to user traffic until Step 6 passes.

### Manual Step 4 — Restart the server with the new key

```bash
docker compose up -d api
docker compose logs -f api | head -50
```

`apps/api/cmd/server/main.go` runs `validateEncryptionKey` at startup; if the
new key is a known placeholder or shorter than 32 bytes the server refuses to
boot. A clean startup is the first confirmation that `.env` was edited
correctly.

### Manual Step 5 — Re-encrypt all rows with the new key

With the API booted under `NEW_KEY`, update the encrypted columns from the
in-memory plaintext captured in Steps 1-2:

```text
for each tenant:
    BEGIN
    SET LOCAL app.current_tenant_id = tenant.id

    for each cached tenant_llm_config plaintext:
        new_cipher := llm.Encrypt(plaintext, new_key)   # fresh random nonce
        UPDATE tenant_llm_config
           SET encrypted_api_key = new_cipher,
               updated_at = NOW()
         WHERE tenant_id = tenant.id

    for each cached issue_tracker_connections plaintext:
        new_cipher := issueTrackerEncrypt(plaintext, new_key)
        UPDATE issue_tracker_connections
           SET auth_token_encrypted = base64_encode(new_cipher),
               updated_at = NOW()
         WHERE id = row.id

    COMMIT
```

### Manual Step 6 — Verify with `migrate-encryption --verify` or `verify-encryption.sh`

> **Sample-only verification limitation for the legacy smoke test (M5 #53 F92)**
>
> `verify-encryption.sh` (via `decrypt-test`) samples **a single row with
> `LIMIT 1` and no `ORDER BY`**. In a multi-tenant DB or multi-row table, Step
> 2.5 and Step 6 may sample different rows, so a digest match proves only that
> one row decrypts consistently across keys, **not** that every encrypted row is
> recoverable.
>
> Recommended posture for production rotation:
>
> 1. Prefer `migrate-encryption --verify --report-input <dry-run-report>`.
> 2. Rehearse rotation in staging with all production tenants imported.
> 3. If forced onto the legacy smoke test, treat it as a sample-only signal.
> 4. Post-rotation, monitor application logs for `decrypt failed` errors for
>    24-48h before destroying the old key.

Run the verification checks in §4, including `verify-encryption.sh` with
`NEW_KEY` after Step 5 has rewritten the DB:

```bash
export DATABASE_URL="${DATABASE_URL:?set DATABASE_URL}"
./docker/scripts/verify-encryption.sh \
    --key-file docker/secrets/encryption_key.txt \
    | tee after-rotation-hash.txt
```

Compare the SHA256 plaintext hash in `after-rotation-hash.txt` with the
old-key hash recorded in Step 2.5:

```bash
diff -u \
    <(sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p' before-rotation-hash.txt) \
    <(sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p' after-rotation-hash.txt)
```

The hashes must match for the same logical secret. The plaintext itself must
never be printed. Do not run the post-rotation check with `OLD_KEY`; after
Step 5, the DB ciphertext is expected to be decryptable only by `NEW_KEY`.
Because this smoke test is sample-only, treat a hash match as a mitigation
signal rather than complete row coverage. The automation `--verify` mode is the
complete per-row check.

### Manual Step 7 — Destroy the old key after retention

Keep `OLD_KEY` only for the retention period approved for this maintenance
window. After §4 passes and the rollback window closes, delete the old `.env`
snapshot, Docker Secret version, KMS version, and any operator shell state that
still contains the old key.

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
   from the upstream, the re-encryption step (§3 step 5) skipped or corrupted
   that row — restore from the §2.2 snapshot and re-run.

4. **BYOK LLM providers** — for each tenant that configured a non-Ollama LLM
   provider with its own API key, run an AI VEX triage or CRA draft generation
   path. Provider resolution must decrypt `tenant_llm_config.encrypted_api_key`
   under the new key. Any provider-resolution decrypt error means that tenant's
   BYOK key was skipped or corrupted during §3.

5. **Application logs** — `docker compose logs api` must show no
   `failed to decrypt`, `cipher: message authentication failed`, or
   `ciphertext too short` errors. Any of those indicates a row was *not*
   re-encrypted and is now unrecoverable under the new key.

6. **`verify-encryption.sh` smoke test** — run the dedicated decrypt
   round-trip CLI (M5-5, issue
   [#53](https://github.com/youichi-uda/sbomhub/issues/53)) to confirm the
   new key actually decrypts the re-encrypted ciphertext at the DB layer:

   ```bash
   export DATABASE_URL="${DATABASE_URL:?set DATABASE_URL}"
   ENCRYPTION_KEY="$(cat docker/secrets/encryption_key.txt)" \
   ./docker/scripts/verify-encryption.sh
   ```

   Equivalent file-based invocation:

   ```bash
   export DATABASE_URL="${DATABASE_URL:?set DATABASE_URL}"
   ./docker/scripts/verify-encryption.sh \
       --key-file docker/secrets/encryption_key.txt
   ```

   On success the script prints `ok ... sha256=<hex>`; on failure it exits
   non-zero with a classification:

   | exit | meaning |
   |---|---|
   | 0  | new key decrypts a sample row (rotation OK so far) |
   | 1  | key mismatch / ciphertext tampered — investigate before reopening traffic |
   | 2  | DB error (DSN, role permissions) |
   | 3  | no encrypted row to test (no BYOK / no integration configured yet) |
   | 64 | usage error (invalid flag or argument) |
   | 65 | prerequisite missing (Go toolchain / `DECRYPT_TEST_BIN`) |

   To verify the round-trip across **the same secret** under both old and
   new keys (recommended sanity check), use the old-key digest recorded in
   §3 Step 2.5 and compare it with the new-key digest from this post-rotation
   check; the SHA256 hashes printed must match. The plaintext itself is never
   emitted. The legacy `--key` argv path is still accepted for compatibility
   but is deprecated because command-line arguments are easier to expose via
   `ps` / procfs.

   The default smoke target is
   `tenant_llm_config.encrypted_api_key`. To spot-check issue tracker tokens,
   pass `--table issue_tracker_connections --column auth_token_encrypted`.

   See [`security/self-host-deployment.md`](./security/self-host-deployment.md) §4.5
   for the full operator contract.

---

## 5. Rollback

Use this path only if §3 step 5 (re-encryption) failed mid-run or §4 detected
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

If you reach §3 step 1 with no working "old" key — e.g. recovering from an
incident where the previous `.env` was destroyed — you cannot decrypt the
existing ciphertext. The pragmatic recovery is:

1. Set a fresh `ENCRYPTION_KEY` via §3 step 3.
2. Clear affected encrypted credentials:
   `UPDATE tenant_llm_config SET encrypted_api_key = NULL` for affected
   tenants, and `TRUNCATE issue_tracker_connections;` (or `DELETE`
   per-tenant if you can identify which tenants you actually want to wipe).
3. Notify affected tenants that their BYOK LLM API key and Jira / Backlog
   connection must be re-entered through the settings and integrations pages.
   They will paste their secrets again; the new key will encrypt them.

This costs the BYOK LLM keys and integration tokens but preserves every other
tenant artefact
(SBOMs, vulnerabilities, VEX, audit log, etc.) because none of those use
`ENCRYPTION_KEY`.

---

## 7. Schedule recommendation

| Trigger | Cadence | Notes |
| --- | --- | --- |
| Routine rotation | Every 90 days | Calendar reminder is sufficient. Rehearse on a staging environment first if you have one. |
| Incident (key leak) | Immediately | Treat all BYOK LLM API keys and `issue_tracker_connections` tokens as exposed; rotating the master key does not invalidate already-exfiltrated plaintext. After rotation, advise affected tenants to also rotate their upstream LLM provider and Jira / Backlog tokens. |
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

## Automation implementation

M6 issue [#56](https://github.com/youichi-uda/sbomhub/issues/56) implements the
turnkey rotation binary at
[`apps/api/cmd/migrate-encryption`](../apps/api/cmd/migrate-encryption).
Implementation commit: `50be30f` (`feat(api): migrate-encryption rotation CLI
(M6 #56)`).

The binary uses env-only `OLD_ENCRYPTION_KEY` / `NEW_ENCRYPTION_KEY`, imports
the production LLM and issue-tracker encryption helpers, loops per tenant with
`app.current_tenant_id`, emits JSON digest reports, and supports `--dry-run`,
`--apply`, `--verify`, `--resume-from`, `--batch-size`, and
`--continue-on-error`. Treat §3 as the source of truth for the operator flow.
