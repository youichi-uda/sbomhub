#!/bin/sh
# SBOMHub install.sh — self-host bootstrap (.env + DB roles + optional stack up).
#
# 何をするか:
#   - .env.example を雛形に .env を生成
#   - ENCRYPTION_KEY を `openssl rand -base64 32` で発行
#   - sbomhub_app / sbomhub_migrator の DB パスワードをランダム発行し、
#     DATABASE_URL / MIGRATE_DATABASE_URL にも反映
#   - 既存 .env は壊さない (再生成は --force、 元 .env は .env.bak.<date> に退避)
#   - 既存 postgres ボリュームに対して sbomhub_app / sbomhub_migrator ロールを
#     冪等に作成する (--bootstrap-roles、 M0 アップグレード用 / fresh install
#     共通の経路)
#
# 何をしないか:
#   - docker compose pull は実行しない (image 更新は operator 判断)
#   - 既に流れている DB のパスワード変更は出来ない (rotation は別作業)
#
# Trust Rescue P1 #6 / 9.2.2: ENCRYPTION_KEY の既定値削除と起動拒否が入り、
# OSS user が「docker compose up したら起動しない」 という壁に当たるようになった。
# このスクリプトはその壁を 1 行で越えるための公式導線。
#
# Trust Rescue codex-r2 P1: 既存 postgres ボリュームを持つ self-host user は
# init.sh が走らない (新規ボリューム初期化時のみ) ので、 新ロールが DB に
# 存在せず api 起動が password authentication failed で死ぬ。
# --bootstrap-roles はその救済のための公式導線 (詳細: docs/UPGRADE.md)。
#
# Trust Rescue codex-r8 P1: docker-compose.yml に居た init.sh の bind mount は
# host file 依存 (curl-only install では host に存在しない) で stack 全体を
# 落とす罠だったため削除した。 fresh install / existing-volume upgrade を
# 問わず、 ロール作成はこの install.sh が docker compose exec 経由で行う
# (= bootstrap SQL の single source of truth)。
#
# 使い方:
#   ./install.sh                    # .env を生成 (既存があれば保持)
#   ./install.sh --force            # 既存 .env を退避して再生成
#   ./install.sh --bootstrap-roles  # 既存 postgres コンテナにロールを作成
#   ./install.sh --start            # .env 生成 + docker compose up + ロール投入
#                                   # まで一気通貫 (curl-only install 向け)
#   ./install.sh --help             # ヘルプ表示

set -eu

# docker-compose.yml の canonical URL (--start で host に未配置なら download)。
COMPOSE_URL="https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml"

# Operational scripts の canonical URL / 配置先 (--start の curl-only install path 用)。
SCRIPTS_BASE_URL="${SCRIPTS_BASE_URL:-https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker/scripts}"
SCRIPTS_TARGET_DIR="${SCRIPTS_TARGET_DIR:-docker/scripts}"

print_usage() {
    cat <<'EOF'
Usage: ./install.sh [--force | --bootstrap-roles | --start] [--help]

Modes (mutually exclusive):
  (default)            .env を生成する。既存 .env がある場合は何もしない (冪等)。
                       stack は起動しない。
  --force              既存の .env を .env.bak.YYYYMMDD[.N] に退避し、新規に生成する。
                       stack は起動しない。
  --bootstrap-roles    既存 postgres コンテナに sbomhub_app / sbomhub_migrator を
                       作成する (docs/UPGRADE.md §4.2)。.env から MIGRATOR_PASSWORD /
                       APP_PASSWORD を読み出し、docker compose exec で psql 経由に
                       冪等な SQL を流す。postgres コンテナが起動している必要がある。
  --start              curl-only install 向けのワンショット。
                       .env を生成 (なければ) → docker-compose.yml を download (なければ)
                       → docker compose up -d --wait postgres → ロール投入
                       → docker compose up -d で残りを起動、 までを一気に実行する。

Options:
  --help               このメッセージを表示する。

このスクリプトは .env を生成し、 ENCRYPTION_KEY / MIGRATOR_PASSWORD /
APP_PASSWORD をランダム生成して書き込みます。 既存 .env がある場合は
デフォルトでは何もしません (--force で退避して再生成)。
EOF
}

MODE=generate   # generate | force | bootstrap_roles | start
for arg in "$@"; do
    case "$arg" in
        --force)
            if [ "$MODE" != "generate" ]; then
                printf '[FAIL] --force / --bootstrap-roles / --start は同時指定できません。\n' >&2
                exit 1
            fi
            MODE=force
            ;;
        --bootstrap-roles)
            if [ "$MODE" != "generate" ]; then
                printf '[FAIL] --force / --bootstrap-roles / --start は同時指定できません。\n' >&2
                exit 1
            fi
            MODE=bootstrap_roles
            ;;
        --start)
            if [ "$MODE" != "generate" ]; then
                printf '[FAIL] --force / --bootstrap-roles / --start は同時指定できません。\n' >&2
                exit 1
            fi
            MODE=start
            ;;
        -h|--help) print_usage; exit 0 ;;
        *)
            printf '[FAIL] 不明な引数: %s\n' "$arg" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

# postgres コンテナに対して role bootstrap SQL を流す。
#   $1: MIGRATOR_PASSWORD (raw)
#   $2: APP_PASSWORD (raw)
# 前提: docker / docker compose 利用可能、 postgres サービスが running 状態。
#
# Password handling (codex-r8 P2 と同じ規律):
#   - 旧実装は heredoc で '${MIGRATOR_PASSWORD}' / '${APP_PASSWORD}' を
#     SQL string literal の中に shell interpolate していた。 single quote を
#     含む password で SQL injection / 構文エラーになる。
#   - 本実装は password を psql の -v migrator_password=... / -v app_password=...
#     経由で渡し、 SQL 側では :'var' (psql client-side literal quoting) と
#     format(... %L ...) (server-side literal quoting、 belt-and-suspenders)
#     を使う。 raw value は SQL string literal の中に直接出現しないので、
#     任意 byte を含む password でも安全 (codex-r8 で初期 R8-8b commit が
#     init.sh に同じ規律を入れた、 install.sh も同じ規律を継承)。
#   - psql の :'var' 置換は dollar-quoted ($$ ... $$) body の中では効かないので、
#     CREATE ROLE は SELECT ... \gexec パターン (top-level の SELECT で :'var'
#     を展開 → 生成された CREATE ROLE を実行) で書く。
#   - ALTER ROLE は top-level なので :'var' を直接書ける。
#
# Password 値の経路:
#   install.sh ($1, $2)
#     → host shell の環境変数 PSQL_MIGRATOR_PASSWORD / PSQL_APP_PASSWORD
#     → docker compose exec -e NAME (name-only) でコンテナ環境へ転送
#     → コンテナ内 sh -c 'psql -v ... -v ... -f -' の引数展開
#     → psql の -v 値 (内部的に :'var' で SQL literal にエスケープされる)
#     → SELECT format('CREATE ROLE ... PASSWORD %L', :'var') \gexec
apply_role_bootstrap() {
    # POSTGRES_USER / POSTGRES_DB はコンテナ起動時の env として既に定義。
    # psql は Unix socket 経由 (-h 省略) で trust 認証されるためパスワード不要。
    # ヒアドキュメントは quoted (`<<'SQL'`) にして install.sh 側の shell 展開
    # を完全に抑制 (= SQL の中に install.sh の変数値が紛れ込む経路を絶つ)。
    PSQL_MIGRATOR_PASSWORD=$1
    PSQL_APP_PASSWORD=$2
    export PSQL_MIGRATOR_PASSWORD PSQL_APP_PASSWORD

    docker compose exec -T \
        -e PSQL_MIGRATOR_PASSWORD \
        -e PSQL_APP_PASSWORD \
        postgres sh -c '
            psql -v ON_ERROR_STOP=1 \
                 -v migrator_password="$PSQL_MIGRATOR_PASSWORD" \
                 -v app_password="$PSQL_APP_PASSWORD" \
                 -U sbomhub -d sbomhub -X -q -f -
        ' <<'SQL'
-- Create migrator role (DDL / migrations). NOT BYPASSRLS.
--
-- psql variable interpolation (:'var') is NOT performed inside
-- dollar-quoted ($$ ... $$) bodies, so the older
--   DO $$ ... CREATE ROLE ... PASSWORD '${MIGRATOR_PASSWORD}' ... $$
-- pattern is replaced by SELECT ... \gexec, which substitutes :'var'
-- at the SELECT (outside any dollar-quote) and then executes the
-- resulting CREATE ROLE statement. format(... %L ...) ensures the
-- password is emitted as a properly quoted SQL literal.
SELECT format(
    'CREATE ROLE sbomhub_migrator WITH LOGIN PASSWORD %L CREATEDB CREATEROLE',
    :'migrator_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbomhub_migrator')
\gexec

-- Create app role (runtime). NOSUPERUSER NOBYPASSRLS so RLS is enforced.
-- M4 Codex review #F77: NOSUPERUSER is required in addition to NOBYPASSRLS
-- because PostgreSQL superusers ALWAYS bypass RLS regardless of the
-- BYPASSRLS attribute (see #F72 + apps/api/cmd/server/main.go
-- assertAppRoleNotBypassRLS / evaluateAppRoleRLS — production / staging
-- hard-fail on rolsuper || rolbypassrls). Must match the F76
-- docker/docker-compose.enterprise.yml `db-bootstrap` SQL byte-for-byte
-- so the manual install.sh recovery path converges on the same role
-- attributes as the auto compose path.
SELECT format(
    'CREATE ROLE sbomhub_app WITH LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS',
    :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbomhub_app')
\gexec

-- Idempotent password rotation + NOBYPASSRLS / NOSUPERUSER re-assertion.
-- M4 Codex review #F77: existing roles on legacy / hand-recovered volumes
-- may have drifted to SUPERUSER or BYPASSRLS (e.g. operator promoted the
-- role for ad-hoc debugging and forgot to demote it). Without the explicit
-- attribute clauses below, this advanced recovery path leaves the role in
-- whatever attribute state the volume already has, so the F72 startup
-- guard keeps refusing to start until the operator manually runs an
-- ALTER ROLE. Re-asserting NOSUPERUSER / NOBYPASSRLS here is idempotent
-- (no-op on a freshly created role) and brings the install.sh path into
-- byte-for-byte convergence with the F76 `db-bootstrap` SQL.
-- ALTER ROLE is a plain top-level statement (not inside a DO block), so
-- psql will substitute :'var' into a properly quoted SQL literal here.
ALTER ROLE sbomhub_migrator WITH PASSWORD :'migrator_password' NOBYPASSRLS;
ALTER ROLE sbomhub_app      WITH PASSWORD :'app_password'      NOSUPERUSER NOBYPASSRLS;

-- Connect / schema usage.
GRANT CONNECT ON DATABASE sbomhub TO sbomhub_migrator, sbomhub_app;
GRANT USAGE   ON SCHEMA   public  TO sbomhub_migrator, sbomhub_app;

-- Postgres 15+ revoked the implicit CREATE on the public schema for
-- non-owners (https://www.postgresql.org/docs/15/release-15.html), so
-- without this grant the very first migrator-driven statement
--   CREATE TABLE IF NOT EXISTS schema_migrations ...
-- fails with "permission denied for schema public" on a fresh
-- docker compose up. sbomhub_app intentionally does NOT receive CREATE;
-- DDL is exclusively the migrator's job (Trust Rescue R1 / codex-r1).
GRANT CREATE ON SCHEMA public TO sbomhub_migrator;

-- Pre-install required extensions as the bootstrap superuser
-- (= POSTGRES_USER = sbomhub, the role this psql session is logged in as).
--
-- codex-r13 P1: migration 001 starts with
--   CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- which requires database-level CREATE privilege. The application roles
-- created above (sbomhub_migrator / sbomhub_app) are intentionally not
-- superusers — sbomhub_migrator has CREATEDB / CREATEROLE / schema-level
-- CREATE but NOT database-level CREATE, so running migration 001 as the
-- migrator role on a fresh install fails with
--   permission denied to create extension "uuid-ossp"
-- and the whole `./install.sh --start` path (plus the docs-curl-smoke
-- workflow) dies before any application schema is created.
--
-- Installing the extension here, while still connected as the bootstrap
-- superuser, sidesteps that limitation. Migration 001's CREATE EXTENSION
-- IF NOT EXISTS becomes a no-op on every subsequent run (fresh installs
-- and existing-volume upgrades alike), so we keep extension provisioning
-- centralised in install.sh without changing the migration itself.
--
-- Only uuid-ossp is currently required (the sole CREATE EXTENSION in
-- apps/api/migrations/*). Add any future extensions here, not in the
-- migrations, so the same superuser-only privilege is satisfied.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Existing tables (no-op on a fresh DB; needed if re-run against a populated schema).
GRANT ALL ON ALL TABLES IN SCHEMA public TO sbomhub_migrator;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sbomhub_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sbomhub_migrator, sbomhub_app;

-- Future tables created by the migrator role inherit the right grants
-- for sbomhub_app, so we never have to remember to GRANT after each
-- new CREATE TABLE in a migration.
ALTER DEFAULT PRIVILEGES FOR ROLE sbomhub_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sbomhub_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sbomhub_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sbomhub_app;

-- Existing-volume upgrade fix (codex-r3 P1, refined codex-r12 P1):
-- On legacy self-host volumes every table / sequence was created by the
-- POSTGRES_USER role 'sbomhub' and is therefore owned by it. GRANT ALL
-- above is insufficient for owner-only operations (ALTER TABLE, DROP,
-- ALTER COLUMN ... SET NOT NULL etc.), so migrations 027 / 028 / 029
-- abort with "must be owner of table sboms" when run as sbomhub_migrator.
--
-- We deliberately do NOT use `REASSIGN OWNED BY sbomhub TO
-- sbomhub_migrator` here: on a fresh `docker compose up` with
-- POSTGRES_USER=sbomhub, that role also owns the database itself
-- (CREATE DATABASE side-effect) plus other system-tied objects, and
-- REASSIGN aborts with "cannot reassign ownership of objects owned by
-- role sbomhub because they are required by the database system",
-- which would break every fresh `./install.sh --start` install and the
-- docs-curl-smoke workflow that follows.
--
-- Instead, iterate over the application-owned objects in the `public`
-- schema only (tables, sequences, views, materialized views) and ALTER
-- each one's owner individually. Fresh installs see zero matches and
-- the DO block is a no-op; legacy upgrades transfer exactly the app
-- objects without touching pg_catalog or the database owner.
DO $$
DECLARE
    obj record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbomhub') THEN
        RETURN;
    END IF;

    -- Tables (including partitioned + foreign) currently owned by sbomhub.
    FOR obj IN
        SELECT schemaname, tablename
        FROM pg_tables
        WHERE schemaname = 'public' AND tableowner = 'sbomhub'
    LOOP
        EXECUTE format('ALTER TABLE %I.%I OWNER TO sbomhub_migrator',
            obj.schemaname, obj.tablename);
    END LOOP;

    -- Sequences (own row in pg_class, relkind = 'S').
    FOR obj IN
        SELECT n.nspname AS schemaname, c.relname AS objname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_roles r ON r.oid = c.relowner
        WHERE c.relkind = 'S'
          AND n.nspname = 'public'
          AND r.rolname = 'sbomhub'
    LOOP
        EXECUTE format('ALTER SEQUENCE %I.%I OWNER TO sbomhub_migrator',
            obj.schemaname, obj.objname);
    END LOOP;

    -- Views (relkind = 'v').
    FOR obj IN
        SELECT n.nspname AS schemaname, c.relname AS objname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_roles r ON r.oid = c.relowner
        WHERE c.relkind = 'v'
          AND n.nspname = 'public'
          AND r.rolname = 'sbomhub'
    LOOP
        EXECUTE format('ALTER VIEW %I.%I OWNER TO sbomhub_migrator',
            obj.schemaname, obj.objname);
    END LOOP;

    -- Materialized views (relkind = 'm').
    FOR obj IN
        SELECT n.nspname AS schemaname, c.relname AS objname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_roles r ON r.oid = c.relowner
        WHERE c.relkind = 'm'
          AND n.nspname = 'public'
          AND r.rolname = 'sbomhub'
    LOOP
        EXECUTE format('ALTER MATERIALIZED VIEW %I.%I OWNER TO sbomhub_migrator',
            obj.schemaname, obj.objname);
    END LOOP;
END
$$;
SQL
}

# .env から MIGRATOR_PASSWORD / APP_PASSWORD を抽出して RUN_MIGRATOR_PASSWORD /
# RUN_APP_PASSWORD にセット。 失敗時に exit 1 を呼ぶ side-effect あり。
load_passwords_from_env() {
    RUN_MIGRATOR_PASSWORD=$(sed -n 's/^MIGRATOR_PASSWORD=\(.*\)$/\1/p' .env | sed 's/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/' | head -n 1)
    RUN_APP_PASSWORD=$(sed -n 's/^APP_PASSWORD=\(.*\)$/\1/p' .env | sed 's/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/' | head -n 1)

    if [ -z "${RUN_MIGRATOR_PASSWORD:-}" ] || [ -z "${RUN_APP_PASSWORD:-}" ]; then
        printf '[FAIL] .env に MIGRATOR_PASSWORD または APP_PASSWORD が設定されていません。\n' >&2
        printf '       `./install.sh --force` で .env を再生成するか、\n' >&2
        printf '       手動で 2 行を追加してから再実行してください。\n' >&2
        exit 1
    fi
}

# .env を新規生成する (上書きしない側のチェックは呼び元の責任)。
# ENCRYPTION_KEY / MIGRATOR_PASSWORD / APP_PASSWORD をランダム発行して
# DATABASE_URL / MIGRATE_DATABASE_URL にも反映。 副作用: chmod 600 .env。
# 生成したパスワードを GENERATED_MIGRATOR_PASSWORD / GENERATED_APP_PASSWORD に export。
generate_env_file() {
    if ! command -v openssl >/dev/null 2>&1; then
        printf '[FAIL] openssl が見つかりません。インストールしてから再実行してください。\n' >&2
        exit 1
    fi
    if [ ! -f .env.example ]; then
        printf '[FAIL] .env.example がカレントディレクトリにありません。\n' >&2
        printf '       sbomhub リポジトリのルート、 または docker-compose.yml と .env.example\n' >&2
        printf '       を取得済みのディレクトリで実行してください。\n' >&2
        exit 1
    fi

    cp .env.example .env

    # ランダム生成。 base64 32B = 256bit (AES-256 要件)、 hex 16B = 128bit。
    GENERATED_ENCRYPTION_KEY=$(openssl rand -base64 32)
    GENERATED_MIGRATOR_PASSWORD=$(openssl rand -hex 16)
    GENERATED_APP_PASSWORD=$(openssl rand -hex 16)

    # DATABASE_URL / MIGRATE_DATABASE_URL は .env.example で既定値 (dev パスワード
    # + localhost host) が埋め込まれているので、 上で生成したパスワードに置換し
    # つつ host を compose 内部 DNS の `postgres` に書き換える。
    #
    # codex-r16: docker-compose の environment が `${DATABASE_URL:-...}` 形式に
    # なったため、 .env の DATABASE_URL がそのまま container 環境に伝播する
    # (旧構造では environment が env_file を上書きしていたので host=localhost
    # の .env でも container 内で postgres に強制差し替えされていた)。 ここで
    # host=postgres を書いておかないと compose 起動時に container が localhost
    # に接続しに行き必ず失敗する。 .env.example 自体は `go run` 用に localhost
    # のままにしてある。
    #
    # 生成 password は openssl rand -hex 16 で `[0-9a-f]{32}` なので URL-safe、
    # URL-encode 不要。 operator が production password で `@ : / # ?` 等の
    # URL 区切り文字を使う場合は .env を編集して URL-encoded 値で DATABASE_URL
    # を直接書き換えること (.env.example の DATABASE roles セクション参照)。
    # Secret 値を sed/awk の argv に載せない。環境変数で awk に渡し、
    # awk 側は ENVIRON から読む。
    ENCRYPTION_KEY_VALUE=$GENERATED_ENCRYPTION_KEY \
    MIGRATOR_PASSWORD_VALUE=$GENERATED_MIGRATOR_PASSWORD \
    APP_PASSWORD_VALUE=$GENERATED_APP_PASSWORD \
    awk '
        BEGIN {
            encryption_key = ENVIRON["ENCRYPTION_KEY_VALUE"]
            migrator_password = ENVIRON["MIGRATOR_PASSWORD_VALUE"]
            app_password = ENVIRON["APP_PASSWORD_VALUE"]
        }
        /^ENCRYPTION_KEY=/ {
            print "ENCRYPTION_KEY=" encryption_key
            next
        }
        /^MIGRATOR_PASSWORD=/ {
            print "MIGRATOR_PASSWORD=" migrator_password
            next
        }
        /^APP_PASSWORD=/ {
            print "APP_PASSWORD=" app_password
            next
        }
        {
            gsub("postgres://sbomhub_app:[^@]*@localhost:", "postgres://sbomhub_app:" app_password "@postgres:")
            gsub("postgres://sbomhub_migrator:[^@]*@localhost:", "postgres://sbomhub_migrator:" migrator_password "@postgres:")
            print
        }
    ' .env > .env.tmp
    mv .env.tmp .env

    # Secret なので世界書き込み禁止。 chmod は best-effort (Windows は no-op)。
    chmod 600 .env 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# Mode: --bootstrap-roles
# ----------------------------------------------------------------------------
# Idempotently apply the role-creation SQL to an EXISTING postgres volume.
# Required for self-host users upgrading from any pre-M0 release — fresh
# bootstrap previously relied on a host file bind mount that codex-r8
# removed, so all role creation (fresh OR existing volume) is now this path.
if [ "$MODE" = "bootstrap_roles" ]; then
    if [ ! -f .env ]; then
        printf '[FAIL] .env が見つかりません。\n' >&2
        printf '       先に `./install.sh` を実行して .env を生成してから\n' >&2
        printf '       `./install.sh --bootstrap-roles` を再実行してください。\n' >&2
        exit 1
    fi
    if ! command -v docker >/dev/null 2>&1; then
        printf '[FAIL] docker が見つかりません。\n' >&2
        exit 1
    fi

    load_passwords_from_env

    # postgres コンテナが起動していることを確認 (docker compose ps で state を見る)。
    if ! docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
        printf '[FAIL] postgres コンテナが起動していません。\n' >&2
        printf '       `docker compose up -d postgres` で起動してから再実行してください。\n' >&2
        exit 1
    fi

    printf '[INFO] postgres コンテナに sbomhub_app / sbomhub_migrator ロールを\n'
    printf '       投入します (psql を docker compose exec 経由で実行)。\n'

    if ! apply_role_bootstrap "$RUN_MIGRATOR_PASSWORD" "$RUN_APP_PASSWORD"; then
        printf '[FAIL] ロール投入に失敗しました。 docker compose logs postgres を確認してください。\n' >&2
        exit 1
    fi

    printf '[OK] sbomhub_app / sbomhub_migrator を作成 / 更新しました。\n'
    printf '     続けて `docker compose up -d` で api / web を起動してください。\n'
    exit 0
fi

# ----------------------------------------------------------------------------
# Mode: --start
# ----------------------------------------------------------------------------
# curl-only install 向けワンショット。 .env を生成 → docker-compose.yml /
# operational scripts を download (なければ) → docker compose up -d --wait postgres
# → ロール投入 → docker compose up -d 全体起動、 までを実行する。
if [ "$MODE" = "start" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        printf '[FAIL] docker が見つかりません。 --start は docker compose を必要とします。\n' >&2
        exit 1
    fi

    # docker-compose.yml が無ければ download (curl-only install path)。
    if [ ! -f docker-compose.yml ]; then
        if ! command -v curl >/dev/null 2>&1; then
            printf '[FAIL] docker-compose.yml が無く、 curl も見つかりません。\n' >&2
            printf '       手動で docker-compose.yml を配置してから再実行してください: %s\n' "$COMPOSE_URL" >&2
            exit 1
        fi
        printf '[INFO] docker-compose.yml が無いため download します (%s)。\n' "$COMPOSE_URL"
        if ! curl -fsSL "$COMPOSE_URL" -o docker-compose.yml; then
            printf '[FAIL] docker-compose.yml の download に失敗しました。\n' >&2
            exit 1
        fi
    fi

    # .env.example が無ければ download (curl-only install では未配置)。
    if [ ! -f .env.example ]; then
        if ! command -v curl >/dev/null 2>&1; then
            printf '[FAIL] .env.example が無く、 curl も見つかりません。\n' >&2
            exit 1
        fi
        printf '[INFO] .env.example が無いため download します。\n'
        if ! curl -fsSL "https://raw.githubusercontent.com/youichi-uda/sbomhub/main/.env.example" -o .env.example; then
            printf '[FAIL] .env.example の download に失敗しました。\n' >&2
            exit 1
        fi
    fi

    # operational scripts download (M6 #56 F120):
    mkdir -p "$SCRIPTS_TARGET_DIR"
    for script in backup.sh restore.sh verify-encryption.sh verify-encryption-cron.sh; do
        target="$SCRIPTS_TARGET_DIR/$script"
        if [ ! -f "$target" ]; then
            if ! command -v curl >/dev/null 2>&1; then
                printf '[FAIL] curl が必要です (operational scripts download)。\n' >&2
                exit 1
            fi
            printf '[INFO] %s を download します。\n' "$script"
            if ! curl -fsSL "$SCRIPTS_BASE_URL/$script" -o "$target"; then
                printf '[FAIL] %s の download に失敗しました。\n' "$script" >&2
                exit 1
            fi
            chmod +x "$target"
        fi
    done

    # .env を生成 (既存なら保持し、 そこから password を読む)。
    if [ ! -f .env ]; then
        printf '[INFO] .env を生成します。\n'
        generate_env_file
        START_MIGRATOR_PASSWORD="$GENERATED_MIGRATOR_PASSWORD"
        START_APP_PASSWORD="$GENERATED_APP_PASSWORD"
    else
        printf '[INFO] .env が既にあります。 既存の MIGRATOR_PASSWORD / APP_PASSWORD を使用します。\n'
        load_passwords_from_env
        START_MIGRATOR_PASSWORD="$RUN_MIGRATOR_PASSWORD"
        START_APP_PASSWORD="$RUN_APP_PASSWORD"
    fi

    # postgres を先に上げて healthy 待ち。 docker compose v2.1+ の --wait を使用。
    printf '[INFO] postgres を起動して healthy を待ちます (docker compose up -d --wait postgres)。\n'
    if ! docker compose up -d --wait postgres; then
        printf '[FAIL] postgres の起動に失敗しました。 docker compose logs postgres を確認してください。\n' >&2
        exit 1
    fi

    printf '[INFO] sbomhub_app / sbomhub_migrator ロールを投入します。\n'
    if ! apply_role_bootstrap "$START_MIGRATOR_PASSWORD" "$START_APP_PASSWORD"; then
        printf '[FAIL] ロール投入に失敗しました。 docker compose logs postgres を確認してください。\n' >&2
        exit 1
    fi

    # 全体起動。 api 起動時に migrations 027/028/029 が走る。
    printf '[INFO] 残りのサービスを起動します (docker compose up -d)。\n'
    if ! docker compose up -d; then
        printf '[FAIL] サービス起動に失敗しました。 docker compose logs を確認してください。\n' >&2
        exit 1
    fi

    cat <<'EOF'
[OK] セットアップが完了しました。
     ダッシュボード: http://localhost:3000
     API ヘルスチェック: curl -fsS http://localhost:8080/api/v1/health
EOF
    exit 0
fi

# ----------------------------------------------------------------------------
# Mode: (default) / --force — .env generation only (stack は起動しない)
# ----------------------------------------------------------------------------

# 必須前提: openssl がなければランダム生成できないので即死する。
if ! command -v openssl >/dev/null 2>&1; then
    printf '[FAIL] openssl が見つかりません。インストールしてから再実行してください。\n' >&2
    exit 1
fi

# .env.example が無いとそもそもどこで実行してるかおかしい。
if [ ! -f .env.example ]; then
    printf '[FAIL] .env.example がカレントディレクトリにありません。\n' >&2
    printf '       sbomhub リポジトリのルートで実行してください。\n' >&2
    exit 1
fi

# 既存 .env のハンドリング: デフォルトでは触らない (冪等)。
if [ -f .env ]; then
    if [ "$MODE" = "force" ]; then
        BACKUP=".env.bak.$(date +%Y%m%d)"
        # 同日に複数回 --force を撃たれても上書きしない: .1, .2, ... を付ける。
        N=0
        while [ -e "$BACKUP" ]; do
            N=$((N + 1))
            BACKUP=".env.bak.$(date +%Y%m%d).$N"
        done
        cp .env "$BACKUP"
        printf '[INFO] 既存 .env を %s にバックアップしました。\n' "$BACKUP"
    else
        printf '[INFO] .env が既にあります。既存設定を保持します。\n'
        printf '       再生成するには --force を指定してください\n'
        printf '       (元の .env は .env.bak.YYYYMMDD に退避されます)。\n'
        printf '       既存ボリュームへロールだけ流したい場合は --bootstrap-roles\n'
        printf '       を指定してください (docs/UPGRADE.md §4.2)。\n'
        exit 0
    fi
fi

generate_env_file

cat <<EOF
[OK] .env を生成しました。
     ENCRYPTION_KEY と DB パスワードはセキュアに保管してください
     (rotation 手順: docs/encryption-key-rotation.md)。

生成された値:
  ENCRYPTION_KEY     : (32 bytes base64, AES-256)
  MIGRATOR_PASSWORD  : (16 bytes hex)
  APP_PASSWORD       : (16 bytes hex)

次のステップ (自動実行はしません):
  # postgres を先に起動して healthy 待ち
  docker compose up -d --wait postgres
  # sbomhub_app / sbomhub_migrator ロールを投入 (fresh / existing 共通)
  ./install.sh --bootstrap-roles
  # 残りを起動
  docker compose up -d
  # ダッシュボード
  open http://localhost:3000

ワンショットで全部やる場合は \`./install.sh --start\` を使ってください。

既存 postgres ボリュームを持つアップグレードは
docs/UPGRADE.md §4.2 (./install.sh --bootstrap-roles) を参照してください。
EOF
