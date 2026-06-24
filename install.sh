#!/bin/sh
# SBOMHub install.sh — self-host を始めるための .env bootstrapper.
#
# 何をするか:
#   - .env.example を雛形に .env を生成
#   - ENCRYPTION_KEY を `openssl rand -base64 32` で発行
#   - sbomhub_app / sbomhub_migrator の DB パスワードをランダム発行し、
#     DATABASE_URL / MIGRATE_DATABASE_URL にも反映
#   - 既存 .env は壊さない (再生成は --force、 元 .env は .env.bak.<date> に退避)
#   - --bootstrap-roles モードで、 既存 postgres ボリュームに対して
#     sbomhub_app / sbomhub_migrator ロールを冪等に作成 (M0 アップグレード用)
#
# 何をしないか:
#   - docker compose pull / up は実行しない (operator の判断に委ねる)
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
# 使い方:
#   ./install.sh                    # .env を生成 (既存があれば保持)
#   ./install.sh --force            # 既存 .env を退避して再生成
#   ./install.sh --bootstrap-roles  # 既存 postgres コンテナにロールを作成
#   ./install.sh --help             # ヘルプ表示

set -eu

print_usage() {
    cat <<'EOF'
Usage: ./install.sh [--force | --bootstrap-roles] [--help]

Modes (mutually exclusive):
  (default)            .env を生成する。既存 .env がある場合は何もしない (冪等)。
  --force              既存の .env を .env.bak.YYYYMMDD[.N] に退避し、新規に生成する。
  --bootstrap-roles    既存 postgres コンテナに sbomhub_app / sbomhub_migrator を
                       作成する (docs/UPGRADE.md §4.2)。.env から MIGRATOR_PASSWORD /
                       APP_PASSWORD を読み出し、docker compose exec で
                       /docker-entrypoint-initdb.d/10-roles.sh を冪等に実行する。
                       postgres コンテナが起動している必要がある。

Options:
  --help               このメッセージを表示する。

このスクリプトは .env を生成し、 ENCRYPTION_KEY / MIGRATOR_PASSWORD /
APP_PASSWORD をランダム生成して書き込みます。 既存 .env がある場合は
デフォルトでは何もしません (--force で退避して再生成)。
EOF
}

MODE=generate   # generate | force | bootstrap_roles
for arg in "$@"; do
    case "$arg" in
        --force)
            if [ "$MODE" != "generate" ]; then
                printf '[FAIL] --force と --bootstrap-roles は同時指定できません。\n' >&2
                exit 1
            fi
            MODE=force
            ;;
        --bootstrap-roles)
            if [ "$MODE" != "generate" ]; then
                printf '[FAIL] --force と --bootstrap-roles は同時指定できません。\n' >&2
                exit 1
            fi
            MODE=bootstrap_roles
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
# Mode: --bootstrap-roles
# ----------------------------------------------------------------------------
# Idempotently apply the role-creation SQL from apps/api/cmd/migrate/init.sh
# to an EXISTING postgres volume. Required for self-host users upgrading from
# any pre-M0 release — init.sh only runs on fresh volume initialisation, so
# their volumes never received the sbomhub_app / sbomhub_migrator roles, and
# api startup dies with `password authentication failed`.
#
# Idempotency: init.sh wraps CREATE ROLE in DO $$ ... EXCEPTION WHEN
# duplicate_object $$ blocks and ALTER ROLE on every run, so re-execution is
# safe even after the roles already exist.
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

    # .env から MIGRATOR_PASSWORD / APP_PASSWORD を取り出す (末尾の改行や
    # quote を保守的に剥がす)。POSIX sh では IFS=  を使わずに sed で抽出。
    MIGRATOR_PASSWORD=$(sed -n 's/^MIGRATOR_PASSWORD=\(.*\)$/\1/p' .env | sed 's/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/' | head -n 1)
    APP_PASSWORD=$(sed -n 's/^APP_PASSWORD=\(.*\)$/\1/p' .env | sed 's/^"\(.*\)"$/\1/; s/^'"'"'\(.*\)'"'"'$/\1/' | head -n 1)

    if [ -z "${MIGRATOR_PASSWORD:-}" ] || [ -z "${APP_PASSWORD:-}" ]; then
        printf '[FAIL] .env に MIGRATOR_PASSWORD または APP_PASSWORD が設定されていません。\n' >&2
        printf '       `./install.sh --force` で .env を再生成するか、\n' >&2
        printf '       手動で 2 行を追加してから再実行してください。\n' >&2
        exit 1
    fi

    # postgres コンテナが起動していることを確認 (docker compose ps で state を見る)。
    # `docker compose` v2 のサブコマンド形式に依存。
    if ! docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
        printf '[FAIL] postgres コンテナが起動していません。\n' >&2
        printf '       `docker compose up -d postgres` で起動してから再実行してください。\n' >&2
        exit 1
    fi

    printf '[INFO] postgres コンテナに sbomhub_app / sbomhub_migrator ロールを\n'
    printf '       投入します (init.sh を docker compose exec 経由で実行)。\n'

    # init.sh はコンテナ内で /docker-entrypoint-initdb.d/10-roles.sh としてマウント済み。
    # 中身は psql に対する DO $$ ... CREATE ROLE / ALTER ROLE / GRANT を含む冪等スクリプト。
    # POSTGRES_USER / POSTGRES_DB はコンテナ起動時の環境変数として既に設定されている。
    if ! docker compose exec -T \
        -e "MIGRATOR_PASSWORD=$MIGRATOR_PASSWORD" \
        -e "APP_PASSWORD=$APP_PASSWORD" \
        postgres sh /docker-entrypoint-initdb.d/10-roles.sh; then
        printf '[FAIL] ロール投入に失敗しました。 docker compose logs postgres を確認してください。\n' >&2
        exit 1
    fi

    printf '[OK] sbomhub_app / sbomhub_migrator を作成 / 更新しました。\n'
    printf '     続けて `docker compose up -d` で api / web を起動してください。\n'
    exit 0
fi

# ----------------------------------------------------------------------------
# Mode: (default) / --force — .env generation
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

cp .env.example .env

# ランダム生成。 base64 32B = 256bit (AES-256 要件)、 hex 16B = 128bit。
ENCRYPTION_KEY=$(openssl rand -base64 32)
MIGRATOR_PASSWORD=$(openssl rand -hex 16)
APP_PASSWORD=$(openssl rand -hex 16)

# sed -i の inplace は GNU と BSD で挙動が違う。
# 共通解として `-i.bak` を使い、 .bak を後で削除する形にする。
#
# sed の区切り文字は `|` を使用: base64 出力に `/` `+` `=` が含まれる可能性
# があるが `|` は base64 alphabet に無いので衝突しない。 `&` は RHS の
# back-reference 扱いだが base64 alphabet に無いので問題なし。
sed -i.bak \
    -e "s|^ENCRYPTION_KEY=.*$|ENCRYPTION_KEY=${ENCRYPTION_KEY}|" \
    -e "s|^MIGRATOR_PASSWORD=.*$|MIGRATOR_PASSWORD=${MIGRATOR_PASSWORD}|" \
    -e "s|^APP_PASSWORD=.*$|APP_PASSWORD=${APP_PASSWORD}|" \
    .env
rm -f .env.bak

# DATABASE_URL / MIGRATE_DATABASE_URL は .env.example で既定値 (dev パスワード)
# が埋め込まれているので、 上で生成したパスワードに置換する。
# `postgres://sbomhub_app:<old>@host:port/db` の <old> を <new> に差し替え。
# `[^@]*` で @ までを greedy にしないことで、 後続の host 部に影響しない。
sed -i.bak \
    -e "s|postgres://sbomhub_app:[^@]*@|postgres://sbomhub_app:${APP_PASSWORD}@|" \
    -e "s|postgres://sbomhub_migrator:[^@]*@|postgres://sbomhub_migrator:${MIGRATOR_PASSWORD}@|" \
    .env
rm -f .env.bak

# Secret なので世界書き込み禁止。 chmod は best-effort (Windows は no-op)。
chmod 600 .env 2>/dev/null || true

cat <<EOF
[OK] .env を生成しました。
     ENCRYPTION_KEY と DB パスワードはセキュアに保管してください
     (rotation 手順: docs/encryption-key-rotation.md)。

生成された値:
  ENCRYPTION_KEY     : (32 bytes base64, AES-256)
  MIGRATOR_PASSWORD  : (16 bytes hex)
  APP_PASSWORD       : (16 bytes hex)

次のステップ (任意、 自動実行はしません):
  docker compose pull     # 最新 image を取得
  docker compose up -d    # サービス起動
  open http://localhost:3000

既存 postgres ボリュームを持つアップグレードの場合は
docs/UPGRADE.md §4.2 (./install.sh --bootstrap-roles) を参照してください。
EOF
