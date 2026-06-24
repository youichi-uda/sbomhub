#!/bin/sh
# SBOMHub install.sh — self-host を始めるための .env bootstrapper.
#
# 何をするか:
#   - .env.example を雛形に .env を生成
#   - ENCRYPTION_KEY を `openssl rand -base64 32` で発行
#   - sbomhub_app / sbomhub_migrator の DB パスワードをランダム発行し、
#     DATABASE_URL / MIGRATE_DATABASE_URL にも反映
#   - 既存 .env は壊さない (再生成は --force、 元 .env は .env.bak.<date> に退避)
#
# 何をしないか:
#   - docker compose pull / up は実行しない (operator の判断に委ねる)
#   - 既に流れている DB のパスワード変更は出来ない (rotation は別作業)
#
# Trust Rescue P1 #6 / 9.2.2: ENCRYPTION_KEY の既定値削除と起動拒否が入り、
# OSS user が「docker compose up したら起動しない」 という壁に当たるようになった。
# このスクリプトはその壁を 1 行で越えるための公式導線。
#
# 使い方:
#   ./install.sh             # 既存 .env を保持
#   ./install.sh --force     # 既存 .env を退避して再生成
#   ./install.sh --help      # ヘルプ表示

set -eu

print_usage() {
    cat <<'EOF'
Usage: ./install.sh [--force] [--help]

Options:
  --force   既存の .env を .env.bak.YYYYMMDD[.N] に退避し、新規に生成する。
  --help    このメッセージを表示する。

このスクリプトは .env を生成し、 ENCRYPTION_KEY / MIGRATOR_PASSWORD /
APP_PASSWORD をランダム生成して書き込みます。 既存 .env がある場合は
デフォルトでは何もしません (--force で退避して再生成)。
EOF
}

FORCE=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -h|--help) print_usage; exit 0 ;;
        *)
            printf '[FAIL] 不明な引数: %s\n' "$arg" >&2
            print_usage >&2
            exit 1
            ;;
    esac
done

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
    if [ "$FORCE" -eq 1 ]; then
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

EOF
