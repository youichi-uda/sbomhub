# インストールガイド

このガイドでは、SBOMHubをインストールして実行するさまざまな方法を説明します。

## Docker Composeでクイックスタート

最も簡単な方法：

```bash
# docker-compose.ymlをダウンロード
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml -o docker-compose.yml

# すべてのサービスを起動
docker compose up -d
```

ブラウザで http://localhost:3000 を開きます。

## Docker Compose（フルインストール）

### 前提条件

- Docker 20.10+
- Docker Compose v2

### 手順

1. リポジトリをクローン：

```bash
git clone https://github.com/youichi-uda/sbomhub.git
cd sbomhub
```

2. （任意）設定用の`.env`ファイルを作成：

```bash
cp .env.example .env
# .envを編集して設定をカスタマイズ
```

3. サービスを起動：

```bash
docker compose up -d
```

4. http://localhost:3000 でアプリケーションにアクセス

### Dockerサービス

| サービス | ポート | 説明 |
|----------|--------|------|
| web | 3000 | Next.js フロントエンド |
| api | 8080 | Go バックエンドAPI |
| postgres | 5432 | PostgreSQLデータベース |
| redis | 6379 | Redisキャッシュ |

## ソースからビルド

### 前提条件

- Go 1.22+
- Node.js 20+
- pnpm 8+
- PostgreSQL 15+
- Redis 7+

### データベースのセットアップ

1. PostgreSQLとRedisを起動（Dockerを使用）：

```bash
docker compose -f docker/docker-compose.yml up -d postgres redis
```

または、ネイティブにインストールして接続文字列を設定。

2. データベースを作成：

```sql
CREATE DATABASE sbomhub;
CREATE USER sbomhub WITH PASSWORD 'sbomhub';
GRANT ALL PRIVILEGES ON DATABASE sbomhub TO sbomhub;
```

### バックエンドのセットアップ

```bash
cd apps/api

# 依存関係をインストール
go mod download

# データベースマイグレーションを実行
go run ./cmd/migrate up

# サーバーを起動
go run ./cmd/server
```

APIは http://localhost:8080 で利用可能になります。

### フロントエンドのセットアップ

```bash
cd apps/web

# 依存関係をインストール
pnpm install

# 開発サーバーを起動
pnpm dev
```

Webインターフェースは http://localhost:3000 で利用可能になります。

## 本番環境へのデプロイ

### Dockerを使用

本番用イメージをビルド：

```bash
# イメージをビルド
docker compose build

# 本番設定で起動
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 手動デプロイ

#### バックエンド

```bash
cd apps/api

# バイナリをビルド
go build -o sbomhub-api ./cmd/server

# 本番設定で実行
export DATABASE_URL="postgres://user:pass@localhost:5432/sbomhub?sslmode=require"
export REDIS_URL="redis://localhost:6379"
export ENVIRONMENT="production"

./sbomhub-api
```

#### フロントエンド

```bash
cd apps/web

# 本番用バンドルをビルド
pnpm build

# 本番サーバーを起動
pnpm start
```

### リバースプロキシ（Nginx）

Nginx設定例：

```nginx
upstream sbomhub-web {
    server 127.0.0.1:3000;
}

upstream sbomhub-api {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name sbomhub.example.com;

    ssl_certificate /etc/ssl/certs/sbomhub.crt;
    ssl_certificate_key /etc/ssl/private/sbomhub.key;

    location / {
        proxy_pass http://sbomhub-web;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location /api/ {
        proxy_pass http://sbomhub-api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Kubernetes

Kubernetesでのデプロイ方法については[DEPLOYMENT.md](./DEPLOYMENT.md)を参照してください。

## アップデート

### Docker Compose

```bash
# 最新のイメージを取得
docker compose pull

# 新しいイメージで再起動
docker compose up -d

# 必要に応じてマイグレーションを実行
docker compose exec api /app/sbomhub-api migrate up
```

### ソースから

```bash
git pull origin main

# バックエンド
cd apps/api
go mod download
go run ./cmd/migrate up
# サーバーを再起動

# フロントエンド
cd apps/web
pnpm install
pnpm build
# サーバーを再起動
```

## トラブルシューティング

### データベース接続の問題

PostgreSQLが実行中か確認：

```bash
docker compose ps postgres
```

接続文字列を確認：

```bash
psql $DATABASE_URL -c "SELECT 1"
```

### ポートがすでに使用中

docker-compose.ymlまたは.envでポートを変更：

```yaml
services:
  web:
    ports:
      - "3001:3000"  # 3001に変更
```

### ログ

トラブルシューティング用にログを表示：

```bash
# すべてのサービス
docker compose logs -f

# 特定のサービス
docker compose logs -f api
```
