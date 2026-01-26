# SBOMHub Deployment Guide

## ライセンス (AGPL-3.0)

SBOMHubはAGPL-3.0ライセンスです。

- **社内セルフホスト**: 自由に利用可能
- **第三者向けSaaS提供**: 全ソースコードの公開義務あり（商用ライセンスはお問い合わせ）
- **公式SBOMHub Cloud**: https://sbomhub.com で提供予定

## デプロイオプション

| 方式 | 推奨用途 | 難易度 |
|------|---------|--------|
| Docker Compose | ローカル開発、小規模運用 | ★☆☆ |
| Railway | SaaS運用、本番環境 | ★★☆ |
| Kubernetes | 大規模運用、オンプレミス | ★★★ |

---

## 1. Docker Compose（セルフホスト）

### クイックスタート

```bash
git clone https://github.com/youichi-uda/sbomhub.git
cd sbomhub
docker compose up -d
```

アクセス: http://localhost:3000

### カスタム設定

```yaml
# docker-compose.override.yml
services:
  api:
    environment:
      - NVD_API_KEY=your-nvd-api-key
  postgres:
    ports:
      - "5432:5432"  # ローカル接続用
```

---

## 2. Railway（SaaS推奨）

### 2.1 プロジェクト作成

1. https://railway.app でアカウント作成
2. New Project → Empty Project

### 2.2 サービス追加

#### PostgreSQL

1. Add Service → Database → PostgreSQL
2. Variables から `DATABASE_URL` をコピー

#### Redis

1. Add Service → Database → Redis
2. Variables から `REDIS_URL` をコピー

#### API Service

1. Add Service → GitHub Repo → sbomhub
2. Root Directory: `apps/api`
3. Build Command: `go build -o server ./cmd/server`
4. Start Command: `./server`

**Environment Variables:**
```
DATABASE_URL=<PostgreSQL URL>
REDIS_URL=<Redis URL>
PORT=8080
ENVIRONMENT=production
CLERK_SECRET_KEY=sk_live_xxxxx
CLERK_WEBHOOK_SECRET=whsec_xxxxx
LEMONSQUEEZY_API_KEY=xxxxx
LEMONSQUEEZY_WEBHOOK_SECRET=xxxxx
```

#### Web Service

1. Add Service → GitHub Repo → sbomhub
2. Root Directory: `apps/web`
3. Build Command: `npm install && npm run build`
4. Start Command: `npm start`

**Environment Variables:**
```
NEXT_PUBLIC_API_URL=https://api.sbomhub.com
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_xxxxx
CLERK_SECRET_KEY=sk_live_xxxxx
```

### 2.3 カスタムドメイン

Railway Dashboard → Service → Settings → Domains

1. Generate Domain（Railway提供ドメイン）
2. または Custom Domain で独自ドメイン設定

**DNS設定例:**
```
sbomhub.com      CNAME  web-xxx.up.railway.app
api.sbomhub.com  CNAME  api-xxx.up.railway.app
```

### 2.4 railway.toml

```toml
# apps/api/railway.toml
[build]
builder = "nixpacks"

[deploy]
healthcheckPath = "/api/v1/health"
healthcheckTimeout = 30
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
```

```toml
# apps/web/railway.toml
[build]
builder = "nixpacks"

[deploy]
healthcheckPath = "/"
healthcheckTimeout = 30
```

---

## 3. Kubernetes

### Helm Chart（準備中）

```bash
helm repo add sbomhub https://charts.sbomhub.com
helm install sbomhub sbomhub/sbomhub \
  --set api.clerkSecretKey=sk_live_xxxxx \
  --set web.clerkPublishableKey=pk_live_xxxxx
```

### マニフェスト例

```yaml
# api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sbomhub-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sbomhub-api
  template:
    metadata:
      labels:
        app: sbomhub-api
    spec:
      containers:
      - name: api
        image: y1uda/sbomhub-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sbomhub-secrets
              key: database-url
        - name: CLERK_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: sbomhub-secrets
              key: clerk-secret-key
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

---

## データベースマイグレーション

### 本番環境でのマイグレーション

```bash
# Railway CLI使用
railway run --service api go run ./cmd/migrate up

# または psql で直接実行
psql $DATABASE_URL -f migrations/007_multitenancy.up.sql
```

### ロールバック

```bash
go run ./cmd/migrate down 1  # 1つ戻す
```

---

## 監視・ログ

### Railway

- Logs: Dashboard → Service → Logs
- Metrics: Dashboard → Service → Metrics

### 推奨ツール

- **APM**: Sentry, Datadog
- **Logging**: Loki, Papertrail
- **Uptime**: Better Uptime, Pingdom

### ヘルスチェック

```bash
# API
curl https://api.sbomhub.com/api/v1/health
# {"mode":"saas","status":"ok"}

# Web
curl -I https://sbomhub.com
# HTTP/2 200
```

---

## バックアップ

### PostgreSQL

```bash
# Railway CLI
railway run pg_dump > backup.sql

# 復元
railway run psql < backup.sql
```

### 自動バックアップ

Railway PostgreSQLは自動的に日次バックアップを取得（Pro Plan以上）

---

## スケーリング

### 水平スケーリング

Railway Dashboard → Service → Settings → Replicas

推奨設定:
- API: 2-4 replicas
- Web: 2-4 replicas

### 垂直スケーリング

Railway Dashboard → Service → Settings → Resources

推奨設定:
- API: 512MB-1GB RAM
- Web: 256MB-512MB RAM
- PostgreSQL: 1GB+ RAM

---

## セキュリティチェックリスト

- [ ] HTTPS強制（Railway自動対応）
- [ ] 環境変数でシークレット管理
- [ ] Webhook署名検証有効
- [ ] PostgreSQL RLS有効
- [ ] 監査ログ有効
- [ ] 定期バックアップ設定
- [ ] アップデート通知設定
