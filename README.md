# SBOMHub

[![日本語](https://img.shields.io/badge/lang-日本語-red.svg)](./README.md) [![English](https://img.shields.io/badge/lang-English-blue.svg)](./README_en.md)

![License](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)
![Next.js](https://img.shields.io/badge/Next.js-16-black)
![Docker Pulls](https://img.shields.io/docker/pulls/y1uda/sbomhub-api)
![GitHub Stars](https://img.shields.io/github/stars/youichi-uda/sbomhub)

<p align="center">
  <img src="docs/images/dashboard.png" alt="SBOMHub ダッシュボード" width="800">
</p>

## SBOMHubとは？

SBOMHubは、日本市場向けに設計されたオープンソースのSBOM（ソフトウェア部品表）管理ダッシュボードです。

- Syft、cdxgen、Trivyなどで生成したSBOMを**インポート**（CycloneDX/SPDX対応）
- NVD・JVNと連携して**脆弱性を追跡**
- EPSSスコアで**対応優先度を判断**
- VEXステートメントで**脆弱性トリアージを管理**
- **経産省ガイドライン**・EU CRAへの準拠を支援
- **ライセンスポリシー**でプロジェクト全体を管理
- Slack/Discord/Emailで**チームに通知**

## 機能一覧

| 機能 | 説明 |
|------|------|
| マルチフォーマットSBOM | CycloneDX・SPDX JSONに対応 |
| 脆弱性トラッキング | NVD + JVN連携で網羅的にカバー |
| EPSSスコアリング | 悪用可能性に基づく優先度付け |
| VEXサポート | 脆弱性の適用可否を記録 |
| ライセンスポリシー | 許可/拒否ライセンスの管理 |
| コンプライアンススコア | 経産省ガイドライン準拠度チェック |
| CI/CD連携 | GitHub Actions対応（APIキー認証） |
| 日本語UI | 完全日本語対応 |

## クイックスタート

### SaaS版（おすすめ）

インストール不要ですぐに試せます: **https://sbomhub.app**

- セットアップ不要
- 無料プランあり
- 自動アップデート付きマネージドインフラ

### Docker Compose（セルフホスト）

```bash
# ダウンロードして起動（クローン不要）
curl -fsSL https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker-compose.yml -o docker-compose.yml
docker compose up -d
```

または、クローンして起動：

```bash
git clone https://github.com/youichi-uda/sbomhub.git
cd sbomhub
docker compose up -d
```

http://localhost:3000 を開く

### ソースからビルド

**前提条件:**
- Go 1.22+
- Node.js 20+ / pnpm
- PostgreSQL 15+
- Redis 7+

```bash
# データベースを起動
docker compose -f docker/docker-compose.yml up -d postgres redis

# バックエンド
cd apps/api
go run ./cmd/server

# フロントエンド（別ターミナル）
cd apps/web
pnpm install
pnpm dev
```

## スクリーンショット

<details>
<summary>ダッシュボード</summary>
<img src="docs/images/dashboard.png" width="600">
</details>

<details>
<summary>脆弱性一覧</summary>
<img src="docs/images/vulnerabilities.png" width="600">
</details>

<details>
<summary>コンプライアンススコア</summary>
<img src="docs/images/compliance.png" width="600">
</details>

## アーキテクチャ

```
┌─────────────────┐     ┌─────────────────┐
│   Next.js Web   │────▶│    Go API       │
│   (Port 3000)   │     │   (Port 8080)   │
└─────────────────┘     └────────┬────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
             ┌───────────┐ ┌───────────┐ ┌───────────┐
             │ PostgreSQL│ │   Redis   │ │ NVD / JVN │
             │  (Data)   │ │  (Cache)  │ │  (APIs)   │
             └───────────┘ └───────────┘ └───────────┘
```

## APIリファレンス

詳細は[APIドキュメント](./docs/api.md)を参照

### 主要エンドポイント

```
POST   /api/v1/projects              # プロジェクト作成
GET    /api/v1/projects              # プロジェクト一覧
GET    /api/v1/projects/:id          # プロジェクト詳細
DELETE /api/v1/projects/:id          # プロジェクト削除

POST   /api/v1/projects/:id/sbom     # SBOMアップロード
GET    /api/v1/projects/:id/components
GET    /api/v1/projects/:id/vulnerabilities
GET    /api/v1/projects/:id/vex      # VEXステートメント
```

## CI/CD連携

### GitHub Actions

```yaml
name: Upload SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        run: syft . -o cyclonedx-json > sbom.json

      - name: Upload to SBOMHub
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            ${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.PROJECT_ID }}/sbom
```

## ドキュメント

- [インストールガイド](./docs/installation.ja.md)
- [設定](./docs/configuration.ja.md)
- [APIリファレンス](./docs/api.ja.md)
- [GitHub Actions連携](./docs/github-actions.ja.md)

## ロードマップ

- [x] SBOMインポート（CycloneDX/SPDX）
- [x] NVD/JVN脆弱性マッチング
- [x] EPSSスコアリング
- [x] VEXサポート
- [x] ライセンスポリシー
- [x] コンプライアンススコア（経産省ガイドライン）
- [x] CI/CD連携（GitHub Actions）
- [x] 通知機能（Slack/Discord）
- [x] マルチテナント対応（Row-Level Security）
- [x] Clerk認証連携
- [x] Lemon Squeezy課金連携
- [x] SBOMHub Cloud（マネージドSaaS）
- [ ] LDAP/OIDC認証（セルフホスト向け）

## コントリビューション

コントリビューションを歓迎します！詳細は[CONTRIBUTING.md](./CONTRIBUTING.md)をご覧ください。

## ライセンス

本プロジェクトは[AGPL-3.0ライセンス](./LICENSE)の下で公開されています。

## 技術スタック

| レイヤー | 技術 | バージョン |
|---------|------|-----------|
| バックエンド | Go (Echo v4) | 1.22+ |
| フロントエンド | Next.js (App Router) | 16 |
| UIフレームワーク | React | 19 |
| 言語 | TypeScript | 5.7 |
| UIコンポーネント | shadcn/ui | 最新 |
| スタイリング | Tailwind CSS | 3.4 |
| データベース | PostgreSQL | 15+ |
| キャッシュ | Redis | 7+ |
| 国際化 | next-intl | 最新 |
| フォームバリデーション | react-hook-form + zod | 最新 |

## 開発

### 必要環境

- Go 1.22+
- Node.js 20+ と pnpm
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose（オプション）

### プロジェクト構造

```
sbomhub/
├── apps/
│   ├── web/          # Next.js フロントエンド
│   └── api/          # Go バックエンド
├── packages/
│   ├── db/           # DBスキーマとマイグレーション
│   └── types/        # 共有TypeScript型定義
├── docker/           # Docker設定
├── docs/             # ドキュメント
└── .github/workflows/  # CI/CDパイプライン
```

### よく使うコマンド

```bash
# 開発サーバー起動
cd apps/web && pnpm dev      # フロントエンド (http://localhost:3000)
cd apps/api && go run ./cmd/server  # バックエンド (http://localhost:8080)

# データベース
docker compose up -d postgres redis  # DB起動
cd apps/api && go run ./cmd/migrate up  # マイグレーション実行

# テスト
cd apps/api && go test ./...   # バックエンドテスト
cd apps/web && pnpm test       # フロントエンドテスト

# Lint
cd apps/api && golangci-lint run   # Go lint
cd apps/web && pnpm lint           # TypeScript lint

# ビルド
docker compose build           # 全コンテナビルド
```

### コードスタイル

- **Go**: gofmt, golangci-lint
- **TypeScript**: ESLint, Prettier
- **コミット**: [Conventional Commits](https://www.conventionalcommits.org/ja/)

## Claude Code連携

本プロジェクトには、AI支援開発のための[Claude Code](https://claude.ai/code)スキルが導入されています。

### 導入済みスキル

| カテゴリ | ソース | 説明 |
|---------|--------|------|
| セキュリティ | [Trail of Bits](https://github.com/trailofbits/skills) | セキュリティ監査、脆弱性検出、静的解析 |
| Go開発 | [Gopher AI](https://github.com/gopherguides/gopher-ai) | Goベストプラクティス、テストパターン |
| React/Next.js | [Vercel Agent Skills](https://github.com/vercel-labs/agent-skills) | パフォーマンス最適化（57以上のルール） |
| ワークフロー | [Claude Code SDK](https://github.com/hgeldenhuys/claude-code-sdk) | CI/CD、テスト、コードレビューパターン |

### このプロジェクト向けの主要スキル

- **differential-review** - セキュリティ重視のPRレビュー
- **go-best-practices** - 慣用的なGoパターン
- **react-best-practices** - React/Next.js最適化
- **ci-cd-integration** - パイプライン自動化
- **monorepo-patterns** - モノレポワークフロー

スキルは `.claude/skills/` に配置され、Claude Codeによって自動検出されます。

## セキュリティ

### 脆弱性の報告

セキュリティ脆弱性を発見した場合は、以下の方法で報告してください：

1. **GitHub Security Advisories**: [脆弱性を報告](https://github.com/youichi-uda/sbomhub/security/advisories/new)
2. **メール**: security@sbomhub.app（機密性の高い問題の場合）

公開のGitHub Issueでセキュリティ脆弱性を報告しないでください。

### セキュリティ機能

- マルチテナント向けRow-Level Security (RLS)
- CI/CD連携用APIキー認証
- 本番環境でのHTTPS強制
- zodスキーマによる入力バリデーション
- パラメータ化クエリによるSQLインジェクション防止

## 謝辞

- [CycloneDX](https://cyclonedx.org/) - SBOM仕様
- [SPDX](https://spdx.dev/) - SBOM仕様
- [NVD](https://nvd.nist.gov/) - National Vulnerability Database
- [JVN](https://jvn.jp/) - Japan Vulnerability Notes
- [FIRST EPSS](https://www.first.org/epss/) - Exploit Prediction Scoring System
- [Trail of Bits](https://github.com/trailofbits/skills) - Claude Code向けセキュリティスキル
- [Vercel](https://github.com/vercel-labs/agent-skills) - Reactベストプラクティス
