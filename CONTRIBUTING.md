# Contributing to SBOMHub

Thank you for your interest in contributing to SBOMHub!

[日本語版はこちら](#コントリビューションガイド日本語)

## Development Setup

### Prerequisites

- Go 1.22+
- Node.js 20+
- pnpm 9+
- Docker & Docker Compose
- PostgreSQL 15+ (or use Docker)
- Redis 7+ (or use Docker)

### Getting Started

1. Fork and clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/sbomhub.git
cd sbomhub
```

2. Start the development environment

```bash
# Start database services
docker compose -f docker/docker-compose.yml up -d postgres redis

# Backend
cd apps/api
go mod download
go run ./cmd/server

# Frontend (new terminal)
cd apps/web
pnpm install
pnpm dev
```

3. Access the application at http://localhost:3000

## Project Structure

```
sbomhub/
├── apps/
│   ├── api/                 # Go backend (Echo framework)
│   │   ├── cmd/server/      # Entry point
│   │   └── internal/        # Internal packages
│   │       ├── handler/     # HTTP handlers
│   │       ├── service/     # Business logic
│   │       ├── repository/  # Data access
│   │       └── model/       # Data models
│   └── web/                 # Next.js frontend
│       └── src/
│           ├── app/         # App Router pages
│           ├── components/  # React components
│           └── lib/         # Utilities
├── packages/
│   └── types/               # Shared TypeScript types
└── docker/                  # Docker configuration
```

## Pull Request Process

1. Create a feature branch from `main`

```bash
git checkout -b feature/your-feature-name
```

2. Make your changes

3. Run tests

```bash
# Backend tests
cd apps/api && go test ./...

# Frontend tests
cd apps/web && pnpm test
```

4. Run linters

```bash
# Backend
cd apps/api && golangci-lint run

# Frontend
cd apps/web && pnpm lint
```

5. Commit your changes (see commit message guidelines below)

6. Push and create a Pull Request

```bash
git push origin feature/your-feature-name
```

## Commit Message Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Code style (formatting, etc.) |
| `refactor` | Code refactoring |
| `test` | Adding/updating tests |
| `chore` | Maintenance tasks |

Examples:
```
feat: add EPSS score display to vulnerability list
fix: resolve NVD API rate limiting issue
docs: update installation guide for Docker
```

## Code Style

### Go (Backend)

- Follow `gofmt` formatting
- Use `golangci-lint` for linting
- Error handling: wrap errors with context using `fmt.Errorf`
- Logging: use `slog` for structured logging

### TypeScript (Frontend)

- Follow the ESLint + Prettier configuration
- Use TypeScript strict mode
- Prefer Server Components; use Client Components only when necessary
- Use `next-intl` for internationalization

## Testing

### Backend

```bash
cd apps/api

# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/service/...
```

### Frontend

```bash
cd apps/web

# Run tests
pnpm test

# Run with coverage
pnpm test:coverage
```

## Database Migrations

When adding new migrations:

1. Create migration files in `apps/api/migrations/`
2. Name format: `NNN_description.up.sql` and `NNN_description.down.sql`
3. Test both up and down migrations

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Search existing issues before creating a new one
- Provide clear reproduction steps for bugs
- Include relevant logs and screenshots

## Questions?

- Open a [GitHub Discussion](https://github.com/sbomhub/sbomhub/discussions)
- Check existing issues and discussions first

---

# コントリビューションガイド（日本語）

SBOMHubへのコントリビューションに興味を持っていただきありがとうございます！

## 開発環境のセットアップ

### 必要条件

- Go 1.22+
- Node.js 20+
- pnpm 9+
- Docker & Docker Compose
- PostgreSQL 15+（またはDocker使用）
- Redis 7+（またはDocker使用）

### はじめに

1. リポジトリをフォークしてクローン

```bash
git clone https://github.com/YOUR_USERNAME/sbomhub.git
cd sbomhub
```

2. 開発環境を起動

```bash
# データベースサービスを起動
docker compose -f docker/docker-compose.yml up -d postgres redis

# バックエンド
cd apps/api
go mod download
go run ./cmd/server

# フロントエンド（別ターミナル）
cd apps/web
pnpm install
pnpm dev
```

3. http://localhost:3000 でアプリケーションにアクセス

## プルリクエストの流れ

1. `main`ブランチからフィーチャーブランチを作成
2. 変更を加える
3. テストを実行
4. リンターを実行
5. コミット（Conventional Commits形式）
6. プルリクエストを作成

## コミットメッセージ

[Conventional Commits](https://www.conventionalcommits.org/ja/)形式を使用：

- `feat`: 新機能
- `fix`: バグ修正
- `docs`: ドキュメントのみの変更
- `refactor`: リファクタリング
- `test`: テストの追加・更新
- `chore`: メンテナンス

## 質問がある場合

- [GitHub Discussions](https://github.com/sbomhub/sbomhub/discussions)を利用
- 既存のIssueやDiscussionを先に確認
