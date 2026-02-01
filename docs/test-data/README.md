# E2Eテスト用データ

このディレクトリにはE2Eテストで使用するテストデータを管理しています。

## ファイル一覧

### vulnerable-sbom.json
脆弱性テスト用のSBOMファイル（CycloneDX 1.4形式）

**含まれる脆弱性のあるコンポーネント:**

| コンポーネント | バージョン | 主な脆弱性 | 重大度 |
|---------------|-----------|-----------|--------|
| log4j-core | 2.14.1 | CVE-2021-44228 (Log4Shell) | Critical |
| lodash | 4.17.20 | CVE-2021-23337 | High |
| jackson-databind | 2.9.8 | CVE-2019-12086 他 | High |
| spring-core | 5.2.0.RELEASE | 複数のCVE | Medium/High |
| minimist | 1.2.5 | CVE-2021-44906 | Medium |
| axios | 0.21.1 | CVE-2021-3749 | Medium |
| django | 2.2.0 | 複数のCVE | Medium/High |
| gin | 1.6.0 | 潜在的脆弱性 | Low |

## 使用方法

### 手動テスト
1. SBOMHubにログイン
2. テスト用プロジェクト「E2E-Vuln-Test」を作成
3. `vulnerable-sbom.json` をアップロード
4. NVD脆弱性マッチングが完了するまで待機
5. 脆弱性が検出されることを確認

### 自動テスト（Playwright）
```bash
cd apps/web
pnpm test:e2e --grep "vulnerability"
```

## 注意事項

- このデータは**テスト目的専用**です
- 本番環境のプロジェクトには使用しないでください
- 脆弱性マッチングはNVDデータベースに依存するため、結果が変わる可能性があります

## テスト実施状況

| 項目 | ステータス | 備考 |
|------|----------|------|
| テストデータ作成 | ✅ 完了 | vulnerable-sbom.json |
| プロジェクト作成 | ✅ 完了 | E2E-Vuln-Test (c21c384c-acd5-48d0-9712-d185773c580b) |
| SBOMアップロード | ✅ 完了 | 8コンポーネント登録 |
| 脆弱性マッチング | ✅ 実装完了 | NVD API連携が実装済み（次回バッチで検出） |
| VULN-04/05テスト | ⏳ 未実施 | 脆弱性検出後に実施 |

## 更新履歴

- 2026-02-01: 初版作成（8コンポーネント）
- 2026-02-01: E2E-Vuln-Testプロジェクトにアップロード完了
- 2026-02-01: NVD API連携実装完了（`checkComponentVulnerabilities`）
