# GitHub Actions連携

このガイドでは、SBOMHubをGitHub Actionsと連携してSBOM生成とアップロードを自動化する方法を説明します。

## 概要

SBOMワークフローの自動化：

1. プッシュ/リリースごとにSBOMを生成
2. SBOMHubにアップロードして脆弱性を追跡
3. 新しい脆弱性の通知を受信

## 前提条件

1. SBOMHubインスタンス（セルフホストまたはSaaS）
2. SBOMHubでプロジェクトを作成済み
3. プロジェクト用のAPIキーを生成済み

## セットアップ

### 1. APIキーの作成

1. SBOMHubでプロジェクトを開く
2. 設定 → APIキー に移動
3. 「APIキーを作成」をクリック
4. キーを安全に保存（一度しか表示されません）

### 2. GitHubシークレットの追加

GitHubリポジトリで：

1. Settings → Secrets and variables → Actions に移動
2. 以下のシークレットを追加：

| シークレット | 説明 |
|-------------|------|
| `SBOMHUB_API_KEY` | ステップ1で取得したAPIキー |
| `SBOMHUB_URL` | SBOMHubのURL（例: `https://sbomhub.app` または `http://your-server:8080`） |
| `SBOMHUB_PROJECT_ID` | プロジェクトのUUID |

## ワークフロー例

### 基本的なSBOMアップロード

```yaml
name: SBOM

on:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SyftでSBOM生成
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      - name: SBOMHubにアップロード
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### コンテナイメージスキャン付き

```yaml
name: Container SBOM

on:
  push:
    branches: [main]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Dockerイメージをビルド
        run: docker build -t myapp:${{ github.sha }} .

      - name: コンテナからSBOM生成
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft myapp:${{ github.sha }} -o cyclonedx-json > sbom.json

      - name: SBOMHubにアップロード
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### Trivyを使用

```yaml
name: Trivy SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: TrivyでSBOM生成
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'cyclonedx'
          output: 'sbom.json'

      - name: SBOMHubにアップロード
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### cdxgenを使用（多言語対応）

```yaml
name: cdxgen SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Node.jsをセットアップ
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: cdxgenでSBOM生成
        run: |
          npm install -g @cyclonedx/cdxgen
          cdxgen -o sbom.json

      - name: SBOMHubにアップロード
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom"
```

### 複数プロジェクトのマトリックスビルド

```yaml
name: Multi-project SBOM

on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - path: ./frontend
            project_id: ${{ secrets.SBOMHUB_FRONTEND_PROJECT_ID }}
          - path: ./backend
            project_id: ${{ secrets.SBOMHUB_BACKEND_PROJECT_ID }}

    steps:
      - uses: actions/checkout@v4

      - name: SBOM生成
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft ${{ matrix.path }} -o cyclonedx-json > sbom.json

      - name: SBOMHubにアップロード
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ matrix.project_id }}/sbom"
```

### 脆弱性チェックゲート付き

```yaml
name: SBOM with Gate

on:
  pull_request:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SBOM生成
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      - name: SBOMHubにアップロード
        id: upload
        run: |
          RESPONSE=$(curl -s -X POST \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            -F "sbom=@sbom.json" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/sbom")
          echo "response=$RESPONSE" >> $GITHUB_OUTPUT

      - name: 脆弱性チェック
        run: |
          CRITICAL=$(curl -s \
            -H "Authorization: Bearer ${{ secrets.SBOMHUB_API_KEY }}" \
            "${{ secrets.SBOMHUB_URL }}/api/v1/projects/${{ secrets.SBOMHUB_PROJECT_ID }}/vulnerabilities?severity=critical" \
            | jq '.total')
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::$CRITICAL 件の重大な脆弱性が見つかりました！"
            exit 1
          fi
```

## SBOM生成ツール

| ツール | 最適な用途 | コマンド |
|--------|----------|---------|
| Syft | 汎用、コンテナ | `syft . -o cyclonedx-json` |
| Trivy | コンテナ、セキュリティ重視 | `trivy fs --format cyclonedx .` |
| cdxgen | 多言語、モノレポ | `cdxgen -o sbom.json` |
| cyclonedx-gomod | Goプロジェクト | `cyclonedx-gomod mod -json` |
| cyclonedx-npm | Node.jsプロジェクト | `cyclonedx-npm --output-file sbom.json` |

## トラブルシューティング

### 認証エラー

APIキーを確認：

```bash
curl -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  "$SBOMHUB_URL/api/v1/projects"
```

### 無効なSBOMフォーマット

SBOMが有効なJSONか確認：

```bash
cat sbom.json | jq .
```

フォーマット（CycloneDXまたはSPDX）を確認：

```bash
cat sbom.json | jq '.bomFormat // .spdxVersion'
```

### 接続タイムアウト

セルフホストインスタンスの場合、以下を確認：
- サーバーがGitHub Actionsからアクセス可能
- ファイアウォールルールが受信接続を許可
- パブリックURLまたはGitHubセルフホストランナーを使用

## ベストプラクティス

1. **メインブランチで生成**: すべてのコミットではなく、リリース時にSBOMをアップロード
2. **シークレットを使用**: ワークフローにAPIキーをハードコードしない
3. **アクションバージョンを固定**: 再現性のために特定のバージョンを使用
4. **通知を監視**: 新しい脆弱性のSlack/Discordアラートを設定
5. **定期的にレビュー**: SBOMHubダッシュボードを週次で確認
