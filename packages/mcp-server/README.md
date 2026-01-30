# SBOMHub MCP Server

[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for SBOMHub.

Claude Desktop や Cursor から自然言語で SBOMHub の脆弱性情報にアクセスできます。

## 機能

| ツール | 説明 | 使用例 |
|--------|------|--------|
| `sbomhub_list_projects` | プロジェクト一覧 | 「プロジェクト一覧見せて」 |
| `sbomhub_get_dashboard` | ダッシュボード情報 | 「全体の脆弱性サマリー教えて」 |
| `sbomhub_search_cve` | CVE横断検索 | 「CVE-2021-44228の影響範囲は？」 |
| `sbomhub_search_component` | コンポーネント検索 | 「log4jを使ってるプロジェクトは？」 |
| `sbomhub_diff` | SBOM差分比較 | 「前回と今回のSBOMの差分は？」 |
| `sbomhub_get_vulnerabilities` | 脆弱性一覧 | 「Criticalの脆弱性だけ見せて」 |
| `sbomhub_get_compliance` | コンプライアンス | 「経産省ガイドライン準拠度は？」 |

## セットアップ

### 1. APIキーの取得

1. SBOMHub にログイン
2. プロジェクト詳細ページを開く
3. 「API Keys」タブをクリック
4. 「Create API Key」で新規作成
5. 表示されたキー (`sbh_...`) をコピー

> **注意**: APIキーは作成時のみ表示されます。必ずコピーして安全な場所に保存してください。

### 2. ビルド

```bash
cd packages/mcp-server
pnpm install
pnpm build
```

### 3. Claude Desktop に設定

設定ファイルの場所:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sbomhub": {
      "command": "node",
      "args": ["/path/to/sbomhub/packages/mcp-server/dist/index.js"],
      "env": {
        "SBOMHUB_API_URL": "https://your-sbomhub-instance.com",
        "SBOMHUB_API_KEY": "sbh_your_api_key_here"
      }
    }
  }
}
```

### 4. Cursor に設定

プロジェクトルートに `.cursor/mcp.json` を作成:

```json
{
  "mcpServers": {
    "sbomhub": {
      "command": "node",
      "args": ["/path/to/sbomhub/packages/mcp-server/dist/index.js"],
      "env": {
        "SBOMHUB_API_URL": "https://your-sbomhub-instance.com",
        "SBOMHUB_API_KEY": "sbh_your_api_key_here"
      }
    }
  }
}
```

### 5. 再起動

Claude Desktop / Cursor を再起動すると、SBOMHub ツールが利用可能になります。

## 使用例

Claude に話しかけるだけで SBOMHub の情報を取得できます:

```
「SBOMHubのプロジェクト一覧を見せて」

「CVE-2021-44228 (Log4Shell) が影響するプロジェクトを検索して」

「my-app プロジェクトの Critical 脆弱性を教えて」

「react を使っているプロジェクトはある？」

「先週と今週のSBOMの差分を見せて」

「プロジェクトのコンプライアンススコアを確認して」
```

## 環境変数

| 変数 | 必須 | 説明 |
|------|------|------|
| `SBOMHUB_API_URL` | No | SBOMHub API URL (デフォルト: `http://localhost:8080`) |
| `SBOMHUB_API_KEY` | Yes | APIキー (`sbh_` で始まる) |

## トラブルシューティング

### "SBOMHUB_API_KEY is required" エラー

環境変数 `SBOMHUB_API_KEY` が設定されていません。Claude Desktop / Cursor の設定ファイルを確認してください。

### ツールが表示されない

1. `pnpm build` が成功しているか確認
2. `dist/index.js` が存在するか確認
3. 設定ファイルのパスが正しいか確認
4. Claude Desktop / Cursor を再起動

### 認証エラー

1. APIキーが正しいか確認
2. APIキーの有効期限が切れていないか確認
3. SBOMHub の URL が正しいか確認

## 開発

```bash
# 開発ビルド
pnpm build

# 手動実行 (テスト用)
SBOMHUB_API_KEY=sbh_xxx SBOMHUB_API_URL=http://localhost:8080 node dist/index.js
```

## ライセンス

AGPL-3.0
