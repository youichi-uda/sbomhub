# SBOMHub MCP Server

[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for SBOMHub.

Claude Desktop や Cursor から自然言語で SBOMHub の脆弱性情報 / VEX / CRA 報告書ドラフトにアクセスできます (読み取り専用)。

> SBOMHub は CRA (EU Cyber Resilience Act 2026/9) 対応の **AI コンプラ成果物レイヤー** です。SaaS 版 (`sbomhub.app`) は 2026-06 にサンセットされ、現在は self-host (Docker Compose) のみがサポート対象です。MCP Server はローカルの SBOMHub インスタンス (`http://localhost:8080` がデフォルト) を参照します。

## 機能

| ツール | 説明 | 使用例 |
|--------|------|--------|
| `sbomhub_list_projects` | 資格情報が参照できるプロジェクト一覧 (テナント単位キー: 全件 / プロジェクトスコープキー: そのプロジェクト1件のみ) | 「プロジェクト一覧見せて」 |
| `sbomhub_get_dashboard` | テナント全体のダッシュボードサマリー (テナント単位キー必須。プロジェクトスコープキーは403で拒否) | 「全体の脆弱性サマリー教えて」 |
| `sbomhub_get_project_dashboard` | プロジェクト別ダッシュボード (脆弱性/コンプライアンス/SBOM)。脆弱性は最大5,000件まで走査、超過時は `vulnerabilities.scan_truncated=true` で `by_severity` / `top_by_cvss` は走査範囲の値 | 「my-app の状況をまとめて」 |
| `sbomhub_list_sboms` | プロジェクトのSBOM一覧 (新しい順) | 「my-app のSBOM履歴を見せて」 |
| `sbomhub_search_cve` | CVE横断検索 (テナント単位キー必須。プロジェクトスコープキーは403で拒否) | 「CVE-2021-44228の影響範囲は？」 |
| `sbomhub_search_component` | コンポーネント横断検索 (テナント単位キー必須。プロジェクトスコープキーは403で拒否) | 「log4jを使ってるプロジェクトは？」 |
| `sbomhub_diff` | SBOM差分比較 (テナント単位キー必須。プロジェクトスコープキーは自分のSBOM同士でも403で拒否) | 「前回と今回のSBOMの差分は？」 |
| `sbomhub_get_vulnerabilities` | 脆弱性一覧 (CVSS/EPSS順・最大500件、`severity` で絞り込み) | 「Criticalの脆弱性だけ見せて」 |
| `sbomhub_get_compliance` | コンプライアンス | 「経産省ガイドライン準拠度は？」 |

> **APIキーの種類で使えるツールが変わります。** プロジェクト詳細ページの「API Keys」タブ (`POST /api/v1/projects/:id/apikeys`) で作成したキーは **プロジェクトスコープ** で、上表で「テナント単位キー必須」と書いた 4 つのツールは 403 で拒否されます (集計や横断検索を黙って1プロジェクトに絞ると、返ってきた値の意味が変わってしまうため、サーバーは狭い答えを返さず拒否します)。テナント全体を見るには設定画面のテナントAPIキー (`POST /api/v1/apikeys`) を使ってください。`sbomhub_get_project_dashboard` などプロジェクト単位のツールは、キー自身のプロジェクトなら動作し、他プロジェクトのIDを渡すと 403 になります。

> `sbomhub_get_vulnerabilities` の severity 絞り込みはサーバー側 API には無いためクライアント側で適用されます。内部では 500 件/ページで最大 5,000 件まで走査し (CVSS/EPSS 降順)、レスポンスに含める件数は最大 500 件です。`total_in_project` / `scanned` / `scan_truncated` / `matched` / `returned` で全体件数・走査範囲・打ち切りの有無が分かります。

## セットアップ

### 1. APIキーの取得

**プロジェクト単位のキー** (そのプロジェクトだけを見せたい場合):

1. self-host した SBOMHub (例: `http://localhost:8080`) にログイン
2. プロジェクト詳細ページを開く
3. 「API Keys」タブをクリック
4. 「Create API Key」で新規作成
5. 表示されたキー (`sbh_...`) をコピー

**テナント単位のキー** (テナント全体のサマリー / 横断検索を使う場合): 設定 → 「API Keys」から作成します。上の「機能」表で「テナント単位キー必須」としたツールはこちらでないと 403 になります。

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
        "SBOMHUB_API_URL": "http://localhost:8080",
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
        "SBOMHUB_API_URL": "http://localhost:8080",
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
3. SBOMHub の URL が正しいか確認 (self-host 既定は `http://localhost:8080`)

## 開発

```bash
# 開発ビルド
pnpm build

# 手動実行 (テスト用)
SBOMHUB_API_KEY=sbh_xxx SBOMHUB_API_URL=http://localhost:8080 node dist/index.js
```

## ライセンス

AGPL-3.0
