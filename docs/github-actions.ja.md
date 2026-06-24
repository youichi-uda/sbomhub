# GitHub Actions連携

このガイドでは、SBOMHub を GitHub Actions と連携して SBOM 生成と
CRA / VEX 用の証跡アップロードを自動化する方法を説明します。

> SaaS 版 (`sbomhub.app`) は 2026-06 にサンセットされました。本ガイドの
> `SBOMHUB_URL` は **self-host インスタンス** (Docker Compose) を指す前提です
> (例: 社内ネットワーク内の `https://sbomhub.internal.example.com` や
> GitHub self-hosted runner から到達可能な URL)。

> **YAML の正本は別ファイル。** ワークフローの正本スニペットは
> [`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md) に
> 集約しています。本ドキュメントはセットアップ・前提条件・トラブルシュー
> ティング・生成ツール早見表を扱い、`curl` アップロード部分は
> [`snippets/curl-upload.md`](./snippets/curl-upload.md) を単一ソースとして
> 参照しています。

## 概要

SBOM ワークフローの自動化:

1. プッシュ / リリースごとに SBOM を生成
2. self-host の SBOMHub にアップロードして脆弱性を追跡し、VEX / CRA 報告の証跡にする
3. 必要に応じて Critical 検出でビルドを止めるゲートを追加

## 前提条件

1. self-host の SBOMHub インスタンス
2. SBOMHub でプロジェクトを作成済み
3. プロジェクト用の API キーを生成済み (Settings → API Keys、表示は一度きり)

## セットアップ

### 1. APIキーの作成

1. SBOMHub でプロジェクトを開く
2. **設定 → APIキー** に移動
3. **「APIキーを作成」** をクリック
4. キーを安全に保存 (一度しか表示されません)

### 2. GitHubシークレットの追加

GitHub リポジトリで:

1. **Settings → Secrets and variables → Actions** に移動
2. 以下のシークレットを追加:

| シークレット          | 説明                                                                              |
|---------------------|-----------------------------------------------------------------------------------|
| `SBOMHUB_API_KEY`    | ステップ 1 で取得した API キー                                                    |
| `SBOMHUB_URL`        | self-host SBOMHub の URL (例: `https://sbomhub.internal.example.com`)             |
| `SBOMHUB_PROJECT_ID` | プロジェクトの UUID                                                               |

## ワークフロー

完全な YAML は
[`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md) を
参照してください。サポートする 2 形態:

- **推奨**: `sbomhub-cli` をインストールし、`sbomhub scan` を 1 行で叩く。
  CLI が正本契約でアップロードを行い、`--fail-on critical` で CI ゲートも
  ワンライナーで実現できます。
- **フォールバック**: ランナーに `sbomhub-cli` を入れられない場合、お好み
  の生成ツール (Syft / Trivy / cdxgen) と
  [`snippets/curl-upload.md`](./snippets/curl-upload.md) の正本 `curl` を
  組み合わせて使います。

両形態とも同一の正本契約を叩きます:

- `POST /api/v1/projects/:id/sbom`
- `Authorization: Bearer <SBOMHUB_API_KEY>`
- `Content-Type: application/json` で CycloneDX / SPDX JSON の raw body を送信
  (`--data-binary @sbom.json`)。 正本エンドポイントに multipart で送ると
  「不正な SBOM JSON」 として拒否されます (`-F sbom=@sbom.json` は **不可**)。

## SBOM 生成ツール早見表

| ツール             | 主な用途                  | 生成コマンド                                         |
|-------------------|------------------------|----------------------------------------------------|
| Syft              | 汎用・コンテナ           | `syft . -o cyclonedx-json > sbom.json`             |
| Trivy             | コンテナ・セキュリティ重視 | `trivy fs --format cyclonedx . > sbom.json`        |
| cdxgen            | 多言語・モノレポ          | `cdxgen -o sbom.json`                              |
| cyclonedx-gomod   | Go プロジェクト          | `cyclonedx-gomod mod -json > sbom.json`            |
| cyclonedx-npm     | Node.js プロジェクト     | `cyclonedx-npm --output-file sbom.json`            |

アップロードステップは
[`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md) で
1 箇所に集約され、生成ツールが変わっても変化しません。

## トラブルシューティング

### 認証エラー

API キーを確認:

```bash
curl -fsS -H "Authorization: Bearer $SBOMHUB_API_KEY" \
  "$SBOMHUB_URL/api/v1/projects"
```

### 無効な SBOM フォーマット

SBOM が有効な JSON か確認:

```bash
cat sbom.json | jq .
```

フォーマット (CycloneDX または SPDX) を確認:

```bash
cat sbom.json | jq '.bomFormat // .spdxVersion'
```

### 接続タイムアウト

self-host インスタンスの場合、以下を確認:

- サーバが GitHub Actions ランナーから到達可能
- ファイアウォールルールが受信接続を許可
- 社内ネットワーク内なら GitHub self-hosted runner を使用

### 「415 Unsupported Media Type」 や 「malformed SBOM JSON」

正本エンドポイントは CycloneDX / SPDX JSON の **raw body** を期待しています。
`-F sbom=@sbom.json` ではなく `--data-binary @sbom.json` を使ってください。
[`snippets/curl-upload.md`](./snippets/curl-upload.md) の正本コマンドはこの
落とし穴を踏まないように書かれています。

## ベストプラクティス

1. **メインブランチで生成**: すべてのコミットではなく、リリース時に SBOM を
   アップロードする
2. **シークレットを使用**: ワークフローに API キーをハードコードしない
3. **アクションバージョンを固定**: 再現性のため特定のバージョンを使用
4. **通知を監視**: 新しい脆弱性向けに Slack / Discord アラートを設定
5. **定期的にレビュー**: SBOMHub ダッシュボードを週次で確認
