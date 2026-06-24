# APIリファレンス

このドキュメントでは SBOMHub の REST API について説明します。

> SBOMHub は CRA (EU Cyber Resilience Act 2026/9) 対応の **AI コンプラ成果物レイヤー** です。
> SaaS 版 (`sbomhub.app` / `api.sbomhub.app`) は 2026-06 にサンセットされ、self-host (Docker Compose) のみがサポート対象です。本ドキュメントの URL は self-host 既定の `http://localhost:8080` を使用します。

## ベースURL

- self-host (推奨): `http://localhost:8080`
- リバースプロキシ経由の self-host: `https://sbomhub.example.com`

## 認証

### APIキー認証

CI/CD 連携には API キーを使用します：

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/v1/projects
```

APIキーはプロジェクト設定ページで作成できます。

## エンドポイント

### プロジェクト

#### プロジェクト作成

```
POST /api/v1/projects
```

**リクエストボディ:**
```json
{
  "name": "my-project",
  "description": "プロジェクトの説明"
}
```

**レスポンス:**
```json
{
  "id": "uuid",
  "name": "my-project",
  "description": "プロジェクトの説明",
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### プロジェクト一覧

```
GET /api/v1/projects
```

**クエリパラメータ:**
- `page` (int): ページ番号（デフォルト: 1）
- `limit` (int): 1ページあたりの件数（デフォルト: 20）

#### プロジェクト取得

```
GET /api/v1/projects/:id
```

#### プロジェクト削除

```
DELETE /api/v1/projects/:id
```

---

### SBOM

#### SBOMアップロード（正本）

```
POST /api/v1/projects/:id/sbom
```

SBOM アップロードの唯一の正本エンドポイントです（Trust Rescue 9.3.1 / #9）。
Web UI (Clerk セッション) と CLI / GitHub Actions (`Authorization: Bearer sbh_...`)
は両方ともこの経路を `MultiAuth` ミドルウェア経由で呼びます。

**リクエスト:**
- `Authorization: Bearer <CLERK_JWT|sbh_API_KEY>`
- Content-Type: `application/json`（CycloneDX または SPDX JSON の raw body をそのまま送ります。 フォーマットはサーバ側で自動検出します）

**例 (API key):**

`curl` の正本コマンド (スモークテストの後続ステップ・CI 例を含む) は
[`snippets/curl-upload.md`](./snippets/curl-upload.md) を参照してください。
GitHub Actions / GitLab CI 用は
[`snippets/github-actions.yml.md`](./snippets/github-actions.yml.md) /
[`snippets/gitlab-ci.yml.md`](./snippets/gitlab-ci.yml.md) にあります。
いずれも同一の正本契約を使っています。

- `POST /api/v1/projects/:id/sbom`
- `Authorization: Bearer sbh_...`
- `Content-Type: application/json` で CycloneDX / SPDX JSON の raw body を送信
  (`--data-binary @sbom.json`、`-F sbom=@sbom.json` は **不可**)。

#### CLI 経由 SBOM アップロード（非推奨）

```
POST /api/v1/cli/upload   # 非推奨 (Sunset: 2026-09-24)
```

multipart の `/cli/upload` は既存 CI パイプライン互換のため 3 ヶ月間共存させますが、
すべてのレスポンスに以下のヘッダを付与します。

- `Deprecation: true`
- `Sunset: Thu, 24 Sep 2026 00:00:00 GMT`
- `Link: </api/v1/projects/{id}/sbom>; rel="successor-version"`

新規連携は上記の正本エンドポイントに切り替えてください。

#### コンポーネント取得

```
GET /api/v1/projects/:id/components
```

**クエリパラメータ:**
- `page` (int): ページ番号
- `limit` (int): 1ページあたりの件数
- `search` (string): 名前で検索

---

### 脆弱性

#### 脆弱性一覧

```
GET /api/v1/projects/:id/vulnerabilities
```

**クエリパラメータ:**
- `page` (int): ページ番号
- `limit` (int): 1ページあたりの件数
- `severity` (string): 深刻度でフィルタ（critical, high, medium, low）
- `status` (string): VEXステータスでフィルタ

**レスポンス:**
```json
{
  "items": [
    {
      "id": "CVE-2024-1234",
      "severity": "high",
      "cvss_score": 8.5,
      "epss_score": 0.15,
      "component": "lodash",
      "version": "4.17.20",
      "vex_status": "affected"
    }
  ],
  "total": 100,
  "page": 1,
  "limit": 20
}
```

---

### VEXステートメント

#### VEXステートメント作成

```
POST /api/v1/projects/:id/vex
```

**リクエストボディ:**
```json
{
  "vulnerability_id": "CVE-2024-1234",
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "statement": "この脆弱性は当社の利用方法には影響しません"
}
```

**VEXステータス値:**
- `affected` - 影響あり
- `not_affected` - 影響なし
- `fixed` - 修正済み
- `under_investigation` - 調査中

#### VEXステートメント一覧

```
GET /api/v1/projects/:id/vex
```

---

### APIキー

#### APIキー作成

```
POST /api/v1/projects/:id/api-keys
```

**リクエストボディ:**
```json
{
  "name": "CI/CDキー",
  "permissions": "write",
  "expires_in_days": 365
}
```

**レスポンス:**
```json
{
  "id": "uuid",
  "name": "CI/CDキー",
  "key": "sbh_xxxxxxxxxxxx",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

> **注意:** `key` は作成時に一度だけ返されます。安全に保管してください。

#### APIキー一覧

```
GET /api/v1/projects/:id/api-keys
```

#### APIキー失効

```
DELETE /api/v1/projects/:id/api-keys/:key_id
```

---

### コンプライアンス

#### コンプライアンススコア取得

```
GET /api/v1/projects/:id/compliance
```

**レスポンス:**
```json
{
  "score": 85,
  "checks": [
    {
      "name": "sbom_exists",
      "passed": true,
      "description": "SBOMが存在します"
    },
    {
      "name": "vulnerabilities_triaged",
      "passed": false,
      "description": "すべての重大な脆弱性にVEXステートメントが必要です"
    }
  ]
}
```

---

### ライセンスポリシー

#### ライセンスポリシー作成

```
POST /api/v1/license-policies
```

**リクエストボディ:**
```json
{
  "name": "デフォルトポリシー",
  "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "denied": ["GPL-3.0", "AGPL-3.0"]
}
```

#### ライセンス違反チェック

```
GET /api/v1/projects/:id/license-violations
```

---

## エラーレスポンス

すべてのエラーは以下の形式です：

```json
{
  "error": "error_code",
  "message": "人間が読めるメッセージ"
}
```

**一般的なHTTPステータスコード:**
- `400` - 不正なリクエスト
- `401` - 認証エラー
- `403` - アクセス拒否
- `404` - 見つかりません
- `500` - サーバーエラー

---

## レート制限

self-host ではデフォルトでレート制限はかかりません。リバースプロキシ (Nginx 等) で制御してください。

将来 SaaS が再開された場合に向けて、レート制限ヘッダーの形式は以下を予定しています:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```
