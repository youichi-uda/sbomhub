# APIリファレンス

このドキュメントではSBOMHubのREST APIについて説明します。

## ベースURL

- セルフホスト: `http://localhost:8080`
- SaaS: `https://api.sbomhub.app`

## 認証

### APIキー認証

CI/CD連携にはAPIキーを使用します：

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.sbomhub.app/api/v1/projects
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

#### SBOMアップロード

```
POST /api/v1/projects/:id/sbom
```

**リクエスト:**
- Content-Type: `multipart/form-data`
- ボディ: `sbom` ファイル（CycloneDXまたはSPDX JSON）

**例:**
```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "sbom=@sbom.json" \
  https://api.sbomhub.app/api/v1/projects/{project_id}/sbom
```

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

- セルフホスト: 制限なし
- SaaS Free: 100リクエスト/時
- SaaS Pro: 1000リクエスト/時
- SaaS Team: 10000リクエスト/時

レート制限ヘッダー:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1704067200
```
