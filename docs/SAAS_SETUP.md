# SBOMHub SaaS Setup Guide

SBOMHubはセルフホストモードとSaaSモードの両方をサポートしています。

## ライセンスについて

SBOMHubは **AGPL-3.0** ライセンスで提供されています。

| 利用形態 | 許可 | 条件 |
|---------|------|------|
| **セルフホスト（社内利用）** | ✅ | ソースコード公開不要 |
| **セルフホスト（改変あり）** | ✅ | 改変部分のソースコード公開必要 |
| **SaaS提供（第三者向け）** | ⚠️ | 全ソースコードをAGPLで公開必要 |
| **公式SBOMHub Cloud** | ✅ | 開発元による提供 |

> **注意**: 第三者がSBOMHubを基にした商用SaaSを提供する場合、AGPLに基づき全ソースコード（改変部分含む）を同じライセンスで公開する義務があります。商用ライセンスが必要な場合はお問い合わせください。

## 動作モード

| モード | 条件 | 認証 | 課金 | マルチテナント |
|--------|------|------|------|---------------|
| **セルフホスト** | 環境変数なし | なし（全機能開放） | なし | シングルテナント |
| **SaaS** | `CLERK_SECRET_KEY` 設定 | Clerk | Lemon Squeezy | マルチテナント |

---

## セルフホストモード

環境変数を設定せずに起動すると、セルフホストモードで動作します。

```bash
# 最小構成で起動
docker compose up -d postgres redis
cd apps/api && go run ./cmd/server
cd apps/web && npm run dev
```

**特徴:**
- 認証不要（全ユーザーが管理者権限）
- 全機能が利用可能（Enterprise相当）
- デフォルトテナントを自動作成
- プラン制限なし

---

## SaaSモード設定

### 1. Clerk設定

#### 1.1 Clerkアカウント作成

1. https://clerk.com でアカウント作成
2. 新規アプリケーション作成（例: SBOMHub）
3. 認証方法を選択:
   - Email/Password
   - Google OAuth
   - GitHub OAuth
4. **Organization機能を有効化**（Settings → Organizations）

#### 1.2 環境変数設定

```bash
# Backend (.env)
CLERK_SECRET_KEY=sk_live_xxxxx          # Dashboard → API Keys
CLERK_WEBHOOK_SECRET=whsec_xxxxx        # Webhooks設定後に取得

# Frontend (.env.local)
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_xxxxx
CLERK_SECRET_KEY=sk_live_xxxxx
```

#### 1.3 Webhook設定

Clerk Dashboard → Webhooks → Add Endpoint

- **URL**: `https://api.your-domain.com/api/webhooks/clerk`
- **Events**:
  - `user.created`
  - `user.updated`
  - `user.deleted`
  - `organization.created`
  - `organization.updated`
  - `organization.deleted`
  - `organizationMembership.created`
  - `organizationMembership.updated`
  - `organizationMembership.deleted`

---

### 2. Lemon Squeezy設定（課金）

#### 2.1 アカウント・ストア作成

1. https://lemonsqueezy.com でアカウント作成
2. Store作成

#### 2.2 Products作成

| Product名 | 価格 | Variant ID |
|-----------|------|------------|
| SBOMHub Starter | ¥2,500/月 | `LEMONSQUEEZY_STARTER_VARIANT_ID` |
| SBOMHub Pro | ¥8,000/月 | `LEMONSQUEEZY_PRO_VARIANT_ID` |
| SBOMHub Team | ¥20,000/月 | `LEMONSQUEEZY_TEAM_VARIANT_ID` |

#### 2.3 環境変数設定

```bash
LEMONSQUEEZY_API_KEY=xxxxx
LEMONSQUEEZY_WEBHOOK_SECRET=xxxxx
LEMONSQUEEZY_STORE_ID=xxxxx
LEMONSQUEEZY_STARTER_VARIANT_ID=xxxxx
LEMONSQUEEZY_PRO_VARIANT_ID=xxxxx
LEMONSQUEEZY_TEAM_VARIANT_ID=xxxxx
```

#### 2.4 Webhook設定

Lemon Squeezy Dashboard → Settings → Webhooks

- **URL**: `https://api.your-domain.com/api/webhooks/lemonsqueezy`
- **Events**:
  - `subscription_created`
  - `subscription_updated`
  - `subscription_cancelled`
  - `subscription_resumed`
  - `subscription_expired`
  - `subscription_paused`
  - `subscription_unpaused`

#### 2.5 テナントとサブスクリプションの紐付け（重要）

テナントと Lemon Squeezy サブスクリプションの**紐付けは Checkout 時に一度だけ**行われます。

- `POST /api/v1/subscription/checkout` が発行する URL は `checkout[custom][tenant_id]=<テナントID>` を含みます。
- Lemon Squeezy はこの値を **Webhook の `meta.custom_data` でのみ**返します。
- REST API の subscription オブジェクト（`GET /v1/subscriptions/{id}`）には `custom_data` が**存在しません**（2026-07-27 時点の
  [公式ドキュメント](https://docs.lemonsqueezy.com/api/subscriptions/the-subscription-object) で確認。属性は `store_id` /
  `customer_id` / `order_id` / `order_item_id` / `product_id` / `variant_id` / `product_name` / `variant_name` /
  `user_name` / `user_email` / `status` / `status_formatted` / `card_brand` / `card_last_four` / `payment_processor` /
  `pause` / `cancelled` / `trial_ends_at` / `billing_anchor` / `first_subscription_item` / `urls` / `renews_at` /
  `ends_at` / `created_at` / `updated_at` / `test_mode`）。order オブジェクトにも `custom_data` はありません。

**したがって Webhook が唯一の紐付け経路です。** Webhook 設定（2.4）が正しく動作していることを必ず確認してください。

##### `POST /api/v1/subscription/sync` の契約（M46 で縮小）

このエンドポイントは Webhook 取りこぼしからの**復旧専用**であり、**すでに自テナントに紐付いている** サブスクリプションの
再同期のみを行います。

| 状況 | 応答 |
|------|------|
| 自テナントに紐付いた `ls_subscription_id` | `200 {"status":"synced","plan":"..."}`（provider 側の status / plan を取り込む） |
| **他テナント**に紐付いた `ls_subscription_id` | `404`（拒否。所有権は移らない） |
| どのテナントにも紐付いていない `ls_subscription_id` | `404`（拒否。**新規作成はしない**） |
| Lemon Squeezy に存在しない `ls_subscription_id` | `404` |
| リクエストボディに `ls_subscription_id` が無い | `200 {"status":"manual_required", ...}` |
| リクエストボディが不正な JSON | `400 {"error":"invalid request"}` |

- 上記 4 つの拒否は**同一の 404 応答（本文も同一）**です。Lemon Squeezy のサブスクリプション ID は短い連番であり、
  API キーはストア単位のため、応答を区別すると「どの ID が他テナントに使われているか」を列挙できてしまうためです。
- 所有権判定は **Lemon Squeezy API を呼ぶ前に**、テナントスコープの DB 参照（`GetByTenantID`）だけで行います。
  そのため (a) 拒否 4 パターンは実行経路も同一で応答時間からも区別できず、(b) 認可されない ID で外向き API
  リクエストを発生させることもできません。
- **付与される plan（`tenants.plan`）は product 名と status の両方から決まります**（`entitlementPlan`）。
  `status = expired` のサブスクリプションを再同期しても `free` のままです（Webhook の `handleSubscriptionExpired`
  と同じ挙動）。`cancelled` / `paused` / `past_due` / `unpaid` は Webhook 側と同じく plan を維持します。
  以前は product 名だけで判定していたため、期限切れ後に自分の ID を再同期するだけで有料 plan を復活させられました。
- 一方 **`subscriptions.plan` には「購入した product」をそのまま記録**します（Webhook 各ハンドラと同一）。
  ここに entitlement を書くと `handleSubscriptionUpdated` の `newPlan != previousPlan` 判定が誤発火し、
  `subscription_expired` と同時に届く `subscription_updated` で有料 plan が復活してしまいます。
- サブスクリプション行と `tenants.plan` の両方の書き込みは同一トランザクション（`TenantTx`）で行われ、
  どちらかが失敗すれば両方ロールバックされます。
- ロールは **Owner / Admin のみ**（`RequireAdmin`）。Member / Viewer は 403 です。
- **機能縮小の内容**: 以前はこのエンドポイントで未紐付けのサブスクリプションを自テナントに「取り込む」ことができました。
  所有権を証明する手段が無いため（上記のとおり REST API に `custom_data` が無い）、この取り込みは廃止されています。
  Webhook が完全に失われた場合の復旧は、現状**運用対応（DB での手動紐付け）** が必要です。

> **SaaS 再開時の残件（未修正・要設計判断）**
>
> 1. **所有権証明の設計が未決定**。「テナントがそのサブスクリプションの所有者であること」を証明する手段（例: Checkout 時に
>    発行したワンタイム claim トークンを DB に控えて Webhook 側で消し込む、`orders` の `user_email` と検証済みテナント
>    請求先メールを突き合わせる、Lemon Squeezy の customer portal 経由での再紐付け）が決まっていません。これが決まるまで、
>    セルフサービスでの紐付け作成は意図的に塞いだままにしてください。
> 2. **Checkout の `tenant_id` はクライアント側で改変可能**（未修正）。`POST /api/v1/subscription/checkout` が返す URL の
>    `checkout[custom][tenant_id]` はブラウザで書き換えられ、Lemon Squeezy はその値をそのまま Webhook の
>    `meta.custom_data` に載せて返します。HMAC 署名が保証するのは「Lemon Squeezy からの配信であること」だけで、
>    **テナント紐付けの正当性は保証しません**。実際に決済を完了させる必要があるため悪用コストは高いものの、
>    他テナントの plan を書き換え・`UNIQUE(tenant_id)` の枠を占有し、以後の expire/downgrade イベントを
>    そのテナントに向けることが理論上可能です。上記 1 の claim トークン設計で同時に解消してください
>    （サーバ側で [Checkouts API](https://docs.lemonsqueezy.com/api/checkouts/create-checkout) を叩いて nonce を保持するのが本筋）。
> 3. **`POST /api/v1/plan/select-free` にロールゲートが無い**（未修正）。Viewer / Member でも `tenants.plan` を `free` に
>    書き換えられ、有料サブスクリプションが存在していても無条件にダウングレードします（課金は継続したまま権限だけ失う）。
>    現在フロントエンドからは呼ばれていません（`billing/page.tsx` でハンドラが除去済み）。SaaS 再開前に
>    `appmw.RequireAdmin()` の付与、および「サブスクリプションが存在する場合は拒否」の条件追加が必要です。
> 4. **Webhook 署名検証が fail-open**（未修正）。`verifySignature` は `LEMONSQUEEZY_WEBHOOK_SECRET` が空のとき
>    `!IsProduction()` を返すため、`APP_ENV` が `production` 以外（既定は `development`）かつシークレット未設定の
>    デプロイでは**誰でも署名なしで Webhook を投げられます**。連番のサブスクリプション ID を推測して
>    `subscription_expired` / `subscription_updated` を送れば、他テナントの plan を書き換え可能です
>    （`custom_data` を必要としないため残件 2 とは独立）。SaaS 再開前に「billing 有効時はシークレット必須」を
>    起動時に強制し、ローカル用のバイパスは `APP_ENV` からの推論ではなく明示的な opt-in にしてください。
> 5. **Webhook の 2 つの書き込みが非アトミック**（未修正）。`handleSubscriptionCreated` 等は TenantTx の外で動くため
>    subscriptions の更新と `tenants.plan` の更新が別コミットになり、後者が失敗しても 200 を返して再送も止まります
>    （downgrade/expire が反映されないまま高い plan が残る）。`TenantRepository.UpdatePlan` の `RowsAffected` 未検証も
>    同根です（`subscriptions` 側は M46 で検証済み）。
> 6. **sync と Webhook の競合（TOCTOU）**（緩和のみ・未解決）。sync は所有権確認 → 外部 API 呼び出し（最大 30 秒）
>    → 書き込み、の順で動き、Webhook はこのトランザクションの外で走ります。`Update` は行全体を書くため、
>    外部 API 待ちの間に届いた Webhook の書き込み（`cancelled_at` / `ends_at` 等）を巻き戻す可能性がありました。
>    M46 で **書き込み直前に行を読み直す**（リンクが消えている／張り替わっていれば拒否）ようにしたため、
>    競合ウィンドウは HTTP 呼び出しの長さから通常の read-then-write 間隔まで縮んでいます。
>    **完全な解決には provider の `updated_at` を保持したバージョン条件付き更新（または購読単位の直列化）が必要**で、
>    これは残件 8 と同じ対策で同時に解消するのが自然です。
> 7. **`POST /api/v1/subscription/checkout` に Admin ゲートが無い**（未修正）。URL を作るだけとはいえ、その checkout を
>    完了させると `subscription_created` が届いてテナント唯一のサブスクリプション枠を占有し plan を変えられます。
>    残件 3 と同じ wave で `RequireAdmin` を検討してください。
> 8. **Webhook が順序保証なしで適用される**（未修正・既存）。`handleSubscriptionCreated` は無条件に、
>    `handleSubscriptionUpdated` は product が変わったときに `tenants.plan` を書き換えますが、provider 側の
>    `attributes.updated_at`（リビジョン）を一切参照しません。そのため **遅延した古い配信が新しい状態を上書き**します
>    （例: Team → Starter へダウングレード後、遅れて届いた Team の `subscription_updated` で Team に戻る）。
>    sync の結果も同様に上書きされ得ます。恒久対策は provider の `updated_at` を別カラムに保持して
>    「古いリビジョンは棄却」＋終端イベント優先の適用順序を実装すること（Webhook inbox 化の残件と同時に対応するのが自然）。
>    ※ これは sync 側の変更とは独立した既存の不具合で、M46 で悪化はしていません。

---

### 3. データベースマイグレーション

SaaS機能を使用するには、追加のマイグレーションが必要です。

```bash
# マイグレーション実行
cd apps/api
go run ./cmd/migrate up

# または手動実行
psql -U sbomhub -d sbomhub -f migrations/006_notification_settings.up.sql
psql -U sbomhub -d sbomhub -f migrations/007_multitenancy.up.sql
psql -U sbomhub -d sbomhub -f migrations/008_subscriptions.up.sql
```

---

## プラン制限

| プラン | ユーザー数 | プロジェクト数 | 主な機能 |
|--------|-----------|---------------|----------|
| Free | 1 | 2 | 基本機能のみ |
| Starter | 3 | 10 | VEX, ライセンスポリシー, Slack/Discord通知 |
| Pro | 10 | 無制限 | 上記 + 優先サポート |
| Team | 30 | 無制限 | 上記 + 無制限SBOMストレージ |
| Enterprise | 無制限 | 無制限 | SSO, カスタム統合, SLA |

---

## APIエンドポイント

### 認証関連

```
GET  /api/v1/me                    # 現在のユーザー情報
GET  /api/v1/subscription          # サブスクリプション情報
POST /api/v1/subscription/checkout # Checkout URL生成
GET  /api/v1/subscription/portal   # Billing Portal URL
POST /api/v1/subscription/sync     # 紐付け済みサブスクリプションの再同期（Owner/Admin のみ、2.5 参照）
GET  /api/v1/plan/usage            # 使用量確認
```

### Webhooks

```
POST /api/webhooks/clerk           # Clerk Webhook
POST /api/webhooks/lemonsqueezy    # Lemon Squeezy Webhook
```

---

## ローカル開発でのSaaSモードテスト

### ngrokを使用したWebhookテスト

```bash
# ngrokでローカルAPIを公開
ngrok http 8080

# 表示されたURLをWebhook設定に使用
# 例: https://xxxx.ngrok.io/api/webhooks/clerk
```

### テスト用環境変数

```bash
# .env.local (開発用)
CLERK_SECRET_KEY=sk_test_xxxxx
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_xxxxx
```

---

## トラブルシューティング

### 認証エラー

```
401 Unauthorized: invalid token
```

→ `CLERK_SECRET_KEY` が正しく設定されているか確認

### Webhookエラー

```
401 Unauthorized: invalid signature
```

→ `CLERK_WEBHOOK_SECRET` / `LEMONSQUEEZY_WEBHOOK_SECRET` を確認

### テナント未検出

```
403 Forbidden: tenant not found
```

→ Clerk Organizationが作成されているか確認
→ Webhookでテナントが同期されているか確認

---

## セキュリティ考慮事項

1. **環境変数**: シークレットキーは絶対にコミットしない
2. **HTTPS**: 本番環境では必ずHTTPSを使用
3. **Webhook署名**: 必ず署名検証を有効化
4. **RLS**: PostgreSQL Row-Level Securityでテナント分離
5. **監査ログ**: 重要な操作は`audit_logs`テーブルに記録
