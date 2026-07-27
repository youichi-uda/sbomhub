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
LEMONSQUEEZY_WEBHOOK_SECRET=xxxxx   # 未設定だと Webhook は全て 401（production では起動拒否）
LEMONSQUEEZY_STORE_ID=xxxxx         # Checkouts API の store relationship に必須。未設定だと checkout 作成が 500
LEMONSQUEEZY_STARTER_VARIANT_ID=xxxxx
LEMONSQUEEZY_PRO_VARIANT_ID=xxxxx
LEMONSQUEEZY_TEAM_VARIANT_ID=xxxxx

# 開発専用のエスケープハッチ（M47）。シークレット未設定の Webhook 受信を
# 署名検証なしで受理する。**有効なのは APP_ENV=development のときだけ**（staging 等では
# 無視、production では起動拒否）。既定は false（fail-closed）。
# SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS=true
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

> **M47 で紐付け方式が変わりました**（下の「Checkout の claim トークン」参照）。以前は checkout URL に
> `checkout[custom][tenant_id]=<テナントID>` を載せていましたが、この値は購入者のブラウザを経由するため
> 改変可能でした。現在は **テナント ID をクライアントに渡さず**、サーバが保持する不透明な claim トークンで
> 紐付けます。

- `POST /api/v1/subscription/checkout` は [Checkouts API](https://docs.lemonsqueezy.com/api/checkouts/create-checkout)
  をサーバ側で呼び、`checkout_data.custom` に **claim トークンのみ**（テナント ID は含めない）を渡します。
- Lemon Squeezy は custom data を、**subscription / order の REST オブジェクトには載せません**。復旧経路で参照できるのは
  Webhook の `meta.custom_data` だけです（[checkout オブジェクト](https://docs.lemonsqueezy.com/api/checkouts/the-checkout-object)
  自体は `checkout_data.custom` を保持しており、`ls_checkout_id` を控えてあるので将来の所有権証明の材料にはなり得ます — 残件 1）。
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
| provider の状態より**新しい** Webhook が適用済み（M47） | `200 {"status":"up_to_date", ...}`（何も書かない） |

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

##### Checkout の claim トークン（M47 で修正）

**旧実装の欠陥**: `POST /api/v1/subscription/checkout` はローカルで
`https://sbomhub.lemonsqueezy.com/checkout/buy/<variant>?checkout[custom][tenant_id]=<自テナント>` という URL を組み立てて
返していました。`checkout[custom][...]` は
[公式ドキュメント](https://docs.lemonsqueezy.com/help/checkout/passing-custom-data)（2026-07-28 再取得）が明示する
**URL パラメータ**であり、購入者はブラウザ上で書き換えられます。Webhook の HMAC が保証するのは「Lemon Squeezy からの配信」
だけで custom data の正当性ではないため、**購入を完了できる者は他テナントに subscription を紐付けられました**
（以後の cancel/expire でそのテナントを downgrade でき、`UNIQUE(tenant_id)` の枠も占有するため被害テナントは自分で
契約できなくなる）。

**現在の方式**:

| 段階 | 動作 |
|------|------|
| Checkout 作成 | サーバが [Checkouts API](https://docs.lemonsqueezy.com/api/checkouts/create-checkout) を **server-to-server** で呼ぶ。`checkout_data.custom` は `{"claim_token": "<256bit 乱数>"}` のみ（**テナント ID は含めない**） |
| 保存 | `subscription_checkout_claims` に **SHA-256 ハッシュ**とテナント ID / plan / 有効期限を記録（migration 060。生トークンは保存しない、`api_keys` と同じ規律） |
| 応答 | provider が返した checkout URL をそのまま返す（テナント ID は URL に出現しない）。SBOMHub 側の検証は「絶対 https URL であること」のみで、provider の `expires` / `signature` パラメータは検証していません |
| Webhook | `subscription_created` の `meta.custom_data.claim_token` を SHA-256 して消し込み、**そのテナントに紐付ける**。`custom_data.tenant_id` は**一切参照しない** |

- 消し込みは単一の条件付き `UPDATE ... RETURNING` で、**同一 subscription の再配信は何度でも成功**し（Lemon Squeezy は
  非 2xx を最大 3 回再送、ダッシュボードからの手動再送も後日あり得る）、**別 subscription による使い回しは拒否**します。
- **有効期限は provider 側と DB 側の両方に入れます**。`model.CheckoutClaimTTL`（7 日）を Checkouts API の
  `expires_at` として送り、**同じ期限で URL 自体が決済不能**になります。claim 行はさらに
  `model.CheckoutClaimGrace`（7 日）長く残し、決済は期限内だったが Webhook 配信が遅れた／後日再送された場合でも
  初回紐付けができるようにしています（provider 側で期限切れの checkout は決済できないので安全側です）。
  **有効期限が効くのは「最初の消し込み」だけ**で、いったん subscription に紐付いた claim は
  その subscription からの再配信であれば期限後でも解決します。
  ※ `expires_at` の送信は**本番 API に対しては未検証**です（ドキュメント記載の形式に従っただけ）。もし provider が
  拒否した場合、checkout 作成が 502 になりログに provider の生レスポンスが出ます。その場合はこのフィールドの送信を
  やめてください（代わりに「URL が無期限になる」残件が復活します）。
- **claim トークンはログに出しません**（キー名のみ記録）。custom data をそのままログすると、未消費のトークンが
  平文でログに残るためです。
- **この設計は「provider 発行 URL に custom パラメータを追記できるか」に依存していません**。追記可否は公式ドキュメントに
  記載がなく未検証のため、仮に追記できたとしても *偽造すべきテナント ID が存在しない* 形にしてあります。

**運用上の影響（機能縮小）**:

- **旧方式（`checkout[custom][tenant_id]` 付き URL）で作成された checkout は紐付けに失敗します**（400 + ログに
  `has_legacy_tenant_id=true`）。SaaS 再開時に未完了の checkout が残っている場合は、DB での手動紐付けが必要です。
- Lemon Squeezy ダッシュボードで手動作成した checkout も同様に紐付きません（claim トークンが無いため）。
- `LEMONSQUEEZY_STORE_ID` が未設定だと checkout 作成は 500 で拒否されます（従来は無意味な URL を返していた）。

##### Webhook 署名検証（M47 で fail-closed 化）

**旧実装の欠陥**: Clerk / Lemon Squeezy いずれの `verifySignature` も、シークレット未設定時に `!IsProduction()` を返して
いました。`APP_ENV` も `ENVIRONMENT` も未設定なら既定値は `development` なので、**「何も設定していないデプロイ」が
そのまま「誰でも署名なしで Webhook を投げられるエンドポイント」**でした。Lemon Squeezy 側は連番のサブスクリプション ID を
推測して `subscription_expired` を投げるだけで他テナントを downgrade でき（`custom_data` すら不要）、Clerk 側は
`organization.deleted` でテナントごと削除（配下の projects/SBOM も CASCADE）できました。

**現在の契約**:

| 状況 | 挙動 |
|------|------|
| シークレット設定済み | 常に検証（`SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` を無視） |
| シークレット未設定 | **401 で拒否**（`APP_ENV` に関係なく） |
| シークレット未設定 + `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS=true` + **`APP_ENV=development`**（未設定時の既定値） | 検証をスキップ。**受理のたびに `signature verification BYPASSED` を WARN 出力** |
| シークレット未設定 + `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS=true` + **staging 等の development 以外**（production を除く） | **401**（フラグは無視。起動時に「set but IGNORED」を WARN） |
| シークレット未設定 + `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS=true` + production | **起動を拒否**（`validateWebhookVerification`）。仮に起動できても request 時に 401 |
| production + SaaS モードで `CLERK_WEBHOOK_SECRET` 未設定 | **起動を拒否** |
| production + billing 有効で `LEMONSQUEEZY_WEBHOOK_SECRET` 未設定 | **起動を拒否** |

- セルフホスト（`CLERK_SECRET_KEY` 未設定）は上記の拒否に一切該当しません。両 Webhook は署名検証の手前で
  200 `skipped` を返すため、シークレットを要求されることはありません。
- **開発フローへの影響**: ngrok で本物の Clerk / Lemon Squeezy を繋ぐ場合はシークレットを設定してください（従来から推奨）。
  `curl` で手作りペイロードを投げるローカル検証をしていた場合は、`SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS=true` を明示的に
  設定するか、テストのように HMAC を自分で計算してください（`webhook_signature_failopen_test.go` の
  `driveLSWebhook` / `driveClerkWebhook` が最小実装例）。

##### `POST /api/v1/plan/select-free` の契約（M47 で縮小）

| 状況 | 応答 |
|------|------|
| Viewer / Member | `403`（`appmw.RequireAdmin()`） |
| サブスクリプション行が無い / `status = expired` | `200 {"status":"ok","plan":"free"}` |
| それ以外の status（`active` / `on_trial` / `past_due` / `unpaid` / `paused` / `cancelled`） | **`409`**（拒否 + カスタマーポータルへ誘導） |
| サブスクリプション参照が一時失敗 | `500`（未設定扱いにフォールバックしない） |

- **なぜ拒否か（製品判断・最も安全側）**: このエンドポイントは Lemon Squeezy を一切呼びません。ダウングレードを許すと
  **課金は継続したまま権限だけ失い**、さらに `subscriptions` と `tenants.plan` が次の Webhook まで食い違います。
  「ここから provider 側も解約する」案は、金銭が動く外向き呼び出しを冪等性・失敗時処理ごと新設する話なので、
  plan 選択エンドポイントに付け足す変更ではないと判断しました。解約はカスタマーポータル
  （`GET /api/v1/subscription/portal`）で行い、期間終了時に `subscription_expired` Webhook が downgrade します。
- `cancelled` を「まだ有効」に含めるのは `handleSubscriptionCancelled` が意図的に downgrade しない（`ends_at` まで有効）
  ためで、`entitlementPlan` と同じ線引きです。

##### Webhook のリビジョン順序（M47 で「古い配信の破棄」を追加）

**旧実装の欠陥**: 全ハンドラが provider 側リビジョン（`data.attributes.updated_at`）を参照せず、届いた順に適用していました。
配送順序は best-effort（Lemon Squeezy は非 2xx を 5s/25s/125s で最大 3 回再送、ダッシュボードからの再送は任意のタイミング）
なので、**遅延した古い配信が新しい状態を上書き**しました（例: Team → Starter に downgrade 後、再送された古い Team の
`subscription_updated` で Team に復帰）。

**現在の挙動**: `subscriptions.provider_updated_at`（migration 061）に「適用済みの最大リビジョン」を保持し、書き込み前に
compare-and-swap します。

| 配信のリビジョン | 挙動 |
|------------------|------|
| 保存値より新しい / 等しい | 適用（watermark を更新） |
| 保存値より**古い** | **破棄**。`200 {"status":"skipped","reason":"stale revision"}` + WARN ログ |
| （同一 subscription への配信が**同時に 2 本**走った場合） | CAS と本体書き込みが別文のため `claim(R1) → claim(R2) → write(R2) → write(R1)` の順序があり得ます。保証しているのは「比較に負けた配信は書かない」であって「常に最新が勝つ」ではありません（残件 6 と同じトランザクション化が必要） |
| `updated_at` が空 / パース不能 | **適用**（順序判定不能）。WARN ログ |
| watermark が NULL（061 以前の行 / 新規作成直後） | 適用 |

- **等しいリビジョンを受理する理由**: Lemon Squeezy は 1 つの状態遷移に対して同じ `updated_at` を持つ複数イベントを
  発行します（`subscription_expired` と同時に `subscription_updated` が届く）。厳密な「より新しい」を要求すると
  後着イベントを落とし、**終端イベント（expiry）を落とすと権利を与えてしまう**方向の失敗になります。
- sync（`POST /api/v1/subscription/sync`）も同じ CAS を通します。

> **SaaS 再開時の残件（未修正・要設計判断）**
>
> 1. **所有権証明の設計が未決定**（M47 で部分的に前進）。**新規 checkout については claim トークンで解決済み**ですが、
>    「既に存在するが紐付いていないサブスクリプション」を後から自テナントのものだと証明する手段は依然ありません
>    （REST API に `custom_data` が無いため）。`POST /api/v1/subscription/sync` の新規作成分岐は塞いだままにしてください。
>    復旧はドキュメント記載の運用対応（DB での手動紐付け）です。
> 2. **checkout URL / claim トークンは bearer secret**（M47 の設計上の残余リスク）。
>    checkout URL は Admin にしか返しませんが、**入手した第三者が決済を完了すると発行元テナントに紐付きます**
>    （＝「他人のテナントに贈与する」方向。奪取ではない）。ただし副作用として、そのテナント唯一の
>    subscription 枠（`UNIQUE(tenant_id)`）を埋めてしまいます。共有リンクのトークンと同じ性質です。
>    緩和は claim の TTL（7 日、**初回紐付けのみに効く**）だけで、**provider 側の checkout URL 自体には有効期限を
>    設定していません**（`expires_at` は未検証のため送っていない）。厳密にするなら checkout 完了時のリダイレクト先で
>    ログイン済みユーザーと突き合わせる等の追加設計が要ります。
> 3. **claim 行の掃除がスケジューラ未実装**。期限切れの `subscription_checkout_claims` は残り続けます（無害ですが増える）。
>    `expires_at` にインデックスは張ってあるので、
>    `DELETE FROM subscription_checkout_claims WHERE consumed_at IS NULL AND expires_at < NOW() - INTERVAL '30 days'`
>    を既存スケジューラに足すだけです。**`consumed_at IS NULL` は必須**です（消し込み済みの行は
>    後日の再配信の解決に必要なため削除してはいけません）。
> 4. **checkout 作成が外向き HTTP 呼び出しの間トランザクションを開いたまま保持します**（最大 30 秒）。
>    `TenantTx` がハンドラ全体を包むためで、`/subscription/sync` が M46 から持っている性質と同じです。
>    低頻度エンドポイントなので現状は許容していますが、コネクションプールを 30 秒占有し得る点は認識してください。
>    provider 呼び出しをトランザクション外に出すか、claim だけ別トランザクションで書くのが対策です。
> 5. **再購入・同時 checkout は `UNIQUE(tenant_id)` に衝突して「課金済みだが紐付かない」状態になり得ます**（既存・未修正）。
>    `subscriptions` はテナントあたり 1 行しか持てません（migration 008）。そのため
>    (a) 期限切れ（`status = expired`）の行が残っているテナントが再契約する、(b) 同一テナントで 2 つの checkout が
>    同時に完了する、のいずれでも `handleSubscriptionCreated` の `INSERT` が UNIQUE 制約に衝突して 500 になり、
>    Lemon Squeezy の再送（最大 3 回）を使い切ると **決済済みなのに紐付かない subscription** が残ります。
>    checkout 作成側にも「有効な契約がある場合は拒否」「保留中 checkout は 1 件まで」といったガードはありません。
>    恒久対策には「期限切れ行を置換／再有効化する原子的な経路」の設計判断が必要です（M47 では触れていません）。
>    現状の復旧は運用対応（DB での手動紐付け）です。
> 6. **Webhook の 2 つの書き込みが非アトミック**（未修正）。`handleSubscriptionCreated` 等は TenantTx の外で動くため
>    subscriptions の更新と `tenants.plan` の更新が別コミットになり、後者が失敗しても 200 を返して再送も止まります
>    （downgrade/expire が反映されないまま高い plan が残る）。`TenantRepository.UpdatePlan` の `RowsAffected` 未検証も
>    同根です（`subscriptions` 側は M46 で検証済み）。**claim の消し込みも同じ性質**で、消し込み後に subscription の
>    作成が失敗した場合は再配信で復旧します（同一 subscription なら再消し込みできる設計）。
> 7. **sync と Webhook の競合（TOCTOU）**（M47 で大幅に緩和・完全解決ではない）。M46 の「書き込み直前の再読み込み」に加え、
>    M47 で **リビジョン CAS** が入ったため（sync も同じ CAS を通し、適用したリビジョンを watermark に記録します）、
>    外部 API 待ちの間に届いた**より新しい** Webhook の書き込みを sync が巻き戻すことはなくなりました。
>    残るのは**同一リビジョン同士の競合**（下記 8）と、CAS 通過後〜行書き込みまでの通常の read-then-write ウィンドウです。
>    完全な直列化には購読単位のロック（`SELECT ... FOR UPDATE` 等）が要ります。
>    **`/plan/select-free` の check→write は M47 で単一の条件付き UPDATE になりました**（`UPDATE tenants ... WHERE NOT EXISTS
>    (live subscription)`）。ただしこれは窓を**狭める**だけで、閉じてはいません（2026-07-28 に dev PostgreSQL で実測）:
>
>    | 競合 subscription の INSERT | guard の結果 | 最終状態 |
>    |---|---|---|
>    | 実行時点で **commit 済み** | 0 行（拒否） | 正しく 409 |
>    | 実行時点で **未 commit** | 1 行（適用） | `tenants.plan = free` と `status = active` が併存 |
>
>    READ COMMITTED では他トランザクションの未コミット行はサブクエリからも見えないため、SQL を工夫しても解決しません。
>    本番の Webhook は autocommit（明示トランザクション無し）で書くため、後者の窓は INSERT 1 文の実行時間分です。
>    完全に閉じるには **Webhook 側にも同じテナント行ロックを取らせる**必要があります。
>    なお「free に落とした直後に checkout が完了する」順序は無害です（`subscription_created` が無条件に plan を書くため
>    最終状態は有料 plan で整合）。危険なのは上表の 2 行目、Webhook が先に plan を書いた後に select-free が上書きする順序です。
> 8. **同一リビジョンの配信は順序保証されない**（M47 の意図的な限界）。CAS は「等しいリビジョン」を受理するため、
>    同じ `updated_at` を持つ複数イベント（`subscription_updated` + `subscription_expired` 等）は**到着順**に適用されます。
>    現在の実装では `subscription_expired` が `tenants.plan` を free にした後に同リビジョンの `subscription_updated` が
>    届いても、その `updated_at` は expired 状態を反映しているため実害は確認されていませんが、
>    **順序に依存しない設計にはなっていません**。恒久対策はイベント種別ごとの優先度（終端イベント優先）を
>    Webhook inbox 化と同時に実装することです。
> 9. **`updated_at` を持たない配信は順序判定できない**（M47 の意図的な限界）。パースできない場合は破棄ではなく適用します。
>    破棄側に倒すと、provider 側のフィールド変更で課金更新が全停止するためです。
> 10. **Clerk（Svix）側には順序保証が無いまま**（未修正）。`webhook_clerk.go` 冒頭の KNOWN LIMIT のとおり、
>    遅延した `user.updated` が `user.deleted` の後に届いて行を復活させる等が依然起こり得ます。Lemon Squeezy 側と違い
>    Clerk のペイロードには行のリビジョンに相当する単調な値が無く、Svix の `svix-id` + イベント timestamp を保持する
>    inbox テーブルが必要です。

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
POST /api/v1/subscription/checkout # Checkout 作成（Owner/Admin のみ、2.5 参照）
GET  /api/v1/subscription/portal   # Billing Portal URL
POST /api/v1/subscription/sync     # 紐付け済みサブスクリプションの再同期（Owner/Admin のみ、2.5 参照）
GET  /api/v1/plan/usage            # 使用量確認
POST /api/v1/plan/select-free      # free プラン選択（Owner/Admin のみ・有効な契約中は 409、2.5 参照）
```

### Webhooks

```
POST /api/webhooks/clerk           # Clerk Webhook（署名必須、2.5 参照）
POST /api/webhooks/lemonsqueezy    # Lemon Squeezy Webhook（署名必須、2.5 参照）
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
