# ENCRYPTION_KEY ローテーション手順

> **ステータス**: 本ドキュメントは SBOMHub の `ENCRYPTION_KEY` を回す際の
> 公式オペレータ向けランブックです。ターンキーな
> `sbomhub migrate-encryption` サブコマンドは**未実装**です (フォローアップ
> として追跡 — 本ドキュメント末尾「フォローアップ: 自動化」 参照)。
> 実装されるまで、 オペレータは本ランブックの手動 SQL 手順に従ってください。
>
> 英語版 (canonical): [`encryption-key-rotation.md`](./encryption-key-rotation.md)。

`ENCRYPTION_KEY` は、 API サーバが DB 内の機密データを保存時に暗号化する
AES-256 マスター鍵です。 ローテーションは計画的に行う **短時間ダウンタイム**
保守作業であり、 ciphertext を新鍵で再暗号化する間、 API はオフラインで
ある必要があります。

---

## 1. いつローテーションするか

以下のいずれかの状況で `ENCRYPTION_KEY` をローテーションしてください。

- **インシデント対応** — 鍵が漏洩した、 または漏洩が疑われる場合 (`.env`
  からの流出、 バックアップ経由での露出、 git への誤コミット等)。 即時
  ローテーションし、 鍵で保護されていたデータも露出した可能性として扱う。
- **既知の既定値 / プレースホルダ鍵での本番起動** — 本番で
  `apps/api/cmd/server/main.go` の `knownDefaultEncryptionKeys` に列挙される
  プレースホルダ鍵で 1 度でも API が起動したことがあれば、 速やかに新規
  ランダム鍵へローテーション。
- **定期ローテーション (推奨: 90 日ごと)** — Google Calendar / Outlook 等の
  カレンダードリブンで運用。 インシデント時にぶっつけ本番で初実行するのを
  避け、 ランブックが動くことを*事前に*確認しておく目的。
- **担当者 / アクセス権の変更** — 以前に鍵への読み取りアクセスがあった人物
  が不要になった場合 (退職、 業務委託の入れ替え、 組織変更等)。

---

## 2. 着手前に

### 2.1 `ENCRYPTION_KEY` の影響データ

`ENCRYPTION_KEY` は現在、 以下のデータを保存時に暗号化するために使用されて
います。 自分のチェックアウトでは以下で確認してください。

```bash
grep -rn 'EncryptionKey\|encryptionKey\|GetEncryptionKey' apps/api/ --include='*.go' \
  | grep -v '_test.go'
```

| テーブル | カラム | 格納内容 | 暗号化方式 | 再暗号化が必要? |
| --- | --- | --- | --- | --- |
| `issue_tracker_connections` | `auth_token_encrypted` | 連携先 Jira / Backlog の API トークン (テナント別) | AES-256-GCM (12-byte ランダム nonce、 base64 エンコード) | **はい** |
| `api_keys` | `key_hash` | 発行された SBOMHub API キーの SHA-256 ハッシュ | SHA-256 (一方向ハッシュ、 `ENCRYPTION_KEY` で暗号化されていない) | いいえ — ハッシュはローテーションの影響を受けない |

> 上記の一覧は、 本ドキュメントの commit 時点で網羅的です。 将来別の暗号化
> カラムが追加された際は、 本表と §3 の手順に**必ず追記**してください。

### 2.2 必須事前チェックリスト

> **警告 — `ENCRYPTION_KEY` を触る前に以下を全て実施してください。 ステップ 1
> (DB ダンプ) とステップ 4 (旧鍵の確認) を省略しローテーションが失敗すると、
> 該当 ciphertext は復元不可能です。**

1. **DB の完全ダンプを取り、 検証する。**

   ```bash
   docker compose exec -T postgres \
     pg_dump -U sbomhub_app sbomhub > backup-pre-rotation-$(date +%Y%m%d).sql

   # 中身が空でないこと、 パースできることを軽く確認。
   wc -l backup-pre-rotation-*.sql
   head -5 backup-pre-rotation-*.sql
   ```

   ダンプは API サーバ以外のホストに保管し、 機密情報として扱う (旧 ciphertext
   を含むため)。

2. **`.env` のスナップショット**を取り、 旧鍵をロールバック可能にする。

   ```bash
   cp .env .env.bak.pre-rotation.$(date +%Y%m%d)
   chmod 600 .env.bak.pre-rotation.*
   ```

3. **メンテナンス枠を確保**しユーザに通知する。 移行中は API がオフライン。
   issue tracker 連携がない新規環境なら数秒、 連携が多いと
   `issue_tracker_connections` の行数に応じて線形に時間が伸びる。

4. **本当に現在の鍵を持っているか確認する。** ローテーションには*旧鍵*
   (復号用) と*新鍵* (再暗号化用) の両方が必要。 旧鍵がもう手元になければ
   ciphertext を復号できないため、 該当行を削除して各テナントにローテーション
   後の再登録を依頼するしかない (§6 参照)。

---

## 3. ローテーション手順 (短時間ダウンタイム)

大枠は以下のフロー。

```
API 停止 → 新鍵生成 → 旧鍵で復号→新鍵で再暗号化
  → .env 差し替え → API 起動 → 検証
```

### Step 1 — API を停止

```bash
docker compose stop api
```

`postgres` と `redis` は起動したまま。 移行スクリプトが DB にアクセスする
ため。

### Step 2 — 新鍵を生成し、 旧鍵を保持

```bash
NEW_KEY="$(openssl rand -base64 32)"

# 旧鍵はシェルセッション中だけ保持。 .env への書き戻しは step 4。
OLD_KEY="$(grep ^ENCRYPTION_KEY= .env | cut -d= -f2-)"

echo "OLD: $OLD_KEY"
echo "NEW: $NEW_KEY"
```

両値とも機密。 共有ログやチャットに echo しないこと。

### Step 3 — 該当 ciphertext を再暗号化

ターンキーなサブコマンドは**未実装**。 実装まで、 部分失敗時にクリーンに
ロールバックできるよう、 以下を**単一トランザクション**内で実行してください。

暗号化方式は **AES-256-GCM**、 12-byte ランダム nonce、 オンディスク形式は
`base64( nonce || ciphertext || gcm_tag )`。 暗号実装は
[`apps/api/internal/service/issue_tracker.go`](../apps/api/internal/service/issue_tracker.go)
の `encrypt` / `decrypt` を参照。

> **なぜ単なる shell ではなく本物のプログラムが必要なのか。** レコード毎に
> ランダム nonce を持つ AES-256-GCM は、 純粋な SQL では安全に表現できま
> せん。 推奨は同じ cipher ロジックを import する小さな単発 Go プログラム。
> 本ドキュメント末尾「フォローアップ: 自動化」 参照。 擬似コードは以下。

```text
for each row in issue_tracker_connections:
    plaintext  := AES-256-GCM-decrypt(old_key, base64_decode(row.auth_token_encrypted))
    new_cipher := AES-256-GCM-encrypt(new_key, plaintext)   # 新規ランダム nonce
    UPDATE issue_tracker_connections
       SET auth_token_encrypted = base64_encode(new_cipher),
           updated_at = NOW()
     WHERE id = row.id
```

運用上のガードレール:

- ループは単一トランザクション (`BEGIN ... COMMIT`) で。 エラー時は
  `ROLLBACK` してローテーション中止。 §2.2 の DB スナップショットは
  トランザクションの**さらに後ろ**の安全網。
- 接続は `sbomhub_app` ではなく `sbomhub_migrator` ロールで。 migrator は
  スキーマ所有者で RLS の対象外 (RLS はアプリケーションロールにのみ強制 —
  `apps/api/migrations/023_rls_security_hardening.up.sql` 参照)。
- *新*鍵で*どの*行も暗号化する前に、 全行が*旧*鍵で復号できることを確認。
  1 行でも復号できなければ、 その ciphertext は本当の "old_key" 由来では
  ないことを意味し、 無視するとそのテナントの連携が孤立する。
- 行数 (`before` / `decrypted` / `re-encrypted`) をログ。 3 つは一致する
  必要がある。 平文トークン / どちらの鍵もログに出さない。

### Step 4 — `.env` の鍵を差し替え

最も堅牢な方法は `install.sh --force` の再実行で、 既存 `.env` を
`.env.bak.YYYYMMDD` へ退避し新規 `ENCRYPTION_KEY` (および新規 DB
パスワード) を発行する。

> **注意**: `install.sh --force` は `sbomhub_app` と `sbomhub_migrator` の
> パスワードも回す。 既に初期化済みの DB は、 同時に PostgreSQL ロール側も
> 回さない限り壊れる。 **`ENCRYPTION_KEY` 単独ローテーションでは
> `--force` インストールではなく、 `.env` を in-place 編集すること。**

in-place 編集:

```bash
# .env の ENCRYPTION_KEY 行を step 2 の NEW_KEY で置換。
# (エディタはお好みで; 例は POSIX 互換のため awk を使用)

awk -v new="$NEW_KEY" 'BEGIN{FS=OFS="="} /^ENCRYPTION_KEY=/{$2=new; print; next} 1' \
  .env > .env.tmp && mv .env.tmp .env
chmod 600 .env
```

### Step 5 — API を起動して検証

```bash
docker compose up -d api
docker compose logs -f api | head -50
```

`apps/api/cmd/server/main.go` は起動時に `validateEncryptionKey` を実行する。
新鍵が既知プレースホルダだったり 32 バイト未満だと起動拒否。 クリーンに
起動することが `.env` 編集が正しかった最初の確認。

その後、 §4 の検証チェックを実行。

---

## 4. 検証

ローテーション後、 新鍵が有効化されていること、 過去に暗号化されたレコードが
依然読めることをエンドツーエンドで確認する。

1. **`sbomhub doctor`** (CLI) — 設定済みエンドポイントに対し API 到達性 と
   auth プローブを実行。

   ```bash
   sbomhub doctor
   ```

   `auth-verify` チェックが pass する必要がある (認証付きリクエストを往復;
   401 が出る場合は API キーか新 `ENCRYPTION_KEY` の起動どちらかが不正)。

2. **API キー一覧 (Web UI)** — Web UI にサインインし、 API キーページへ。
   既存キーが `key_prefix` 付きで列挙される必要がある。 `api_keys` は
   SHA-256 ハッシュ (`ENCRYPTION_KEY` での暗号化ではない) なので
   ローテーションの影響を受けてはならない — もし無効になっていれば別の
   問題なので、 ローテーションをリトライしないこと。

3. **Issue tracker 連携** — Jira / Backlog 連携を設定していた任意の
   テナントの統合ページを開く。 connection が active と表示されること。
   手動同期 (またはテストチケット作成) を行い、 新鍵で再暗号化された API
   トークンが上流トラッカーで依然認証できることを確認。 上流から
   `401 Unauthorized` が返る場合、 §3 step 3 の再暗号化でその行が skip
   されたか壊れたかなので、 §2.2 のスナップショットから復旧してやり直す。

4. **アプリケーションログ** — `docker compose logs api` で
   `failed to decrypt`、 `cipher: message authentication failed`、
   `ciphertext too short` 等のエラーが出ていないこと。 これらは
   再暗号化されなかった行が新鍵下では復元不能になっていることを示す。

---

## 5. ロールバック

§3 step 3 (再暗号化) が途中で失敗、 または §4 で再起動後にデータ欠損を
検知した場合のみ使うパス。 半端にローテーション済みの DB を in-place で
「修繕」しようとしないこと。

1. API 停止。

   ```bash
   docker compose stop api
   ```

2. `.env` をスナップショットから復元。

   ```bash
   cp .env.bak.pre-rotation.YYYYMMDD .env
   chmod 600 .env
   ```

3. §2.2 ダンプから DB を復元。

   ```bash
   docker compose exec -T postgres \
     psql -U sbomhub_app -d sbomhub < backup-pre-rotation-YYYYMMDD.sql
   ```

   稼働中 DB に対し `pg_dump` で取った場合、 リストアはスキーマ全体をリプレイ
   する。 ノーデータロスを優先する本番では `pg_restore --clean` + カスタム
   形式ダンプを推奨。

4. API を起動し §4 の検証を再実行。

   ```bash
   docker compose up -d api
   sbomhub doctor
   ```

5. ローテーション失敗の原因を調査してからリトライ。 最頻出の原因は、 ある行
   の ciphertext がそもそも「旧鍵」由来ではなかったケース (例: 過去に
   文書化されないローテーションが行われた行が紛れ込んでいる)。

---

## 6. 旧鍵を失った場合のフォールバック

§3 step 3 に「旧鍵がない」 状態で到達した場合 — 例: 前回 `.env` を破壊した
インシデント復旧 — 既存 ciphertext は復号できない。 現実的な復旧は以下:

1. 新規 `ENCRYPTION_KEY` を §3 step 4 でセット。
2. `TRUNCATE issue_tracker_connections;` (または、 どのテナントを実際に
   消したいか特定できるならテナント毎に `DELETE`)。
3. 影響テナントへ Jira / Backlog 連携をインテグレーション画面から再入力
   するよう通知。 トークンを貼り直すと、 新鍵で暗号化される。

これは連携トークンを犠牲にするが、 他のテナント成果物 (SBOM、
vulnerabilities、 VEX、 監査ログ等) はそもそも `ENCRYPTION_KEY` を使わない
ので維持される。

---

## 7. スケジュール推奨

| トリガー | サイクル | 備考 |
| --- | --- | --- |
| 定期ローテーション | 90 日ごと | カレンダーリマインダで十分。 ステージング環境があれば事前にリハーサル推奨。 |
| インシデント (鍵漏洩) | 即時 | 全 `issue_tracker_connections` トークンを露出済みとして扱う; マスター鍵ローテーションは流出済み平文を無効化しない。 ローテーション後、 影響テナントには*上流*の Jira / Backlog トークンも回すよう案内。 |
| 担当者変更 | オフボーディング後 7 日以内 | 退職者が `.env` への operator アクセス権を持っていた場合は回す。 |
| 既知の既定鍵での初回起動 | `apps/api/cmd/server/main.go` の `validateEncryptionKey` を更新しアップグレードしたら即時 | 起動チェックは新規起動を止めるが、 既定鍵で既に暗号化済みの行は回すまで読み取り可能。 |

シンプルな Google Calendar リマインダのテンプレート:

```
Title: SBOMHub ENCRYPTION_KEY ローテーション期限
Repeat: every 90 days
Notes: docs/encryption-key-rotation.ja.md に従う。
       開始前に DB スナップショット。 鍵単独ローテーションでは
       install.sh --force は使わないこと。
```

---

## フォローアップ: 自動化

§3 step 3 をラップする `sbomhub migrate-encryption` (もしくは
`apps/api/cmd/migrate-encryption`) サブコマンドは**未実装**。 フォロー
アップ issue として追跡 (本ドキュメントを読んでいる operator / contributor
が無ければ起票してください)。 実装時の推奨設計:

- フラグ: `--old-key <base64>`、 `--new-key <base64>`、 `--dry-run`、
  `--table issue_tracker_connections` (拡張可)。
- `sbomhub_migrator` ロールで接続 (RLS 対象外、 スキーマ所有者)。
- `apps/api/internal/service/issue_tracker.go` の AES-GCM ヘルパを再利用
  し、 cipher 契約を 1 箇所に集約。
- `--dry-run` は再暗号化する*予定*の行数を報告し、 全行が `--old-key` で
  復号可能なことを書き込まずに検証する。
- 再書き込みを単一トランザクションでラップ。
- `APP_ENV=production` かつ `--dry-run` が 1 度も実行されていない、 もしくは
  復号件数が行数と一致していない場合は実行拒否。

サブコマンドが実装されるまでは、 §3 step 3 を真理 source として扱う。
