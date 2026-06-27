# ENCRYPTION_KEY ローテーション手順

> **ステータス**: 本ドキュメントは SBOMHub の `ENCRYPTION_KEY` を回す際の
> 公式オペレータ向けランブックです。標準 path は M6 issue
> [#56](https://github.com/youichi-uda/sbomhub/issues/56) で実装した
> [`apps/api/cmd/migrate-encryption`](../apps/api/cmd/migrate-encryption) です。
> 旧 7 step 手動 flow は offline / 緊急時用 fallback として §3.1 に残します。
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

| テーブル | カラム | 形式 | 格納内容 | 暗号化 path | 再暗号化が必要? |
| --- | --- | --- | --- | --- | --- |
| `tenant_llm_config` | `encrypted_api_key` | BYTEA `nonce \|\| sealed` | BYOK LLM API key (テナント別) | `internal/service/llm/crypto.go`; `internal/handler/settings_llm.go` で保存; `cmd/server/llm_resolver.go` で復号 | **はい** |
| `issue_tracker_connections` | `auth_token_encrypted` | TEXT base64 `nonce \|\| sealed` | 連携先 Jira / Backlog の API トークン (テナント別) | `internal/service/issue_tracker.go` | **はい** |
| `api_keys` | `key_hash` | SHA-256 一方向ハッシュ | 発行された SBOMHub API キーの検証子 | `internal/service/apikey.go` の検証 path のみ | いいえ — `ENCRYPTION_KEY` で暗号化されておらず、 ローテーションの影響を受けない |

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
   BYOK LLM key と issue tracker 連携がない新規環境なら数秒、 連携が多いと
   `tenant_llm_config` と `issue_tracker_connections` の暗号化済み行数に
   応じて線形に時間が伸びる。

4. **本当に現在の鍵を持っているか確認する。** ローテーションには*旧鍵*
   (復号用) と*新鍵* (再暗号化用) の両方が必要。 旧鍵がもう手元になければ
   ciphertext を復号できないため、 該当行を削除して各テナントにローテーション
   後の再登録を依頼するしかない (§6 参照)。

---

## 3. ローテーション手順 (automation-first、短時間ダウンタイム)

API を停止し両方の鍵を用意する。

```bash
docker compose stop api
NEW_KEY="$(openssl rand -base64 32)"
OLD_KEY="$(grep ^ENCRYPTION_KEY= .env | cut -d= -f2-)"
export OLD_ENCRYPTION_KEY="$OLD_KEY"
export NEW_ENCRYPTION_KEY="$NEW_KEY"
```

`postgres` と `redis` は起動したまま。 移行 binary が DB にアクセスするため。
両値とも機密であり、 environment 経由だけで渡す。 argv、 共有ログ、
shell history、 ticket には載せない。

`apps/api` から CLI を実行する。

```bash
cd apps/api
export PATH=$PATH:/usr/local/go/bin
go run ./cmd/migrate-encryption \
  --db-url "$DATABASE_URL" \
  --dry-run \
  --report ../../migrate-encryption-dry-run.json
```

dry-run は `OLD_ENCRYPTION_KEY` で全 encrypted row を復号し、 DB には書き込ま
ない。 report には per-row の `SHA256(plaintext)` だけを書く。 次の apply /
verify で同じ report を使う。

apply:

```bash
go run ./cmd/migrate-encryption \
  --db-url "$DATABASE_URL" \
  --apply \
  --report-input ../../migrate-encryption-dry-run.json \
  --report ../../migrate-encryption-apply.json
```

tool は transaction 内で tenant ごとに
`SELECT set_config('app.current_tenant_id', ..., true)` を実行する。 これにより
`tenant_llm_config` と `issue_tracker_connections` は runtime と同じ FORCE RLS
posture で処理される。 推奨 role は production runtime と同じ
`sbomhub_app` (`NOBYPASSRLS`)。 data maintenance を migrator role に限定する
運用なら `sbomhub_migrator` も使用可能だが、 同じく `NOBYPASSRLS` なので
per-tenant GUC は必須。

apply 成功後、 `.env` / Docker Secrets / KMS の `ENCRYPTION_KEY` を `NEW_KEY`
へ差し替え、 API を restart し、 dry-run digest と全行比較する。

```bash
go run ./cmd/migrate-encryption \
  --db-url "$DATABASE_URL" \
  --verify \
  --report-input ../../migrate-encryption-dry-run.json \
  --report ../../migrate-encryption-verify.json
```

`--verify` は旧 Step 2.5 / Step 6 の sample hash 比較を置き換える。 全 target
row を `NEW_ENCRYPTION_KEY` で復号し、 dry-run report の per-row digest と比較
するため、 旧 `LIMIT 1` smoke sample の限界を受けない。

運用メモ:

- default target は `tenant_llm_config.encrypted_api_key` (BYTEA) と
  `issue_tracker_connections.auth_token_encrypted` (TEXT base64)。
- `--batch-size` default は tenant transaction あたり 1000 row。 大規模 tenant
  は transaction 分割され、 lock 時間と rollback 範囲を抑える。 ※要確認:
  10k row 超の tenant は staging で lock 影響を確認すること。
- `--apply` は冪等。 既に `NEW_ENCRYPTION_KEY` で復号できる行は
  `already-new` として skip。 旧鍵・新鍵の両方で復号不能な行は error。
- 中断時は同じ dry-run report で再実行できる。 厳密に再開したい場合は
  `--resume-from <row_id>` を渡す。 既に新鍵化済みの行は skip される。
- `--continue-on-error` は row failure を report しつつ batch 内の次行へ進む。
  未指定なら現在 transaction を rollback して終了する。

### 3.1 手動 fallback (offline / 緊急時のみ)

Go binary を build / 実行できない場合だけ以下を使う。 大枠は旧 7 step。

1. 全 tenant の暗号化済み行を旧 KEY で復号する (per-tenant loop):
   `tenant_llm_config.encrypted_api_key` と
   `issue_tracker_connections.auth_token_encrypted`。
2. plaintext は memory 内だけに一時保持し、 disk には書き出さない。
   digest 記録は automation path の `--dry-run` report が推奨。 完全手動の場合
   のみ、 下記 Step 2.5 の sample check を限定的 fallback として使う。
3. `ENCRYPTION_KEY` を新 KEY に切り替える (`.env` / Docker Secrets / KMS)。
4. server を restart し、 新 KEY で起動する。
5. 全 plaintext を新 KEY で再暗号化し、 DB を更新する (per-tenant loop)。
6. `verify-encryption.sh --key-file <new-key>` を実行し、 旧鍵で記録済みの
   SHA256 digest と比較する。
7. 合意した保持期間後に旧 KEY を destroy する。

### Manual Step 1 — 全暗号化済み行を旧鍵で復号

部分失敗時にクリーンにロールバックできるよう、 手動手順はトランザクション
内で実行する。

暗号化方式は **AES-256-GCM**、 12-byte ランダム nonce。
`tenant_llm_config.encrypted_api_key` は
[`apps/api/internal/service/llm/crypto.go`](../apps/api/internal/service/llm/crypto.go)
経由の BYTEA `nonce || sealed`。 `issue_tracker_connections.auth_token_encrypted`
は
[`apps/api/internal/service/issue_tracker.go`](../apps/api/internal/service/issue_tracker.go)
経由の base64 `nonce || sealed`。

> **なぜ単なる shell ではなく本物のプログラムが必要なのか。** レコード毎に
> ランダム nonce を持つ AES-256-GCM は、 純粋な SQL では安全に表現できま
> せん。 推奨は同じ cipher ロジックを import する小さな単発 Go プログラム。
> 本ドキュメント末尾「フォローアップ: 自動化」 参照。 擬似コードは以下。

```text
for each tenant:
    BEGIN
    SET LOCAL app.current_tenant_id = tenant.id

    for each row in tenant_llm_config where encrypted_api_key is not null:
        plaintext := llm.Decrypt(row.encrypted_api_key, old_key)
        plaintext は memory 内だけに row.tenant_id で保持

    for each row in issue_tracker_connections:
        plaintext := issueTrackerDecrypt(base64_decode(row.auth_token_encrypted), old_key)
        plaintext は memory 内だけに row.id で保持

    COMMIT
```

運用上のガードレール:

- tenant ごとのループはトランザクション (`BEGIN ... COMMIT`) で。 エラー時は
  `ROLLBACK` してローテーション中止。 §2.2 の DB スナップショットは
  トランザクションの**さらに後ろ**の安全網。
- `sbomhub_migrator` ロールは `sbomhub_app` と同じく `NOBYPASSRLS`。
  `tenant_llm_config` と `issue_tracker_connections` は
  `FORCE ROW LEVEL SECURITY` なので、 `app.current_tenant_id` 未設定の
  migrator SELECT は policy を bypass せず、 tenant 行が 0 件に見える。
- 全 tenant 行を手動で読むには RLS-aware な方法を使うこと: option A (推奨)
  は tenant ごとに `SET LOCAL app.current_tenant_id = '<tenant uuid>'` してから
  SELECT / UPDATE; option B は rotation 中だけ一時的に
  `DISABLE ROW LEVEL SECURITY` し、 traffic 再開前に `ENABLE` + `FORCE` を
  restore (migration 045 の maintenance pattern と同じ); option C は
  tenant ごとの API 経由で再暗号化し、 `sbomhub_app` と通常の tenant context
  に RLS を効かせる。
- *新*鍵で*どの*行も暗号化する前に、 全行が*旧*鍵で復号できることを確認。
  1 行でも復号できなければ、 その ciphertext は本当の "old_key" 由来では
  ないことを意味し、 無視するとそのテナントの連携または BYOK LLM provider
  が孤立する。
- 行数 (`before` / `decrypted` / `re-encrypted`) をログ。 3 つは一致する
  必要がある。 平文トークン / どちらの鍵もログに出さない。

### Manual Step 2 — plaintext は memory 内だけに保持

Step 1 の plaintext は process memory 内だけに保持する。 temporary file、 SQL
dump、 shell history、 application log、 chat、 ticketing system へ書き出さない。
全 plaintext を memory に保持できない場合は tenant 単位で処理し、 その tenant
の再暗号化と検証が終わってから commit する。

### Manual Step 2.5 — ciphertext 上書き前に旧鍵 plaintext hash を記録

DB 行を `NEW_KEY` で再暗号化する前に、 まだ旧鍵 ciphertext が残っている DB に
対して decrypt smoke test を実行し、 出力された SHA256 plaintext hash だけを
保存する。 旧 master key を disk に書かない environment 経路を first choice
にする。

```bash
# Recommended (env path, no disk persistence):
ENCRYPTION_KEY="$OLD_KEY" ./docker/scripts/verify-encryption.sh \
  --db-url "$DATABASE_URL" > before-rotation-hash.txt
# $OLD_KEY shell variable lives only in this shell session.
```

shell 変数が実用的でない場合のみ、 command 実行中だけ managed temporary file を
使う。

```bash
# Alternative (file path, if shell variable is impractical):
# CAREFUL: writes the old master key to disk. Use the lifecycle pattern below.
old_key_file="$(mktemp)"
chmod 600 "$old_key_file"
trap 'shred -u "$old_key_file" 2>/dev/null || rm -f "$old_key_file"' EXIT
echo "$OLD_KEY" > "$old_key_file"
./docker/scripts/verify-encryption.sh --key-file "$old_key_file" \
  --db-url "$DATABASE_URL" > before-rotation-hash.txt
```

保存ファイルに含めるのは `ok ... sha256=<hex>` 行だけ。 旧鍵や plaintext を
含めてはならない。 DB 上の ciphertext が `OLD_KEY` で復号できるのはこの時点
だけ。 Step 5 で DB を更新した後は、 書き換え済み行を `OLD_KEY` で復号でき
ないのが正常なので、 post-rotation 比較として旧鍵で再実行しない。
temporary-file lifecycle は手動運用になる。 automation binary が利用可能なら
`migrate-encryption --dry-run` report を優先する。

### Manual Step 3 — `.env` / Docker Secrets / KMS の鍵を差し替え

最も堅牢な方法は `install.sh --force` の再実行で、 既存 `.env` を
`.env.bak.YYYYMMDD` へ退避し新規 `ENCRYPTION_KEY` (および新規 DB
パスワード) を発行する。

> **注意**: `install.sh --force` は `sbomhub_app` と `sbomhub_migrator` の
> パスワードも回す。 既に初期化済みの DB は、 同時に PostgreSQL ロール側も
> 回さない限り壊れる。 **`ENCRYPTION_KEY` 単独ローテーションでは
> `--force` インストールではなく、 `.env` を in-place 編集すること。**

in-place 編集:

```bash
# .env の ENCRYPTION_KEY 行を準備済み NEW_KEY で置換。
# (エディタはお好みで; 例は POSIX 互換のため awk を使用)

awk -v new="$NEW_KEY" 'BEGIN{FS=OFS="="} /^ENCRYPTION_KEY=/{$2=new; print; next} 1' \
  .env > .env.tmp && mv .env.tmp .env
chmod 600 .env
```

enterprise Docker Secrets では `docker/secrets/encryption_key.txt` を `NEW_KEY`
に置換し、 permission は `0600` のままにする。 KMS-backed deployment では、
restart 前に API が参照する KMS secret version / alias を更新する。 Step 6 が
pass するまでは maintenance window を閉じたままにする。

### Manual Step 4 — 新鍵で server を restart

```bash
docker compose up -d api
docker compose logs -f api | head -50
```

`apps/api/cmd/server/main.go` は起動時に `validateEncryptionKey` を実行する。
新鍵が既知プレースホルダだったり 32 バイト未満だと起動拒否。 クリーンに
起動することが `.env` 編集が正しかった最初の確認。

### Manual Step 5 — 全行を新鍵で再暗号化

新鍵で API が起動した状態で、 Step 1-2 で memory に保持した plaintext から
暗号化カラムを更新する。

```text
for each tenant:
    BEGIN
    SET LOCAL app.current_tenant_id = tenant.id

    for each cached tenant_llm_config plaintext:
        new_cipher := llm.Encrypt(plaintext, new_key)   # 新規ランダム nonce
        UPDATE tenant_llm_config
           SET encrypted_api_key = new_cipher,
               updated_at = NOW()
         WHERE tenant_id = tenant.id

    for each cached issue_tracker_connections plaintext:
        new_cipher := issueTrackerEncrypt(plaintext, new_key)
        UPDATE issue_tracker_connections
           SET auth_token_encrypted = base64_encode(new_cipher),
               updated_at = NOW()
         WHERE id = row.id

    COMMIT
```

### Manual Step 6 — `migrate-encryption --verify` または `verify-encryption.sh` で検証

> **legacy smoke test の sample-only verification limitation (M5 #53 F92)**
>
> `verify-encryption.sh` (`decrypt-test` 経由) は **`LIMIT 1` かつ
> `ORDER BY` なしで単一行だけを sample** する。 multi-tenant DB や複数行を
> 持つ table では、 Step 2.5 と Step 6 が別の行を sample する可能性がある。
> そのため digest の一致は、 ある 1 行が key をまたいで一貫して復号できた
> ことだけを示し、 **全 encrypted row が recoverable であることは証明しない**。
>
> production rotation の推奨 posture:
>
> 1. `migrate-encryption --verify --report-input <dry-run-report>` を優先する。
> 2. staging に production tenant を全て import して rotation を rehearse する。
> 3. legacy smoke test しか使えない場合は sample-only signal として扱う。
> 4. post-rotation は旧鍵 destroy 前に 24-48h、 application log の
>    `decrypt failed` error を監視する。

Step 5 で DB を書き換えた後、 `NEW_KEY` で §4 の検証チェックを実行する。

```bash
./docker/scripts/verify-encryption.sh \
    --key-file docker/secrets/encryption_key.txt \
    --db-url "$DATABASE_URL" \
    | tee after-rotation-hash.txt
```

`after-rotation-hash.txt` の SHA256 plaintext hash を、 Step 2.5 で記録した
旧鍵 hash と比較する。

```bash
diff -u \
    <(sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p' before-rotation-hash.txt) \
    <(sed -n 's/.*sha256=\([0-9a-f]\{64\}\).*/\1/p' after-rotation-hash.txt)
```

同じ logical secret なら hash は一致する必要がある。 plaintext 自体は絶対に
出力しない。 post-rotation check を `OLD_KEY` で実行しないこと。 Step 5 後の
DB ciphertext は `NEW_KEY` だけで復号できるのが正常。
この smoke test は sample-only なので、 hash 一致は完全な row coverage では
なく mitigation signal として扱う。 完全な per-row check は automation の
`--verify` mode を使う。

### Manual Step 7 — 保持期間後に旧鍵を destroy

`OLD_KEY` はこの maintenance window で承認された保持期間だけ保持する。 §4 が
pass し rollback window が閉じたら、 旧 `.env` snapshot、 Docker Secret
version、 KMS version、 旧鍵を含む operator shell state を削除する。

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
   `401 Unauthorized` が返る場合、 §3 step 5 の再暗号化でその行が skip
   されたか壊れたかなので、 §2.2 のスナップショットから復旧してやり直す。

4. **BYOK LLM provider** — 非 Ollama の LLM provider に tenant 独自 API key を
   設定していた各 tenant で、 AI VEX triage または CRA draft 生成 path を実行
   する。 provider resolution が新鍵で `tenant_llm_config.encrypted_api_key`
   を復号できること。 decrypt error が出る場合、 その tenant の BYOK key が
   §3 で skip されたか壊れている。

5. **アプリケーションログ** — `docker compose logs api` で
   `failed to decrypt`、 `cipher: message authentication failed`、
   `ciphertext too short` 等のエラーが出ていないこと。 これらは
   再暗号化されなかった行が新鍵下では復元不能になっていることを示す。

6. **`verify-encryption.sh` smoke test** — 専用の decrypt round-trip CLI
   (M5-5、 issue [#53](https://github.com/youichi-uda/sbomhub/issues/53))
   を実行し、 新鍵が DB layer で再暗号化済み ciphertext を実際に復号できる
   ことを確認する。

   ```bash
   ENCRYPTION_KEY="$(cat docker/secrets/encryption_key.txt)" \
   ./docker/scripts/verify-encryption.sh \
       --db-url "$DATABASE_URL"
   ```

   file 経由の同等 invocation:

   ```bash
   ./docker/scripts/verify-encryption.sh \
       --key-file docker/secrets/encryption_key.txt \
       --db-url "$DATABASE_URL"
   ```

   success 時は `ok ... sha256=<hex>` を出力する。 失敗時は exit code で分類
   する。

   | exit | 意味 |
   |---|---|
   | 0 | 新鍵で sample row を復号できた (rotation はここまで OK) |
   | 1 | 鍵不一致 / ciphertext 破損 — traffic 再開前に調査 |
   | 2 | DB error (DSN, role 権限不足) |
   | 3 | 検証対象の encrypted row 不在 (BYOK / integration 未設定) |
   | 64 | usage error (flag / 引数不正) |
   | 65 | 事前準備不足 (Go toolchain / `DECRYPT_TEST_BIN`) |

   同じ logical secret の round-trip を旧鍵と新鍵で確認する場合 (推奨 sanity
   check)、 §3 Step 2.5 で記録した旧鍵 digest と、この post-rotation check
   で出した新鍵 digest を比較する。 出力される SHA256 hash は一致する必要が
   ある。 plaintext 自体は出力されない。 legacy な `--key` argv path は互換性
   のため受け付けるが、 command-line arguments は `ps` / procfs 経由で露出し
   やすいため deprecated。 default smoke target は
   `tenant_llm_config.encrypted_api_key`。 issue tracker token を spot check
   する場合は `--table issue_tracker_connections --column auth_token_encrypted`
   を渡す。

   full operator contract は
   [`security/self-host-deployment.md`](./security/self-host-deployment.md) §4.5
   を参照。

---

## 5. ロールバック

§3 step 5 (再暗号化) が途中で失敗、 または §4 で再起動後にデータ欠損を
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

§3 step 1 に「旧鍵がない」 状態で到達した場合 — 例: 前回 `.env` を破壊した
インシデント復旧 — 既存 ciphertext は復号できない。 現実的な復旧は以下:

1. 新規 `ENCRYPTION_KEY` を §3 step 3 でセット。
2. 影響する暗号化済み credential を消す:
   影響 tenant の `tenant_llm_config.encrypted_api_key` を `NULL` にし、
   `TRUNCATE issue_tracker_connections;` (または、 どのテナントを実際に
   消したいか特定できるならテナント毎に `DELETE`)。
3. 影響テナントへ BYOK LLM API key と Jira / Backlog 連携を設定画面 /
   インテグレーション画面から再入力するよう通知。 secret を貼り直すと、
   新鍵で暗号化される。

これは BYOK LLM key と連携トークンを犠牲にするが、 他のテナント成果物 (SBOM、
vulnerabilities、 VEX、 監査ログ等) はそもそも `ENCRYPTION_KEY` を使わない
ので維持される。

---

## 7. スケジュール推奨

| トリガー | サイクル | 備考 |
| --- | --- | --- |
| 定期ローテーション | 90 日ごと | カレンダーリマインダで十分。 ステージング環境があれば事前にリハーサル推奨。 |
| インシデント (鍵漏洩) | 即時 | 全 BYOK LLM API key と `issue_tracker_connections` トークンを露出済みとして扱う; マスター鍵ローテーションは流出済み平文を無効化しない。 ローテーション後、 影響テナントには上流 LLM provider と Jira / Backlog トークンも回すよう案内。 |
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

## 自動化実装

M6 issue [#56](https://github.com/youichi-uda/sbomhub/issues/56) で
turnkey rotation binary を
[`apps/api/cmd/migrate-encryption`](../apps/api/cmd/migrate-encryption) に実装済み。
実装 commit: `50be30f` (`feat(api): migrate-encryption rotation CLI (M6 #56)`)。

binary は env-only の `OLD_ENCRYPTION_KEY` / `NEW_ENCRYPTION_KEY` を使い、
production の LLM / issue tracker 暗号化 helper を import する。 tenant ごとに
`app.current_tenant_id` を bind し、 JSON digest report を出力し、
`--dry-run`、 `--apply`、 `--verify`、 `--resume-from`、 `--batch-size`、
`--continue-on-error` をサポートする。 operator flow は §3 を source of truth
として扱う。
