# 045 遅延 FK 制約の VALIDATE 手順

> `docker/scripts/validate-deferred-constraints.sh` の運用 runbook。
> English: [`validate-deferred-constraints.md`](./validate-deferred-constraints.md)。

## 1. 背景

マイグレーション
[`apps/api/migrations/045_composite_fk_extension.up.sql`](../../apps/api/migrations/045_composite_fk_extension.up.sql)
は、 legacy な project-child 7 テーブルに対して
`(tenant_id, project_id) → projects(tenant_id, id)` の複合 FK 制約を追加する。

| テーブル | 制約名 |
| --- | --- |
| `sboms` | `sboms_tenant_project_fk` |
| `vex_statements` | `vex_statements_tenant_project_fk` |
| `license_policies` | `license_policies_tenant_project_fk` |
| `notification_settings` | `notification_settings_tenant_project_fk` |
| `notification_logs` | `notification_logs_tenant_project_fk` |
| `public_links` | `public_links_tenant_project_fk` |
| `vulnerability_tickets` | `vulnerability_tickets_tenant_project_fk` |

これら 7 制約は `NOT VALID` で導入されている (M8 F157, commit
[`9367702`](https://github.com/youichi-uda/sbomhub/commit/9367702))。
理由: マイグレーション apply 中の FK 検証スキャンは FORCE ROW LEVEL
SECURITY 配下で走るが、 該当する RLS ポリシー (012/013/014/015/021) は
`current_setting('app.current_tenant_id')` を `missing_ok=true` なしで呼ぶ
ため、 GUC 未設定状態でスキャンが crash する
(より広い背景は [F156](https://github.com/youichi-uda/sbomhub/commit/047a21e))。

`NOT VALID` はインストール時の全表スキャンを skip する一方で、
**以降の全ての write には制約が効く**。 さらに 045 Step 3 の `DO $$` ブロックが
既存 tenant_id 不整合に対して `RAISE` するため、 インストール時点で既存データは
事実上 pre-validate されている。 残るのは `pg_constraint.convalidated` を
`f` から `t` に切り替えるだけ。

`docker/scripts/validate-deferred-constraints.sh` がそれを単一トランザクションで
行う。 045 の Step 1 / Step 5 と同じ構造で、 7 child テーブル + 親 `projects` の
RLS を一時的に `NO FORCE` + `DISABLE` した上で 7 制約を全表スキャンで
`VALIDATE` し、 元の RLS posture を snapshot から復元する。

> **なぜ per-tenant `SET LOCAL app.current_tenant_id` ループにしないのか?**
> `public_links` はマイグレーション 030 で RLS が外されているので `VALIDATE` は
> 全行を見るが、 親 `projects` への FK 参照は **依然 RLS で filter される**。
> 結果、 GUC の tenant 以外が owner の行が「親が存在しない」 という偽陽性
> FK 違反になる。 また RLS 配下の `VALIDATE` はセッションから可視な subset
> しか確認しないため、 整合性保証も不完全になる。 DDL で RLS を一時 lift する
> 方式なら `ACCESS EXCLUSIVE` ロックが掛かるため並行 reader からは lift 状態が
> 観測されず、 全行が検証される。

## 2. 実行タイミング

- **マイグレーション 045 を含む初回デプロイ直後。** M8 F157 以降は検証が
  deferred なため、 新規インストールでは 7 制約とも `convalidated=false` の
  ままになる。 このスクリプトを 1 回走らせて `t` に flip する。
- **定期 (例: 毎月の保守時間枠)。** スクリプトは冪等で、 既に
  `convalidated=true` の制約に対する `VALIDATE` は PostgreSQL の中で
  metadata-only な no-op になるため、 定期再実行はコストが低く、 運用ログ
  上に制約状態が可視に残る利点がある。
- **bulk import / 他 SBOM ストアからの移行直後。** 外部 ETL が
  アプリの tenant スコープを bypass して child テーブルに直接書く場合、
  クロステナント整合性を確認する canonical な手段になる。
- **CRA / METI 監査の前。** `convalidated=true` は
  `(tenant_id, project_id)` invariant を満たすことの PostgreSQL レベルの
  証跡として機能する。

## 3. 実行時間の目安

`VALIDATE` は全表シーケンシャルスキャンで FK を確認する。 テーブル別のコスト感:

- `sboms` / `vex_statements` / `vulnerability_tickets` は project 活動に
  比例 (普通は最大級)
- `notification_logs` は append-only。 retention が長いと行数最大
- `license_policies` / `notification_settings` / `public_links` は通常小さい

目安として、 7 テーブル合計 `<100k` 行のインストールであれば **1 分以内**
で完了する。 最大テーブルの行数にほぼ線形にスケールする。 DDL トランザクションは
8 テーブル (7 child + `projects`) に `ACCESS EXCLUSIVE` ロックを取るので、
`notification_logs` が数百万行を超える環境では保守時間枠での実行を推奨。

## 4. 実行方法

スクリプトは migrator DSN を `MIGRATE_DATABASE_URL` (推奨) から読む。
未設定の場合、 リポジトリ root の `.env` から共有ヘルパ `read_env_var`
経由で fall-back する。

```bash
export MIGRATE_DATABASE_URL="postgres://sbomhub_migrator:PASSWORD@localhost:5432/sbomhub?sslmode=disable"
./docker/scripts/validate-deferred-constraints.sh
```

DSN は **migrator ロール** (DDL 可能、 `NOT BYPASSRLS`、 8 テーブルの owner
— Enterprise compose では `sbomhub_migrator`) を指している必要がある。
アプリ runtime ロール (`sbomhub_app`、 `NOSUPERUSER`、 `NOBYPASSRLS`) は DDL 権限を
持たないため、 最初の `ALTER TABLE` で失敗する。

`psql` バイナリは `PSQL` 環境変数で上書き可能 (例: コンテナ化された psql):

```bash
PSQL="docker run --rm -i --network host postgres:15-alpine psql" \
    MIGRATE_DATABASE_URL="postgres://..." \
    ./docker/scripts/validate-deferred-constraints.sh
```

## 5. 終了コード

| Code | 意味 |
| --- | --- |
| 0 | 7 制約すべて `convalidated=true`。 成功。 |
| 1 | 1 つ以上の制約が `convalidated=false` のままになった。 違反している制約名と、 初回失敗 FK プローブの `(tenant_id, project_id)` を出力する。 §6 参照。 |
| 2 | 前提不足: `psql` が PATH にない、 `MIGRATE_DATABASE_URL` 未設定、 DB 接続失敗、 ロールが DDL 権限を持たない、 8 テーブルのいずれかが存在しない、 等。 |

## 6. 失敗時 (`exit 1`) の対応

スクリプト完了後に `convalidated=false` が残るのは、 **実データに
クロステナント整合性違反がある** ことを意味する。 制約述語が
`(tenant_id, project_id)` が同 tenant の `projects` 行と対応しない child 行を
正しく検出している、 ということ。

スクリプトは以下を出力する:

- `VALIDATE` に失敗した制約名
- PostgreSQL の `DETAIL:` 行に含まれる、 違反している `(tenant_id,
  project_id)` ペア (PG はスキャンを最初の違反でアボートするので、 一度に
  1 件しか報告されない)

**自動 DELETE は禁止。** 適切な次手は、 マイグレーション 045 Step 3 に
埋め込まれている inspect クエリ
(`apps/api/migrations/045_composite_fk_extension.up.sql` を
`Inspect with:` で grep) を使って違反行を手動確認することである。

例: `sboms` の orphan 検出:

```sql
SELECT s.id, s.tenant_id AS child_tenant, s.project_id,
       p.tenant_id AS parent_tenant
FROM sboms s
LEFT JOIN projects p ON p.id = s.project_id
WHERE s.tenant_id IS NULL
   OR p.id IS NULL
   OR p.tenant_id IS NULL
   OR p.tenant_id <> s.tenant_id;
```

その上でデータ owner と相談して remediation を決める (典型的には: 失われた
親 project を復元する、 または child 行を正しい tenant に reassign する)。
remediation が済んだら本スクリプトを再実行する。

スクリプトのトランザクションは **atomic**。 `VALIDATE` が raise した場合、
lift 状態の RLS は自動 ROLLBACK される。 permissive な RLS posture の
テーブルは残らない。

## 7. 関連リンク

- マイグレーション本体: [`apps/api/migrations/045_composite_fk_extension.up.sql`](../../apps/api/migrations/045_composite_fk_extension.up.sql)
- M8 F157 fix commit: [`9367702`](https://github.com/youichi-uda/sbomhub/commit/9367702)
- M10-1 issue: [#70](https://github.com/youichi-uda/sbomhub/issues/70)
- RLS posture リファレンス: マイグレーション 023 (FORCE RLS install)、 030 (public_links RLS 撤去)
- 運用スクリプト: [`docker/scripts/validate-deferred-constraints.sh`](../../docker/scripts/validate-deferred-constraints.sh)
