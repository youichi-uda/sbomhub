# CRA 第14条 最終報告 (Final Report)

> **法的注記**
> 本文書は SBOMHub による下書きであり、最終的な確認・承認は事業者が行うものとします。
> SBOMHub は提出支援のためのドラフト生成を行いますが、法的助言を提供するものではありません。
> 最終報告の提出可否、提出先 (欧州 CSIRT / ENISA / 関連当局) の判断は、事業者の責任者が決定してください。

## 1. 報告区分

- **報告種別**: CRA 第14条(2)(c) 最終報告 (Final Report)
- **対象期限**: 是正措置の完了後、可及的速やかに
- **言語**: 日本語
- **関連早期警告 ID**: SBH-CRA-2026-0001
- **関連詳細通知 ID**: SBH-CRA-2026-0002

## 2. 製品情報

- **製品名**: SmartGateway-X1
- **製品バージョン**: 1.4.2
- **製造業者**: Example Manufacturing Co., Ltd.

## 3. 脆弱性 (確定情報)

- **CVE ID**: CVE-2026-12345
- **CVSS スコア**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **重大度**: Critical
- **確定した技術的説明**:

An attacker can craft a malformed CONNECT packet that triggers a buffer overflow in the MQTT broker module, leading to remote code execution as root on the gateway device.

### 確定根本原因
Missing length validation on the client identifier field in libmosquitto 2.0.14 (CVE-2026-12345).

## 4. 恒久対応 (Permanent Remediation)

Firmware 1.4.3 has been released and shipped to 100% of fleet via OTA as of 2026-07-02. libmosquitto upgraded to 2.0.15; defensive length validation added to smartgw-mqtt-bridge 1.4.3.

## 5. 修正バージョン (Released Fixed Versions)

| 修正バージョン | リリース日 | 配布チャネル |
|---|---|---|
| 1.4.3 | 2026-06-26 | OTA + manufacturer download portal |
| 1.5.0 | 2026-07-15 | OTA |


### 影響コンポーネントと修正状況

| コンポーネント | 影響バージョン | 修正バージョン |
|---|---|---|
| libmosquitto | 2.0.14 | 2.0.15 |
| smartgw-mqtt-bridge | 1.4.2 | 1.4.3 |


## 6. 再発防止 (Prevention of Recurrence)

1. Add libmosquitto to the SBOM watchlist with a 24h SLA on new CVEs.
2. Enforce a fuzzing gate on the MQTT bridge in CI.
3. Adopt the secure-by-default firewall profile so MQTT is closed unless explicitly enabled.


## 7. ユーザー通知 (User Notification)

End-user advisory PSIRT-2026-007 was published in Japanese and English on 2026-06-23. Direct email notification was sent to all registered fleet operators on the same day.

## 8. 対応タイムライン

- **2026-06-22T08:30:00Z**: Awareness: PoC observed on public exploit site.
- **2026-06-23T07:00:00Z**: Early warning submitted to CSIRT.
- **2026-06-25T07:00:00Z**: Detailed notification submitted.
- **2026-06-26T00:00:00Z**: Firmware 1.4.3 released.
- **2026-07-02T12:00:00Z**: 100% fleet OTA coverage reached.
- **2026-07-05T09:00:00Z**: Final report submitted.


## 9. 報告者情報

- **報告者氏名**: Taro Yamada
- **役職**: PSIRT Lead
- **連絡先メール**: psirt@example.co.jp
- **連絡先電話**: +81-3-1234-5678

## 10. 提出メタ情報

- **提出日時 (UTC)**: 2026-06-23T07:00:00Z
- **当初認識日時 (UTC)**: 2026-06-22T08:30:00Z
- **是正完了日時 (UTC)**: 2026-07-02T12:00:00Z
- **報告 ID (社内管理)**: SBH-CRA-2026-0001

---

_本書は SBOMHub (SBOMHub v0.9.0 (test fixture)) により 2026-06-23T07:00:00Z に生成された下書きです。_
_提出前に事業者の最終確認・承認を経てください。_
