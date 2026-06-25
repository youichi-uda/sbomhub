# CRA 第14条 詳細通知 (72時間以内通知)

> **法的注記**
> 本文書は SBOMHub による下書きであり、最終的な確認・承認は事業者が行うものとします。
> SBOMHub は提出支援のためのドラフト生成を行いますが、法的助言を提供するものではありません。
> 72時間カウントの起点判断、および欧州 CSIRT / ENISA への提出可否は、事業者の責任者が決定してください。

## 1. 報告区分

- **報告種別**: CRA 第14条(2)(b) 詳細通知 (Detailed Notification)
- **対象期限**: 認識後 72 時間以内
- **言語**: 日本語
- **関連早期警告 ID**: SBH-CRA-2026-0001

## 2. 製品情報

- **製品名**: SmartGateway-X1
- **製品バージョン**: 1.4.2
- **製造業者**: Example Manufacturing Co., Ltd.

## 3. 脆弱性詳細

- **CVE ID**: CVE-2026-12345
- **CVSS スコア**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **重大度**: Critical
- **技術的説明**:

An attacker can craft a malformed CONNECT packet that triggers a buffer overflow in the MQTT broker module, leading to remote code execution as root on the gateway device.

### 根本原因
Missing length validation on the client identifier field in libmosquitto 2.0.14 (CVE-2026-12345).

## 4. 影響コンポーネント (Affected Components)

| コンポーネント | 影響バージョン | 修正バージョン | PURL |
|---|---|---|---|
| libmosquitto | 2.0.14 | 2.0.15 | `pkg:generic/libmosquitto@2.0.14` |
| smartgw-mqtt-bridge | 1.4.2 | 1.4.3 | `pkg:generic/smartgw-mqtt-bridge@1.4.2` |


## 5. 対象バージョン (Affected Product Versions)

- 1.0.0
- 1.1.0
- 1.2.0
- 1.3.0
- 1.4.0
- 1.4.1
- 1.4.2


## 6. 緩和策 (Mitigation Steps)

1. Block inbound TCP port 1883 at the perimeter firewall.
2. Disable the MQTT broker on the device via the admin console (Settings > Services > MQTT > Disable).
3. Rotate any device credentials that may have been exposed.


## 7. 是正予定 (Remediation Plan)

Firmware 1.4.3 patches libmosquitto to 2.0.15 and adds input length validation in the MQTT bridge. Staged rollout begins 2026-06-26.

### 修正版リリース予定

| 修正バージョン | リリース予定日 | 配布チャネル |
|---|---|---|
| 1.4.3 | 2026-06-26 | OTA + manufacturer download portal |
| 1.5.0 | 2026-07-15 | OTA |


## 8. 悪用状況の更新

- **悪用状況の判定**: Actively exploited in the wild
- **悪用の根拠**:

Vendor SOC observed scanning campaigns targeting affected MQTT port from 2026-06-20 onward; PoC published on a public exploit site on 2026-06-22.

## 9. 報告者情報

- **報告者氏名**: Taro Yamada
- **役職**: PSIRT Lead
- **連絡先メール**: psirt@example.co.jp
- **連絡先電話**: +81-3-1234-5678

## 10. 提出メタ情報

- **提出日時 (UTC)**: 2026-06-23T07:00:00Z
- **認識日時 (UTC, 72h カウント起点)**: 2026-06-22T08:30:00Z
- **報告 ID (社内管理)**: SBH-CRA-2026-0001

---

_本書は SBOMHub (SBOMHub v0.9.0 (test fixture)) により 2026-06-23T07:00:00Z に生成された下書きです。_
_提出前に事業者の最終確認・承認を経てください。_
