# CRA 第14条 早期警告 (24時間以内通知)

> **法的注記**
> 本文書は SBOMHub による下書きであり、最終的な確認・承認は事業者が行うものとします。
> SBOMHub は提出支援のためのドラフト生成を行いますが、法的助言を提供するものではありません。
> 24時間カウントの起点判断、および欧州 CSIRT / ENISA への提出可否は、事業者の責任者が決定してください。

## 1. 報告区分

- **報告種別**: CRA 第14条(2)(a) 早期警告 (Early Warning)
- **対象期限**: 認識後 24 時間以内
- **言語**: 日本語

## 2. 製品情報

- **製品名**: SmartGateway-X1
- **製品バージョン**: 1.4.2
- **製造業者**: Example Manufacturing Co., Ltd.

## 3. 脆弱性概要

- **CVE ID**: CVE-2026-12345
- **CVSS スコア**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **重大度**: Critical
- **脆弱性の概要**:

Remote code execution via unauthenticated MQTT broker handler.

## 4. 悪用状況 (Exploitation Status)

- **悪用状況の判定**: Actively exploited in the wild
- **CISA KEV 収載**: はい
- **EPSS スコア**: 0.94
- **悪用の根拠**:

Vendor SOC observed scanning campaigns targeting affected MQTT port from 2026-06-20 onward; PoC published on a public exploit site on 2026-06-22.

## 5. 暫定影響範囲 (Preliminary Impact Scope)

All SmartGateway-X1 units shipped between 2024-Q1 and 2026-Q2 with firmware 1.0.0 through 1.4.2 inclusive.


### 暫定影響コンポーネント


- libmosquitto (バージョン: 2.0.14) `pkg:generic/libmosquitto@2.0.14`
- smartgw-mqtt-bridge (バージョン: 1.4.2) `pkg:generic/smartgw-mqtt-bridge@1.4.2`


## 6. 現時点で講じた緩和措置 (Immediate Mitigations)

Disable inbound MQTT (port 1883) at the device firewall until firmware 1.4.3 is installed.

## 7. 報告者情報

- **報告者氏名**: Taro Yamada
- **役職**: PSIRT Lead
- **連絡先メール**: psirt@example.co.jp
- **連絡先電話**: +81-3-1234-5678

## 8. 提出メタ情報

- **提出日時 (UTC)**: 2026-06-23T07:00:00Z
- **認識日時 (UTC, 24h カウント起点)**: 2026-06-22T08:30:00Z
- **報告 ID (社内管理)**: SBH-CRA-2026-0001

---

_本書は SBOMHub (SBOMHub v0.9.0 (test fixture)) により 2026-06-23T07:00:00Z に生成された下書きです。_
_提出前に事業者の最終確認・承認を経てください。_
