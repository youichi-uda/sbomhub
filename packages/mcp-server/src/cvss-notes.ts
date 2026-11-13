// What every tool whose payload carries `cvss_score` says about the
// `cvss_version` the API returns beside it.
//
// apps/api records which CVSS version a vulnerability's score and severity
// were taken from (M67, migration 069: v3.1 > v3.0 > v4.0 > v2) and publishes
// it as `cvss_version` next to `cvss_score` on every read that returns the
// score (M71, then the dashboard Top Risks). This server passes the backend
// payload through unchanged (z.looseObject in client/api.ts), so the field
// reaches the model — but a model that is not told what it means reads a v2
// 7.5 and a v3.1 7.5 as the same claim.
//
// Stated once and shared, for the reason SCOPE_NOTE is: a per-tool rewording is
// a per-tool opportunity to describe a field the tool does not return.
// test/tool-contract.test.mjs asserts that
//   (1) CVSS_VERSIONS equals the canonical versions in
//       apps/api/internal/cvss/select.go (the only values the column can hold),
//   (2) every tool observed returning cvss_score embeds CVSS_VERSION_NOTE
//       verbatim, and no other tool does, and
//   (3) cvss_version reaches the tool result unchanged, including when it is
//       present without cvss_score.

// The canonical values of vulnerabilities.cvss_version (cvss.V31 / V30 / V40 /
// V2), in the preference order the backend selects by.
export const CVSS_VERSIONS = ["3.1", "3.0", "4.0", "2.0"] as const;

export const CVSS_VERSION_NOTE =
  "cvss_score の横の cvss_version は、そのスコアと severity を取ったCVSSのバージョン " +
  `(${CVSS_VERSIONS.map((v) => `"${v}"`).join(" / ")})。` +
  "バージョンが不明なときは cvss_version が省略される。" +
  "cvss_score が無くても cvss_version だけが返ることがある " +
  "(評価はあるが使えるスコアが無い場合)。" +
  "バージョンの違うスコアは算出方式が異なるため、同じ尺度の値として比較しないこと";
