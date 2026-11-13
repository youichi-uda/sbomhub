// M70 distro labels: the badge / evidence mapping (src/lib/match-method.ts).
//
// Run: pnpm --filter web test
//
// What is pinned and why:
//   - only the three distro methods produce a badge or an evidence view; the
//     M60 NVD / JVN labels are not touched by this mapping;
//   - distro_fixed is a "review" badge, never an "affected" or resolved one,
//     and never suggests an upgrade (it is not not_affected, UPGRADE.md §21);
//   - "upgrade to <fixed>" appears only for distro_affected with a fixed
//     version; distro_unfixed has none by definition;
//   - basis = later_releases raises the end-of-life inference caveat;
//   - OSV record links are built only from id-shaped tokens and encoded, so
//     evidence text can never become an arbitrary href;
//   - evidence that is absent or malformed degrades to "no evidence" and
//     the badge still shows (a label is never hidden for lack of evidence).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";

import {
  distroBadge,
  distroEvidenceView,
  findingMatchBadge,
  isNvdMatchMethod,
  isDistroMatchMethod,
  osvRecordUrl,
  parseDistroEvidence,
} from "../match-method.ts";

const affectedEv = {
  source: "osv",
  status: "affected",
  basis: "release",
  release: "Debian:12",
  package: "openssl",
  installed: "3.0.11-1~deb12u1",
  fixed: "3.0.11-1~deb12u2",
  records: ["DEBIAN-CVE-2023-5678", "DSA-5532-1"],
  fetched_at: "2026-11-10T00:00:00Z",
  source_url: "https://api.osv.dev",
  data_modified: "2026-11-09T12:00:00Z",
};

const fixedLaterEv = {
  source: "osv",
  status: "fixed",
  basis: "later_releases",
  release: "Debian:11",
  ecosystems: ["Debian:12", "Debian:13"],
  package: "openssl",
  installed: "1.1.1n-0+deb11u5",
  fixed: "1.1.1k-1",
  records: ["DEBIAN-CVE-2021-3449"],
  fetched_at: "2026-11-10T00:00:00Z",
};

describe("isDistroMatchMethod", () => {
  test("accepts exactly the three M70 labels", () => {
    for (const m of ["distro_affected", "distro_unfixed", "distro_fixed"]) {
      assert.equal(isDistroMatchMethod(m), true, m);
    }
    for (const m of [
      "nvd_cpe",
      "nvd_cpe_distro",
      "nvd_cpe_unverified",
      "nvd_keyword",
      "jvn_keyword",
      "cve_sync_keyword",
      "",
      undefined,
      null,
      "distro_other",
    ]) {
      assert.equal(isDistroMatchMethod(m), false, String(m));
    }
  });
});

describe("distroBadge", () => {
  test("distro_affected with a fixed version says upgrade to it", () => {
    assert.deepEqual(distroBadge("distro_affected", affectedEv), {
      method: "distro_affected",
      tone: "affected",
      label: "distroAffectedUpgrade",
      upgradeTo: "3.0.11-1~deb12u2",
    });
  });

  test("distro_affected without a usable fixed version is a plain affected badge", () => {
    for (const ev of [
      undefined, null, {}, { fixed: "" }, { fixed: "   " }, { fixed: 3 }, "x", [],
      // Codex R2 Medium-1: a fixed version outside coherent evidence (no
      // status / release / records, or a contradicting status) is not advice.
      { fixed: "9.9.9" },
      { ...affectedEv, status: "fixed" },
      { ...affectedEv, records: [] },
      // Codex R3 Low-1: no package / installed version
      { status: "affected", release: "Debian:12", records: ["DSA-1"], fixed: "9999.0" },
      { ...affectedEv, installed: undefined },
      { ...affectedEv, package: undefined },
      // Codex R4 Low-1: basis missing or outside the vocabulary
      { ...affectedEv, basis: undefined },
      { ...affectedEv, basis: "guess" },
    ]) {
      assert.deepEqual(
        distroBadge("distro_affected", ev),
        { method: "distro_affected", tone: "affected", label: "distroAffected" },
        JSON.stringify(ev),
      );
    }
  });

  test("distro_unfixed is high-confidence affected and never offers an upgrade", () => {
    // Even if a stray fixed value were present, unfixed has no fix released.
    assert.deepEqual(distroBadge("distro_unfixed", { ...affectedEv, status: "unfixed" }), {
      method: "distro_unfixed",
      tone: "affected",
      label: "distroUnfixed",
    });
  });

  test("distro_fixed is a review badge, not resolved, and never an upgrade hint", () => {
    const b = distroBadge("distro_fixed", fixedLaterEv);
    assert.deepEqual(b, { method: "distro_fixed", tone: "review", label: "distroFixed" });
    assert.equal(b.upgradeTo, undefined);
  });

  test("non-distro methods produce no badge (NVD labels untouched)", () => {
    for (const m of ["nvd_cpe", "nvd_cpe_unverified", "nvd_keyword", "jvn_keyword", "", undefined]) {
      assert.equal(distroBadge(m, affectedEv), null, String(m));
    }
  });
});

describe("osvRecordUrl", () => {
  test("links OSV-shaped ids", () => {
    assert.equal(
      osvRecordUrl("DEBIAN-CVE-2021-3449"),
      "https://osv.dev/vulnerability/DEBIAN-CVE-2021-3449",
    );
    assert.equal(osvRecordUrl("ALSA-2023:1234"), "https://osv.dev/vulnerability/ALSA-2023%3A1234");
    assert.equal(osvRecordUrl("UBUNTU-CVE-2023-5678"), "https://osv.dev/vulnerability/UBUNTU-CVE-2023-5678");
  });

  test("refuses anything that is not an id token", () => {
    for (const id of [
      "",
      "javascript:alert(1)x y",
      "../../etc",
      "a/b",
      "x?y=1",
      "id#frag",
      " DSA-1",
      "-leading-dash",
      "a".repeat(129),
      "<script>",
    ]) {
      assert.equal(osvRecordUrl(id), null, id);
    }
  });
});

describe("parseDistroEvidence", () => {
  test("non-objects are no evidence", () => {
    for (const raw of [undefined, null, "x", 1, [], true]) {
      assert.equal(parseDistroEvidence(raw), null, String(raw));
    }
  });

  test("drops wrong-typed fields and de-duplicates lists", () => {
    const ev = parseDistroEvidence({
      release: 11,
      basis: "release",
      records: ["A-1", "A-1", 2, "", "B-2"],
      ecosystems: "Debian:12",
    });
    assert.equal(ev.release, undefined);
    assert.equal(ev.basis, "release");
    assert.deepEqual(ev.records, ["A-1", "B-2"]);
    assert.deepEqual(ev.ecosystems, []);
  });
});

describe("distroEvidenceView", () => {
  test("release basis: records linked, no end-of-life caveat", () => {
    const v = distroEvidenceView("distro_affected", affectedEv);
    assert.equal(v.hasEvidence, true);
    assert.equal(v.release, "Debian:12");
    assert.equal(v.basis, "release");
    assert.equal(v.inferredFromLaterReleases, false);
    assert.equal(v.fixed, "3.0.11-1~deb12u2");
    assert.deepEqual(v.records, [
      { id: "DEBIAN-CVE-2023-5678", url: "https://osv.dev/vulnerability/DEBIAN-CVE-2023-5678" },
      { id: "DSA-5532-1", url: "https://osv.dev/vulnerability/DSA-5532-1" },
    ]);
  });

  test("later_releases basis raises the caveat and lists the deciding releases", () => {
    const v = distroEvidenceView("distro_fixed", fixedLaterEv);
    assert.equal(v.hasEvidence, true);
    assert.equal(v.inferredFromLaterReleases, true);
    assert.deepEqual(v.laterReleases, ["Debian:12", "Debian:13"]);
    assert.equal(v.release, "Debian:11");
  });

  test("an id that is not a token is kept as text without a link", () => {
    const v = distroEvidenceView("distro_unfixed", { status: "unfixed", basis: "release", release: "Debian:12", package: "p", installed: "1-1", records: ["DSA-1", "bad id"] });
    assert.deepEqual(v.records, [
      { id: "DSA-1", url: "https://osv.dev/vulnerability/DSA-1" },
      { id: "bad id", url: null },
    ]);
  });

  test("a distro label without evidence still yields a view that says so", () => {
    assert.deepEqual(distroEvidenceView("distro_fixed", undefined), {
      method: "distro_fixed",
      hasEvidence: false,
      inferredFromLaterReleases: false,
      laterReleases: [],
      records: [],
      publicOsv: false,
    });
  });

  // Codex R1 Low-1: an object that is not recognisably DistroEvidence is
  // "no evidence", not a table of dashes.
  test("an empty or incoherent evidence object reads as no evidence", () => {
    for (const ev of [
      {},
      { release: "Debian:12" },
      { status: "fixed", records: ["DSA-1"] },
      { status: "bogus", release: "Debian:12", records: ["DSA-1"] },
      { status: "fixed", release: "Debian:12", records: [] },
    ]) {
      assert.equal(distroEvidenceView("distro_fixed", ev).hasEvidence, false, JSON.stringify(ev));
    }
  });

  // Codex R1 Medium-2: the reviewer sees which endpoint and data revision the
  // verdict used, and is told when the osv.dev links are not that endpoint.
  test("source endpoint and data revision are shown; non-public sources are flagged", () => {
    const pub = distroEvidenceView("distro_affected", affectedEv);
    assert.equal(pub.sourceUrl, "https://api.osv.dev");
    assert.equal(pub.dataModified, "2026-11-09T12:00:00Z");
    assert.equal(pub.publicOsv, true);


    const mirror = distroEvidenceView("distro_affected", { ...affectedEv, source_url: "https://osv.mirror.example" });
    assert.equal(mirror.sourceUrl, "https://osv.mirror.example");
    assert.equal(mirror.publicOsv, false);
  });

  // Codex R2 Medium-1: the evidence's status must be the label's own.
  test("evidence whose status contradicts the label is no evidence", () => {
    assert.equal(distroEvidenceView("distro_fixed", affectedEv).hasEvidence, false);
    assert.equal(distroEvidenceView("distro_affected", fixedLaterEv).hasEvidence, false);
    assert.equal(distroEvidenceView("distro_unfixed", affectedEv).hasEvidence, false);
    assert.equal(distroEvidenceView("distro_fixed", fixedLaterEv).hasEvidence, true);
  });

  // Codex R3 Low-1: a later_releases verdict names the releases that decided it.
  test("later_releases without deciding releases is no evidence", () => {
    assert.equal(distroEvidenceView("distro_fixed", { ...fixedLaterEv, ecosystems: [] }).hasEvidence, false);
    assert.equal(distroEvidenceView("distro_fixed", { ...fixedLaterEv, ecosystems: undefined }).hasEvidence, false);
  });

  // Codex R3 Low-2: equivalent spellings of the public origin are public.
  test("public OSV origin is compared after URL normalisation", () => {
    for (const u of ["https://api.osv.dev:443", "https://API.OSV.DEV", "https://api.osv.dev/"]) {
      assert.equal(distroEvidenceView("distro_affected", { ...affectedEv, source_url: u }).publicOsv, true, u);
    }
    for (const u of ["https://api.osv.dev:8443", "http://api.osv.dev", "https://api.osv.dev.evil.example", "configured-endpoint", "https://user@api.osv.dev",
      // Codex R4 Low-2: a blob: URL's origin is its inner origin
      "blob:https://api.osv.dev/0b6f0d0e-1111-2222-3333-444444444444"]) {
      assert.equal(distroEvidenceView("distro_affected", { ...affectedEv, source_url: u }).publicOsv, false, u);
    }
  });

  // Codex R2 Medium-2: only an explicit public endpoint is public.
  test("an absent endpoint is unknown, not public OSV", () => {
    const v = distroEvidenceView("distro_affected", { ...affectedEv, source_url: undefined });
    assert.equal(v.publicOsv, false);
    assert.equal(v.sourceUrl, undefined);
    assert.equal(distroEvidenceView("distro_affected", { ...affectedEv, source_url: "https://api.osv.dev/" }).publicOsv, true);
    assert.equal(distroEvidenceView("distro_affected", { ...affectedEv, source_url: "http://api.osv.dev" }).publicOsv, false);
  });

  test("non-distro methods have no evidence view", () => {
    assert.equal(distroEvidenceView("nvd_cpe", affectedEv), null);
  });
});

// Codex R1 Medium-1: the distro_fixed badge must lead with the review / still
// open state in both locales, so a list scan never reads it as resolved.
describe("distro_fixed badge wording", () => {
  const load = (loc) =>
    JSON.parse(readFileSync(new URL(`../../../messages/${loc}.json`, import.meta.url), "utf8")).MatchMethod;
  test("en leads with Review and says the finding stays open", () => {
    const m = load("en");
    assert.match(m.distroFixed, /^Review required/);
    assert.match(m.distroFixed, /still open/);
  });
  // Codex R3 Medium-1: the review note must not steer the reviewer to
  // not_affected (UPGRADE.md §21: distro_fixed is not not_affected).
  test("the review note does not prescribe not_affected", () => {
    for (const loc of ["en", "ja"]) {
      const m = load(loc);
      assert.doesNotMatch(m.distroFixedReview, /not_affected/, loc);
      assert.match(m.distroFixedReview, /fixed/, loc);
    }
  });
  test("ja leads with 要確認 and says the finding stays open", () => {
    const m = load("ja");
    assert.match(m.distroFixed, /^要確認/);
    assert.match(m.distroFixed, /未解決/);
  });
  test("both locales define the same keys", () => {
    assert.deepEqual(Object.keys(load("en")).sort(), Object.keys(load("ja")).sort());
  });
});

// M60 NVD / JVN labels: the confidence indicator (findingMatchBadge).
//
// What is pinned and why:
//   - the method -> confidence table is the API's own
//     (model.MatchMethod.Confidence, read from the Go source below, so the
//     two cannot drift apart silently);
//   - only a verified CPE match (nvd_cpe) is not marked for review; every
//     keyword / unverified / upstream-version / unknown match is;
//   - a disagreeing match_confidence can only LOWER the confidence shown;
//   - a pre-M60 link ("unknown") and a method this page does not know are
//     still shown (for review), never dropped;
//   - distro labels are left to distroBadge, and nothing is invented when
//     the API sent neither field.
describe("findingMatchBadge", () => {
  const goSource = readFileSync(
    new URL("../../../../api/internal/model/match_method.go", import.meta.url),
    "utf8",
  );
  const goConst = (name) => {
    const m = new RegExp(`\\b${name}\\s+(?:MatchMethod\\s+)?=\\s+"([^"]*)"`).exec(goSource);
    assert.ok(m, `constant ${name} not found in match_method.go`);
    return m[1];
  };
  // case A, B: return MatchConfidenceX  inside func (m MatchMethod) Confidence()
  const goConfidence = (() => {
    const body = goSource.slice(goSource.indexOf("func (m MatchMethod) Confidence() string"));
    const fn = body.slice(0, body.indexOf("\n}\n"));
    const out = {};
    for (const c of fn.matchAll(/case ([^:]+):\s*return (MatchConfidence\w+)/g)) {
      for (const name of c[1].split(",").map((x) => x.trim())) out[goConst(name)] = goConst(c[2]);
    }
    return out;
  })();

  test("mirrors model.MatchMethod.Confidence for every NVD / JVN method", () => {
    const nvd = Object.keys(goConfidence).filter((m) => !m.startsWith("distro_"));
    assert.deepEqual(
      nvd.sort(),
      ["cve_sync_keyword", "jvn_keyword", "nvd_cpe", "nvd_cpe_distro", "nvd_cpe_unverified", "nvd_keyword"],
    );
    for (const m of nvd) {
      assert.equal(isNvdMatchMethod(m), true, m);
      const b = findingMatchBadge(m, goConfidence[m]);
      assert.equal(b?.confidence, goConfidence[m], m);
      assert.equal(b?.method, m);
    }
  });

  test("only a verified CPE match is not marked for review", () => {
    assert.deepEqual(findingMatchBadge("nvd_cpe", "high"), {
      method: "nvd_cpe",
      confidence: "high",
      needsReview: false,
      label: "methodNvdCpe",
    });
    for (const [m, label] of [
      ["nvd_cpe_distro", "methodNvdCpeDistro"],
      ["nvd_cpe_unverified", "methodNvdCpeUnverified"],
      ["nvd_keyword", "methodNvdKeyword"],
      ["jvn_keyword", "methodJvnKeyword"],
      ["cve_sync_keyword", "methodCveSyncKeyword"],
    ]) {
      const b = findingMatchBadge(m, goConfidence[m]);
      assert.equal(b?.needsReview, true, m);
      assert.equal(b?.label, label, m);
    }
    assert.equal(findingMatchBadge("jvn_keyword", "low")?.confidence, "low");
    assert.equal(findingMatchBadge("nvd_cpe_distro", "medium")?.confidence, "medium");
  });

  test("a disagreeing API confidence only ever lowers the label", () => {
    assert.deepEqual(
      [findingMatchBadge("nvd_cpe", "low")?.confidence, findingMatchBadge("nvd_cpe", "low")?.needsReview],
      ["low", true],
    );
    assert.equal(findingMatchBadge("nvd_cpe", "unknown")?.confidence, "unknown");
    assert.equal(findingMatchBadge("nvd_keyword", "high")?.confidence, "low");
    assert.equal(findingMatchBadge("nvd_cpe_distro", "high")?.confidence, "medium");
  });

  // Codex R1 Low-1: an absent or unrecognised match_confidence must not
  // fail open to the method's maximum (a version-skewed or malformed
  // response would otherwise show "high confidence" with no review).
  test("an absent or unrecognised API confidence reads as unknown, for review", () => {
    for (const c of [undefined, null, "", "distro_fixed", "certain", "very_low", 3]) {
      const b = findingMatchBadge("nvd_cpe", c);
      assert.equal(b?.confidence, "unknown", String(c));
      assert.equal(b?.needsReview, true, String(c));
      assert.equal(b?.label, "methodNvdCpe");
    }
    assert.equal(findingMatchBadge("nvd_keyword", "certain")?.confidence, "unknown");
  });

  test("a pre-M60 link is shown as not recorded, for review", () => {
    for (const method of [undefined, null, "", "  "]) {
      assert.deepEqual(findingMatchBadge(method, "unknown"), {
        method: "",
        confidence: "unknown",
        needsReview: true,
        label: "methodNotRecorded",
      });
    }
  });

  test("neither field: nothing is invented", () => {
    assert.equal(findingMatchBadge(undefined, undefined), null);
    assert.equal(findingMatchBadge("", ""), null);
    assert.equal(findingMatchBadge(null, null), null);
  });

  test("distro labels are left to distroBadge", () => {
    for (const m of ["distro_affected", "distro_unfixed", "distro_fixed"]) {
      assert.equal(findingMatchBadge(m, goConfidence[m]), null, m);
    }
  });

  test("a method this page does not know is still shown, for review", () => {
    assert.deepEqual(findingMatchBadge("osv_ecosystem", "high"), {
      method: "osv_ecosystem",
      confidence: "high",
      needsReview: true,
      label: "methodOther",
      otherMethod: "osv_ecosystem",
    });
    assert.equal(findingMatchBadge("osv_ecosystem", "bogus")?.confidence, "unknown");
    const odd = findingMatchBadge("<img src=x>", "low");
    assert.equal(odd?.label, "methodOtherUnnamed");
    assert.equal(odd?.otherMethod, undefined);
    assert.equal(odd?.needsReview, true);
    assert.equal(findingMatchBadge(42, "low")?.label, "methodNotRecorded");
  });
});

describe("finding confidence wording", () => {
  const load = (loc) =>
    JSON.parse(readFileSync(new URL(`../../../messages/${loc}.json`, import.meta.url), "utf8")).MatchMethod;
  test("every label and hint key exists in both locales", () => {
    const keys = [
      "methodNvdCpe",
      "methodNvdCpeDistro",
      "methodNvdCpeUnverified",
      "methodNvdKeyword",
      "methodJvnKeyword",
      "methodCveSyncKeyword",
      "methodNotRecorded",
      "methodOther",
      "methodOtherUnnamed",
      "confidenceHigh",
      "confidenceMedium",
      "confidenceLow",
      "confidenceUnknown",
      "findingBadge",
      "findingBadgeReview",
      "findingReviewNote",
      "findingHintWithNote",
    ];
    for (const loc of ["en", "ja"]) {
      const m = load(loc);
      for (const k of keys) assert.equal(typeof m[k], "string", `${loc}.${k}`);
      for (const k of keys.filter((k) => k.startsWith("method"))) {
        const hint = `hint${k.slice("method".length)}`;
        assert.equal(typeof m[hint], "string", `${loc}.${hint}`);
      }
    }
  });
  test("the review badge leads with the review state and keeps the finding", () => {
    assert.match(load("en").findingBadgeReview, /^Needs review: \{method\}/);
    assert.match(load("ja").findingBadgeReview, /^要確認: \{method\}/);
    // never suggests the finding was dropped or resolved
    for (const loc of ["en", "ja"]) {
      const m = load(loc);
      assert.doesNotMatch(m.findingReviewNote, /not_affected/, loc);
    }
    assert.match(load("en").findingReviewNote, /counted/);
    assert.match(load("ja").findingReviewNote, /件数/);
  });
  test("keyword labels say the version was not checked", () => {
    assert.match(load("en").methodNvdKeyword, /keyword/i);
    assert.match(load("en").methodNvdKeyword, /unverified/);
    assert.match(load("en").methodJvnKeyword, /JVN keyword/);
    assert.match(load("ja").methodNvdKeyword, /キーワード/);
    assert.match(load("ja").methodJvnKeyword, /JVN キーワード/);
  });
});
