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
import { describe, test } from "node:test";

import {
  distroBadge,
  distroEvidenceView,
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
    for (const ev of [undefined, null, {}, { fixed: "" }, { fixed: "   " }, { fixed: 3 }, "x", []]) {
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
    assert.equal(v.inferredFromLaterReleases, true);
    assert.deepEqual(v.laterReleases, ["Debian:12", "Debian:13"]);
    assert.equal(v.release, "Debian:11");
  });

  test("an id that is not a token is kept as text without a link", () => {
    const v = distroEvidenceView("distro_unfixed", { records: ["DSA-1", "bad id"] });
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
    });
  });

  test("non-distro methods have no evidence view", () => {
    assert.equal(distroEvidenceView("nvd_cpe", affectedEv), null);
  });
});
