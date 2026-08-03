// Turns a tool description (free Japanese prose an LLM reads) into checkable
// propositions, and checks them against what the backend says about the routes
// the tool actually called.
//
// THE DEFECT THIS ENCODES  (commit bad1b8c)
//
//   | tool             | description said            | project-scoped key got |
//   |------------------|-----------------------------|------------------------|
//   | list_projects    | 「プロジェクト一覧を取得」      | one project            |
//   | get_dashboard    | 「テナント全体の…」            | 403                    |
//   | search_cve       | 「全プロジェクトを横断検索」     | 403                    |
//   | search_component | 「コンポーネント名で…検索」      | 403                    |
//   | diff             | (no scope mentioned)         | 403                    |
//
// None of those was detectable from the description alone — each is only wrong
// relative to the route's classification. So the rules below are derived from
// the classification, and applied to the LIVE description string:
//
//   scopeTenantWide          → the description must say a tenant-level key is
//                              REQUIRED and that a project-scoped key is
//                              refused with the backend's denial status.
//   scopeProjectListNarrowed → the description must say what a project-scoped
//                              key sees (one project), and must not assert
//                              tenant-wide coverage unconditionally.
//   scopeProjectPathParam    → the description must not claim tenant-wide
//                              coverage at all.
//
// Cross-check in the other direction too: a description may not advertise a
// refusal for a tool that has no refusable route.
//
// The markers are substrings of Japanese prose. That is a deliberate trade:
// a rephrasing that drops the marker fails the test and has to restate the
// claim in the recognised form (or update the marker with intent), whereas a
// rule loose enough to accept any phrasing would accept the five rows above.

// Positive vocabulary. Every one of these is expected to match at least one
// live description (tool-inventory.test.mjs asserts that), so a marker that
// stopped matching anything — a typo, a phrase the product abandoned — is
// caught instead of quietly making a rule unsatisfiable or vacuous.
//
// The negative lookaheads matter: these are substring checks, and Japanese
// negates at the END of the clause. Without them,
// 「テナント単位のAPIキーが必要ではない」 would satisfy a check for
// 「…が必要」 while asserting the opposite (Codex R1, High).
export const MARKERS = {
  // The strong form: this tool needs a tenant-level key.
  tenantKeyRequired:
    /テナント単位のAPIキーが必要(?!ではない|ではありません|でない|ない|とは限らない)/,
  // Weak form: the tenant-level key is at least mentioned as a condition.
  tenantKeyMentioned: /テナント単位のAPIキー/,
  projectScopedKeyMentioned: /プロジェクトスコープのAPIキー/,
  ownProject: /そのプロジェクト/,
  narrowedToOne: /1件/,
  // A claim of tenant-wide reach, in the wordings this product uses. Free
  // prose has no closed vocabulary, so this cannot be complete — see the
  // EVASIONS corpus below for what completeness is being traded for.
  tenantWideClaim:
    /テナント全体|全プロジェクト|すべてのプロジェクト|全ての?プロジェクト|プロジェクト横断/,
};

// Phrasings that assert the OPPOSITE of the rules below. Expected to match no
// description at all; tool-inventory.test.mjs asserts that too, so these stay
// meaningful rather than becoming dead regexes.
export const ANTI_MARKERS = {
  negatedRefusal:
    /拒否され(?:ない|ません)|拒否されることは(?:ない|ありません)|拒否されるわけではない/,
  // 「…1件が返ることはなく」 — the narrowing denied while every marker for it
  // is present (Codex R2).
  negatedNarrowing:
    /1件(?:のみ)?が?返ることは(?:なく|ない|ありません)|1件(?:のみ)?が?返(?:らない|りません)|1件ではなく/,
};

/**
 * 「<status>で拒否される」 as one affirmative clause. Checking the status number
 * and the word 「拒否」 independently would accept a sentence that contains both
 * while denying the refusal.
 */
export function refusalMarker(status) {
  return new RegExp(`${status}で拒否される`);
}

// Claiming the answer gets NARROWED. For a scopeTenantWide route that is the
// exact misconception the backend refuses in order to prevent, so a description
// may not assert both the refusal and a narrowing. It is not a global
// anti-marker: for the narrowed-list route saying this is mandatory.
export const NARROWING_CLAIM = /に絞られ|1件(?:のみ)?[がにへ]?返る|1件に絞/;

const TOOL_NAME = /sbomhub_[a-z_]+/g;

function has(description, marker) {
  return marker.test(description);
}

/**
 * Is the requirement stated ABOUT THIS TOOL, or copied in describing another?
 * A description that says "sbomhub_search_cve needs a tenant-level key" while
 * describing sbomhub_get_dashboard contains every required marker and tells
 * the model nothing true about the tool it is attached to.
 */
function attributedToAnotherTool(description, marker, tool) {
  const match = marker.exec(description);
  if (!match) return null;
  const before = description.slice(0, match.index);
  const names = [...before.matchAll(TOOL_NAME)]
    .map((m) => m[0])
    .filter((n) => n !== tool);
  return names.length > 0 ? names[names.length - 1] : null;
}

/**
 * Which credential does the refusal clause hang off? The refusal applies to a
 * project-scoped key; a description saying "テナント単位のAPIキーが403で拒否
 * される" carries both markers and inverts the meaning. The credential
 * mentioned LAST before the refusal clause is the one it reads as.
 */
function credentialBeforeRefusal(description, status) {
  const match = refusalMarker(status).exec(description);
  if (!match) return null;
  const before = description.slice(0, match.index);
  const mentions = [...before.matchAll(/プロジェクトスコープのAPIキー|テナント単位のAPIキー/g)];
  if (mentions.length === 0) return null;
  return mentions[mentions.length - 1][0];
}

/**
 * @param {object} args
 * @param {string} args.tool
 * @param {string} args.description  the live description, as tools/list returns it
 * @param {Map<string,string>} args.routeKindByKey  "<METHOD> <path>" → backend classification,
 *                                                  for every route the tool actually called
 * @param {number} args.denialStatus status the backend answers a scope violation with
 * @returns {string[]} violations (empty = the description agrees with the backend)
 */
export function scopeClaimViolations({
  tool,
  description,
  routeKindByKey,
  denialStatus,
}) {
  const violations = [];
  const routeKeys = [...routeKindByKey.keys()];
  const kinds = new Set(routeKindByKey.values());
  const where = `${tool} (routes actually called: ${routeKeys.join(", ")})`;

  const tenantWideRoutes = routeKeys.filter(
    (r) => routeKindByKey.get(r) === "scopeTenantWide"
  );
  const hasTenantWide = kinds.has("scopeTenantWide");
  const hasNarrowedList = kinds.has("scopeProjectListNarrowed");

  if (hasTenantWide) {
    if (!has(description, MARKERS.tenantKeyRequired)) {
      violations.push(
        `${where}: at least one route is scopeTenantWide, so a project-scoped API key ` +
          `is REFUSED (${denialStatus}) — but the description never says a tenant-level ` +
          `key is required. An LLM handed a project-scoped key will call this tool and ` +
          `read the refusal as a fault. Expected the description to contain ` +
          `"テナント単位のAPIキーが必要".` +
          (tenantWideRoutes.length ? ` Tenant-wide: ${tenantWideRoutes.join(", ")}` : "")
      );
    }
    if (!has(description, refusalMarker(denialStatus))) {
      violations.push(
        `${where}: the backend answers a project-scope violation with HTTP ${denialStatus} ` +
          `and the tool surfaces it verbatim, but the description does not state the refusal ` +
          `(expected 「${denialStatus}で拒否される」 as one clause). Without it the model ` +
          `cannot tell "refused" from "absent".`
      );
    }
    if (!has(description, MARKERS.projectScopedKeyMentioned)) {
      violations.push(
        `${where}: the refusal only happens to a PROJECT-SCOPED key, and the description ` +
          `never names that credential. A model told only that "a tenant-level key is ` +
          `required" cannot tell whether the key it was given is one.`
      );
    }
    if (has(description, ANTI_MARKERS.negatedRefusal)) {
      violations.push(
        `${where}: the description denies a refusal that the backend does perform ` +
          `(scopeTenantWide → ${denialStatus}). State refusals affirmatively.`
      );
    }
    if (has(description, NARROWING_CLAIM)) {
      violations.push(
        `${where}: the description says the answer is NARROWED for a project-scoped key. ` +
          `It is refused (${denialStatus}). Narrowing is what the backend deliberately does ` +
          `not do here — a narrowed aggregate or search result would read as a tenant-level ` +
          `fact, which is the failure this classification exists to prevent.`
      );
    }
    const misattributed = attributedToAnotherTool(
      description,
      MARKERS.tenantKeyRequired,
      tool
    );
    if (misattributed) {
      violations.push(
        `${where}: the credential requirement is stated about ${misattributed}, not about ` +
          `this tool. A model reads the description of the tool it is calling; a rule ` +
          `attributed to another tool tells it nothing about this one.`
      );
    }
    const credential = credentialBeforeRefusal(description, denialStatus);
    if (credential && credential !== "プロジェクトスコープのAPIキー") {
      violations.push(
        `${where}: the ${denialStatus} refusal is attached to 「${credential}」. The backend ` +
          `refuses the PROJECT-SCOPED key; a tenant-level key is exactly the one that works.`
      );
    }
  } else if (hasNarrowedList) {
    if (
      !has(description, MARKERS.projectScopedKeyMentioned) ||
      !has(description, MARKERS.narrowedToOne) ||
      !has(description, MARKERS.ownProject)
    ) {
      violations.push(
        `${where}: the route is scopeProjectListNarrowed — with a project-scoped key the ` +
          `backend answers with THAT KEY'S OWN project instead of the tenant's list. The ` +
          `description must say which project, not just how many (expected ` +
          `「プロジェクトスコープのAPIキー」, 「そのプロジェクト」 and 「1件」), otherwise a ` +
          `one-element answer reads as "the tenant has one project".`
      );
    }
    if (has(description, ANTI_MARKERS.negatedNarrowing)) {
      violations.push(
        `${where}: the description denies the narrowing the backend performs — with a ` +
          `project-scoped key this route answers with that key's own project, one row.`
      );
    }
    if (
      has(description, MARKERS.tenantWideClaim) &&
      !has(description, MARKERS.tenantKeyMentioned)
    ) {
      violations.push(
        `${where}: the description claims tenant-wide coverage without conditioning it on ` +
          `the credential. The answer depends on the key (tenant-level → the tenant, ` +
          `project-scoped → one project), so the claim has to be conditional.`
      );
    }
  } else {
    if (has(description, MARKERS.tenantWideClaim)) {
      violations.push(
        `${where}: every route this tool calls is project-scoped (the project comes from ` +
          `the caller's project_id), but the description claims tenant-wide coverage ` +
          `(「テナント全体」/「全プロジェクト」). The answer covers one project.`
      );
    }
  }

  // Reverse direction: do not advertise a refusal that cannot happen.
  if (!hasTenantWide && has(description, refusalMarker(denialStatus))) {
    violations.push(
      `${where}: the description announces a ${denialStatus} refusal, but none of the routes ` +
        `this tool calls is scopeTenantWide, so the backend never refuses it on scope ` +
        `grounds. A refusal the model expects but never sees is as misleading as one it ` +
        `is not warned about.`
    );
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Known evasions.
//
// Every entry is a description that is FALSE for the classification it is
// paired with, and that an earlier version of the rules above accepted with
// zero violations. tool-inventory.test.mjs asserts each one still produces at
// least one violation, so a later simplification of the rules cannot quietly
// reopen a hole that was already found and closed.
//
// This corpus is not a claim of completeness. These rules read free Japanese
// prose with regular expressions: a determined author can write something
// false that they do not match. What the corpus pins is that the specific
// evasions found by review (Codex R1) and by adversarial self-probing stay
// closed.
// ---------------------------------------------------------------------------
export const EVASIONS = [
  {
    label: "negates the requirement while containing its words",
    kind: "scopeTenantWide",
    description:
      "テナント全体のダッシュボードサマリーを取得。" +
      "テナント単位のAPIキーが必要ではない — プロジェクトスコープのAPIキーでも403で拒否されることはない",
  },
  {
    label: "announces the refusal, then claims the answer is narrowed instead",
    kind: "scopeTenantWide",
    description:
      "テナント全体のダッシュボードサマリーを取得。テナント単位のAPIキーが必要 — " +
      "プロジェクトスコープのAPIキーでは403で拒否されるが、実際にはそのプロジェクト1件に絞られて返る",
  },
  {
    label: "states the rule about a different tool",
    kind: "scopeTenantWide",
    description:
      "テナント全体のダッシュボードサマリーを取得。sbomhub_search_cve は" +
      "テナント単位のAPIキーが必要 — プロジェクトスコープのAPIキーでは403で拒否される",
  },
  {
    label: "hangs the refusal off the wrong credential",
    kind: "scopeTenantWide",
    description:
      "テナント全体のダッシュボードサマリーを取得。テナント単位のAPIキーが必要 — " +
      "プロジェクトスコープのAPIキーでは使えるが、テナント単位のAPIキーが403で拒否される",
  },
  {
    label: "describes a narrowed list as a refusal",
    kind: "scopeProjectListNarrowed",
    description:
      "プロジェクト一覧を取得。プロジェクトスコープのAPIキーではそのプロジェクト1件のみ403で拒否される",
  },
  {
    label: "claims tenant-wide reach for a per-project tool, avoiding the obvious wording",
    kind: "scopeProjectPathParam",
    description: "すべてのプロジェクトの脆弱性を取得",
  },
  {
    label: "per-project tool warning about a refusal that never happens",
    kind: "scopeProjectPathParam",
    description:
      "プロジェクトの脆弱性一覧を取得。プロジェクトスコープのAPIキーでは403で拒否される",
  },
  {
    label: "attributes the requirement to another tool and then denies its own (Codex R2)",
    kind: "scopeTenantWide",
    description:
      "テナント全体のダッシュボードサマリーを取得。テナント単位のAPIキーが必要なのは" +
      "sbomhub_search_cveである。このツールはどのキーでも利用でき、403で拒否されることはない",
  },
  {
    label: "inverts the narrowed result (Codex R2)",
    kind: "scopeProjectListNarrowed",
    description:
      "プロジェクト一覧を取得。プロジェクトスコープのAPIキーではそのプロジェクト1件が" +
      "返ることはなく、別のプロジェクトが複数返る",
  },
];

// Evasions these prose rules do NOT catch, kept here so the limitation is
// written down next to the rules rather than discovered again:
//
//   - a description that embeds the correct canonical clause and then
//     contradicts it in other words ("単一案件の結果だけを返す");
//   - a scope claim in vocabulary the markers do not know ("あらゆる案件").
//
// The first is bounded by tool-contract.test.mjs's rule that credentials may
// only be named inside the canonical clause; the second is not bounded at all.
// Both are why the canonical clause exists: the claim that MUST be present is
// exact, and only the surrounding explanation is free prose.
