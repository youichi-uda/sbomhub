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
  // An unconditional claim of tenant-wide reach.
  tenantWideClaim: /テナント全体|全プロジェクト/,
};

// Phrasings that assert the OPPOSITE of the rules below. Expected to match no
// description at all; tool-inventory.test.mjs asserts that too, so these stay
// meaningful rather than becoming dead regexes.
export const ANTI_MARKERS = {
  negatedRefusal:
    /拒否され(?:ない|ません)|拒否されることは(?:ない|ありません)|拒否されるわけではない/,
};

/**
 * 「<status>で拒否される」 as one affirmative clause. Checking the status number
 * and the word 「拒否」 independently would accept a sentence that contains both
 * while denying the refusal.
 */
export function refusalMarker(status) {
  return new RegExp(`${status}で拒否される`);
}

function has(description, marker) {
  return marker.test(description);
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
