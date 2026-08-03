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

export const MARKERS = {
  // "テナント単位のAPIキーが必要" — the strong form: this tool needs one.
  tenantKeyRequired: /テナント単位のAPIキーが必要/,
  // Weak form: the tenant-level key is at least mentioned as a condition.
  tenantKeyMentioned: /テナント単位のAPIキー/,
  projectScopedKeyMentioned: /プロジェクトスコープのAPIキー/,
  refusalWord: /拒否/,
  narrowedToOne: /1件/,
  // An unconditional claim of tenant-wide reach.
  tenantWideClaim: /テナント全体|全プロジェクト/,
};

function has(description, marker) {
  return marker.test(description);
}

function mentionsStatus(description, status) {
  return new RegExp(`(?<!\\d)${status}(?!\\d)`).test(description);
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
    if (!mentionsStatus(description, denialStatus)) {
      violations.push(
        `${where}: the backend answers a project-scope violation with HTTP ${denialStatus} ` +
          `and the tool surfaces it verbatim, but the description never names the status. ` +
          `Without it the model cannot tell "refused" from "absent".`
      );
    }
    if (!has(description, MARKERS.refusalWord)) {
      violations.push(
        `${where}: the route is refused, not narrowed, and the description does not say so ` +
          `(expected 「拒否」). A description that leaves this out invites the model to ` +
          `treat a narrowed or empty answer as the tenant's true state.`
      );
    }
  } else if (hasNarrowedList) {
    if (
      !has(description, MARKERS.projectScopedKeyMentioned) ||
      !has(description, MARKERS.narrowedToOne)
    ) {
      violations.push(
        `${where}: the route is scopeProjectListNarrowed — with a project-scoped key the ` +
          `backend answers with that ONE project instead of the tenant's list. The ` +
          `description must say so (expected 「プロジェクトスコープのAPIキー」 and 「1件」), ` +
          `otherwise a one-element answer reads as "the tenant has one project".`
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
  if (!hasTenantWide && has(description, MARKERS.refusalWord) && mentionsStatus(description, denialStatus)) {
    violations.push(
      `${where}: the description announces a ${denialStatus} refusal, but none of the routes ` +
        `this tool calls is scopeTenantWide, so the backend never refuses it on scope ` +
        `grounds. A refusal the model expects but never sees is as misleading as one it ` +
        `is not warned about.`
    );
  }

  return violations;
}
