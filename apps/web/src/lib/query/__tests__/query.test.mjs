// react-query migration pins (2026-11, react-hooks 7.1 lint residual).
//
// Run: pnpm --filter web test   (node --test; imports the .ts modules
// directly through Node's type stripping, same as the form-schema pins).
//
// What is pinned and why:
//   - client defaults: the migration is only behaviour-preserving with
//     retry off, no focus/reconnect refetch and gcTime 0 (see client.ts).
//     A future "let's use the react-query defaults" edit must fail here.
//   - key factory: distinct inputs never collide, project keys nest under
//     byId() so one invalidation reaches all of a project's data, the
//     shared keys really are shared, and filter/undefined normalisation.
//   - error slot: the "most recent writer wins" banner decision table that
//     replaced the shared `error` state.
//   - loadErrorMessage: the backend-message-or-i18n-fallback rule the two
//     panels used inline.

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { hashKey } from "@tanstack/react-query";

import { queryDefaults, makeQueryClient } from "../client.ts";
import { queryKeys } from "../keys.ts";
import { errorSlot, resolveErrorSlot } from "../error-slot.ts";
import { APIError, loadErrorMessage } from "../../api.ts";

const P = "11111111-1111-1111-1111-111111111111";
const Q = "22222222-2222-2222-2222-222222222222";

describe("query client defaults", () => {
  test("pins retry/refetch/gc defaults", () => {
    assert.deepEqual(queryDefaults, {
      queries: {
        retry: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        staleTime: 0,
        gcTime: 0,
      },
      mutations: { retry: false },
    });
  });

  test("makeQueryClient applies them", () => {
    const opts = makeQueryClient().getDefaultOptions();
    assert.equal(opts.queries?.retry, false);
    assert.equal(opts.queries?.gcTime, 0);
    assert.equal(opts.queries?.refetchOnWindowFocus, false);
    assert.equal(opts.mutations?.retry, false);
  });

  test("a failed query is not retried and its data is dropped on unmount", async () => {
    const client = makeQueryClient();
    let calls = 0;
    await client
      .fetchQuery({
        queryKey: ["t", "fail"],
        queryFn: async () => {
          calls++;
          throw new Error("boom");
        },
      })
      .catch(() => {});
    assert.equal(calls, 1, "retry must be off");

    await client.fetchQuery({ queryKey: ["t", "ok"], queryFn: async () => 42 });
    // gcTime 0: with no observer the entry is collected on the next tick.
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(client.getQueryData(["t", "ok"]), undefined);
    client.clear();
  });
});

// Every factory, called with representative arguments. Used for the
// collision check below.
function allKeys(projectId) {
  const k = queryKeys;
  return [
    k.projects.list(),
    k.projects.detail(projectId),
    k.projects.components(projectId),
    k.projects.vulnerabilities(projectId, "cvss"),
    k.projects.vulnerabilities(projectId, "epss"),
    k.projects.vex(projectId),
    k.projects.licensePolicies(projectId),
    k.projects.licenseViolations(projectId, "s1"),
    k.projects.licenseViolations(projectId, null),
    k.projects.latestSbomId(projectId),
    k.projects.scanStatus(projectId, "s1"),
    k.projects.scanStatus(projectId, null),
    k.projects.sboms(projectId),
    k.projects.notificationSettings(projectId),
    k.projects.notificationLogs(projectId),
    k.projects.apiKeys(projectId),
    k.projects.compliance(projectId),
    k.projects.checklist(projectId),
    k.projects.visualization(projectId),
    k.projects.publicLinks(projectId),
    k.projects.diff(projectId, "a", "b"),
    k.projects.diff(projectId, undefined, "b"),
    k.projects.diffGraph(projectId, "a", "b"),
    k.projects.componentPaths(projectId, "c1", undefined),
    k.projects.componentPaths(projectId, "c1", "s1"),
    k.projects.craReports(projectId, { limit: 100 }),
    k.projects.craReports(projectId, { limit: 100, decision: "pending" }),
    k.projects.craReports(projectId, { limit: 100, decision: "approved" }),
    k.projects.craSubmissions(projectId, "r1"),
    k.projects.craSubmissions(projectId, "r2"),
    k.dashboard.summary(),
    k.analytics.summary(30),
    k.analytics.summary(90),
    k.audit.logs({ limit: 50 }, 1),
    k.audit.logs({ limit: 50 }, 2),
    k.audit.logs({ limit: 50, action: "project.created" }, 1),
    k.audit.filterOptions(),
    k.billing.subscription(),
    k.billing.overview(),
    k.reports.list(1),
    k.reports.list(2),
    k.reports.settings(),
    k.apiKeys.list(),
    k.integrations.list(),
    k.ipa.settings(),
    k.ipa.byCve("CVE-2024-0001"),
    k.tickets.byVulnerability("v1"),
    k.kev.check("CVE-2024-0001"),
    k.publicView("tok", 0),
    k.publicView("tok", 1),
    k.tenantSettings.diffWebhook(),
    k.tenantSettings.llm(),
  ];
}

describe("query key factory", () => {
  test("no two distinct queries share a key", () => {
    const keys = [...allKeys(P), ...allKeys(Q).filter((k) => k[0] === "projects" && k[1] !== "list")];
    const seen = new Map();
    for (const key of keys) {
      const h = hashKey(key);
      assert.ok(!seen.has(h), `collision: ${h} (also ${JSON.stringify(seen.get(h))})`);
      seen.set(h, key);
    }
  });

  test("a project id equal to 'list' cannot collide with the project list", () => {
    assert.notEqual(
      hashKey(queryKeys.projects.list()),
      hashKey(queryKeys.projects.detail("list")),
    );
    assert.notEqual(hashKey(queryKeys.projects.list()), hashKey(queryKeys.projects.byId("list")));
  });

  test("every project-scoped key nests under byId(projectId) and not under another project", () => {
    const prefix = queryKeys.projects.byId(P);
    for (const key of allKeys(P)) {
      if (key[0] !== "projects" || key[1] === "list") continue;
      assert.deepEqual(key.slice(0, prefix.length), [...prefix], JSON.stringify(key));
      assert.notDeepEqual(key.slice(0, prefix.length), [...queryKeys.projects.byId(Q)]);
    }
  });

  test("byId invalidation reaches exactly that project's queries", async () => {
    const client = makeQueryClient();
    const seed = (key) => client.setQueryData(key, 1);
    for (const key of [...allKeys(P), ...allKeys(Q)]) seed(key);
    // Mark everything fresh, then invalidate one project.
    await client.invalidateQueries({ queryKey: queryKeys.projects.byId(P), refetchType: "none" });
    const invalidated = client
      .getQueryCache()
      .getAll()
      .filter((q) => q.state.isInvalidated)
      .map((q) => q.queryKey);
    assert.ok(invalidated.length > 0);
    for (const key of invalidated) assert.equal(key[2], P, JSON.stringify(key));
    assert.ok(!invalidated.some((k) => k[1] === "list"), "project list must not be hit");
    client.clear();
  });

  test("audit filter normalisation: undefined/empty members and order do not matter", () => {
    const a = queryKeys.audit.logs({ page: 1, limit: 50, action: undefined, resource_type: "" }, 3);
    const b = queryKeys.audit.logs({ limit: 50, page: 1 }, 3);
    assert.equal(hashKey(a), hashKey(b));
    // ...but the page argument wins over the filter's own `page` member.
    assert.deepEqual(a[2], { limit: 50, page: 3 });
    // and a real filter value is part of the key.
    assert.notEqual(
      hashKey(queryKeys.audit.logs({ limit: 50, action: "x" }, 1)),
      hashKey(queryKeys.audit.logs({ limit: 50 }, 1)),
    );
  });

  test("CRA report keys: one per filter; empty / undefined members and order do not matter", () => {
    assert.equal(
      hashKey(queryKeys.projects.craReports(P, { limit: 100, decision: "", lang: undefined })),
      hashKey(queryKeys.projects.craReports(P, { limit: 100 })),
    );
    assert.equal(
      hashKey(queryKeys.projects.craReports(P, { decision: "approved", limit: 100 })),
      hashKey(queryKeys.projects.craReports(P, { limit: 100, decision: "approved" })),
    );
    assert.notEqual(
      hashKey(queryKeys.projects.craReports(P, { limit: 100, decision: "pending" })),
      hashKey(queryKeys.projects.craReports(P, { limit: 100, decision: "approved" })),
    );
  });

  // M65 bug 2, at the cache level: a slow answer for the previous filter
  // lands in THAT filter's entry and can never become the current filter's
  // data, whatever order the two answers arrive in.
  test("CRA reports: a late response for an older filter never lands in the newer filter's entry", async () => {
    const client = makeQueryClient();
    const pendingKey = queryKeys.projects.craReports(P, { limit: 100, decision: "pending" });
    const approvedKey = queryKeys.projects.craReports(P, { limit: 100, decision: "approved" });
    let releasePending;
    const pendingHeld = new Promise((r) => (releasePending = r));
    const pendingFetch = client.fetchQuery({
      queryKey: pendingKey,
      queryFn: async () => {
        await pendingHeld;
        return { data: [], totalCount: 0 };
      },
    });
    const approved = await client.fetchQuery({
      queryKey: approvedKey,
      queryFn: async () => ({ data: [{ id: "approved-row" }], totalCount: 1 }),
    });
    assert.deepEqual(approved.data.map((r) => r.id), ["approved-row"]);
    releasePending();
    await pendingFetch;
    assert.deepEqual(client.getQueryData(approvedKey).data.map((r) => r.id), ["approved-row"]);
    assert.deepEqual(client.getQueryData(pendingKey).data, []);
    client.clear();
  });

  test("diff keys: missing from/to are null (not dropped), so ?to=b differs from ?from=b", () => {
    assert.notEqual(
      hashKey(queryKeys.projects.diff(P, undefined, "b")),
      hashKey(queryKeys.projects.diff(P, "b", undefined)),
    );
    assert.deepEqual(queryKeys.projects.diff(P, undefined, undefined).at(-1), { from: null, to: null });
  });

  test("shared keys are shared", () => {
    // IPAAlert + IPAAlertBadge, TicketStatus + TicketBadge, KEVBadge per CVE,
    // audit feature gate + nothing else hitting /billing/subscription.
    assert.equal(hashKey(queryKeys.ipa.byCve("CVE-1")), hashKey(queryKeys.ipa.byCve("CVE-1")));
    assert.notEqual(hashKey(queryKeys.ipa.byCve("CVE-1")), hashKey(queryKeys.kev.check("CVE-1")));
    assert.notEqual(hashKey(queryKeys.billing.subscription()), hashKey(queryKeys.billing.overview()));
  });

  test("the public-link password never appears in a key", () => {
    // The key carries only the attempt counter; see public/[token]/page.tsx.
    assert.deepEqual(queryKeys.publicView("tok", 2), ["public-view", "tok", { attempt: 2 }]);
  });
});

describe("error slot (shared banner)", () => {
  // A real QueryClient supplies the per-key failure counts, as in the pages.
  const K1 = ["audit", "logs", { page: 1 }];
  const K2 = ["audit", "logs", { page: 2 }];
  async function fail(client, key) {
    await client.fetchQuery({ queryKey: key, queryFn: async () => { throw new Error("x"); } }).catch(() => {});
  }
  async function succeed(client, key) {
    await client.fetchQuery({ queryKey: key, queryFn: async () => 1 });
  }
  const count = (client, key) => client.getQueryState(key)?.errorUpdateCount ?? 0;
  const show = (slot, client, key) => resolveErrorSlot(slot, key, count(client, key), "load");

  test("no writers -> no banner; a failed load -> load message", async () => {
    const c = makeQueryClient();
    assert.equal(show(null, c, K1), null);
    await fail(c, K1);
    assert.equal(show(null, c, K1), "load");
    c.clear();
  });

  test("action after a failed load wins (message or clear); a later failure wins back", async () => {
    const c = makeQueryClient();
    await fail(c, K1);
    assert.equal(show(errorSlot("export", K1, c), c, K1), "export");
    const cleared = errorSlot(null, K1, c);
    assert.equal(show(cleared, c, K1), null);
    await fail(c, K1);
    assert.equal(show(cleared, c, K1), "load");
    c.clear();
  });

  test("a load success never writes the banner", async () => {
    const c = makeQueryClient();
    const slot = errorSlot("export", K1, c);
    await succeed(c, K1);
    assert.equal(show(slot, c, K1), "export");
    c.clear();
  });

  test("R4: key change after a failure — the new key's first failure is shown", async () => {
    const c = makeQueryClient();
    await fail(c, K1); // page 1 failed
    const cleared = errorSlot(null, K1, c); // handler: clear, then setPage(2)
    assert.equal(show(cleared, c, K2), null, "page 2 in flight");
    await fail(c, K2); // page 2 fails: its count is 1, same as K1's was
    assert.equal(show(cleared, c, K2), "load");
    c.clear();
  });

  test("R4: an async action that completes after a concurrent failure is the latest writer", async () => {
    const c = makeQueryClient();
    // export starts (render snapshot: 0 failures), the list reload fails
    // meanwhile, then the export fails: the export error is newest.
    await fail(c, K1);
    const exportErr = errorSlot("export", K1, c); // stamped from the cache, not a render snapshot
    assert.equal(show(exportErr, c, K1), "export");
    c.clear();
  });

  test("R1: an action error raised while a load is in flight survives the load's success", async () => {
    const c = makeQueryClient();
    const exportErr = errorSlot("export", K1, c);
    await succeed(c, K1);
    assert.equal(show(exportErr, c, K1), "export");
    c.clear();
  });
});

describe("loadErrorMessage", () => {
  test("APIError with a backend error string -> that string", () => {
    assert.equal(loadErrorMessage(new APIError(422, { error: "sbom has no graph" }), "fb"), "sbom has no graph");
  });
  test("APIError without one -> fallback, never 'API error: 500'", () => {
    assert.equal(loadErrorMessage(new APIError(500), "fb"), "fb");
    assert.equal(loadErrorMessage(new APIError(500, { error: 7 }), "fb"), "fb");
  });
  test("plain Error -> its message; non-Error -> fallback", () => {
    assert.equal(loadErrorMessage(new TypeError("Failed to fetch"), "fb"), "Failed to fetch");
    assert.equal(loadErrorMessage("nope", "fb"), "fb");
    assert.equal(loadErrorMessage(undefined, "fb"), "fb");
  });
});

// ---- Codex R1 regressions ---------------------------------------------

import { orgScopeKey } from "../org-scope.ts";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

describe("R1/R2 Critical: organisation switch never shows the previous org's data", () => {
  // ApiAuthProvider renders the dashboard subtree only when orgScopeKey()
  // returns a key, and mounts it under `key={that}` with its own
  // QueryClient. A different key = a fresh subtree + fresh cache: no query
  // data, no retained data, no drafts, and a late Org A mutation can only
  // write into the discarded client.
  test("nothing renders until the token getter is wired", () => {
    assert.equal(orgScopeKey(undefined, "org_A"), null);
    assert.equal(orgScopeKey(undefined, null), null);
  });
  test("wired org == current org -> stable key per org", () => {
    assert.equal(orgScopeKey("org_A", "org_A"), "org:org_A");
    assert.equal(orgScopeKey(null, null), "no-org");
  });
  test("org changed but the getter is still wired to the old org -> gate (render nothing)", () => {
    assert.equal(orgScopeKey("org_A", "org_B"), null);
    assert.equal(orgScopeKey(null, "org_B"), null);
    assert.equal(orgScopeKey("org_A", null), null);
  });
  test("different orgs never share a key (so never share a QueryClient / subtree)", () => {
    assert.notEqual(orgScopeKey("org_A", "org_A"), orgScopeKey("org_B", "org_B"));
    assert.notEqual(orgScopeKey(null, null), orgScopeKey("no-org", "no-org"));
  });
});

describe("R4 Low: ApiAuthProvider wiring (per-org client, keyed, gated)", () => {
  const prov = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "../../../components/providers/api-auth-provider.tsx"),
    "utf8",
  );
  test("children render only under the org-scope key, inside a fresh per-org QueryClient", () => {
    assert.match(prov, /const scopeKey = isLoaded \? orgScopeKey\(wiredOrg, orgId \|\| null\) : null;/);
    assert.match(prov, /if \(scopeKey === null\) \{\s*return \(/);
    assert.match(prov, /<OrgScopedQueryClient key=\{scopeKey\}>\{children\}<\/OrgScopedQueryClient>/);
    assert.match(prov, /function OrgScopedQueryClient[\s\S]*?useState\(makeQueryClient\)[\s\S]*?<QueryClientProvider client=\{client\}>/);
    // no other path renders children
    assert.equal((prov.match(/\{children\}/g) || []).length, 2, "children rendered only via the scoped client");
  });
});

describe("R1 Low: components that must share a cache entry use the shared hook", () => {
  const src = (p) =>
    readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../components", p), "utf8");
  test("IPAAlert and IPAAlertBadge both read useIPAAnnouncements (ipa.byCve)", () => {
    const s = src("vulnerability/ipa-alert.tsx");
    assert.match(s, /queryKey: queryKeys\.ipa\.byCve\(cveId\)/);
    for (const fn of ["IPAAlert", "IPAAlertBadge"]) {
      const body = s.slice(s.indexOf(`export function ${fn}(`)).split("\nexport function")[0];
      assert.match(body, /useIPAAnnouncements\(cveId\)/, fn);
    }
  });
  test("TicketStatus and TicketBadge both read useVulnerabilityTickets (tickets.byVulnerability)", () => {
    const s = src("vulnerability/ticket-status.tsx");
    assert.match(s, /queryKey: queryKeys\.tickets\.byVulnerability\(vulnerabilityId\)/);
    for (const fn of ["TicketStatus", "TicketBadge"]) {
      const body = s.slice(s.indexOf(`export function ${fn}(`)).split("\nexport function")[0];
      assert.match(body, /useVulnerabilityTickets\(vulnerabilityId/, fn);
    }
  });
});

// ---- Codex R3 regressions ---------------------------------------------

import { nextRetained } from "../retain.ts";

describe("R3 Medium: retained data never crosses a scope (project) boundary", () => {
  test("retains across parameter changes within one scope", () => {
    let r = nextRetained(null, "p1", { sort: "cvss" });
    assert.deepEqual(r, { scope: "p1", data: { sort: "cvss" } });
    const same = nextRetained(r, "p1", undefined); // epss loading / failed
    assert.equal(same, r);
  });
  test("a different scope drops what was retained", () => {
    const r = nextRetained(null, "p1", ["A's CVE"]);
    assert.equal(nextRetained(r, "p2", undefined), null);
  });
  test("identity-stable when nothing changes (render-time setState guard)", () => {
    const data = [1];
    const r = nextRetained(null, "s", data);
    assert.equal(nextRetained(r, "s", data), r);
  });
});

describe("R3 High/Medium: form seeding is per project / per mount, never from a queryFn", () => {
  const appSrc = (p) =>
    readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../../app/[locale]/(dashboard)", p), "utf8");
  test("NotificationSettingsForm is keyed by project", () => {
    assert.match(
      appSrc("projects/[id]/page.tsx"),
      /<NotificationSettingsForm\s+key=\{projectId\}/,
    );
  });
  for (const page of ["settings/llm/page.tsx", "settings/diff-webhook/page.tsx"]) {
    test(`${page}: the queryFn does not reset the form; the form mounts after the query settles`, () => {
      const s = appSrc(page);
      const qfn = s.slice(s.indexOf("queryFn:"), s.indexOf("});", s.indexOf("queryFn:")));
      assert.doesNotMatch(qfn, /reset\(|seedForm\(/);
      assert.match(s, /useForm<FormInput, unknown, FormValues>\(\{[\s\S]*?defaultValues: initialValues/);
    });
  }
});
