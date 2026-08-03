// The canonical sentence each tool description uses to tell the model what the
// configured API key reaches.
//
// WHY THESE ARE CONSTANTS AND NOT PROSE
//
// bad1b8c fixed five descriptions that claimed a scope the backend does not
// grant. The tests added afterwards check the live description text against the
// backend's own route classification — but they read free Japanese prose with
// regular expressions, and a review round demonstrated wordings that are false
// yet match every pattern ("あらゆる案件", "単一案件の結果だけを返す", a rule
// stated about a different tool, ...). Pattern-matching prose can be tightened
// forever without ever being sound.
//
// So the load-bearing claim is not written per tool at all: it is ONE string
// per classification, and every tool of that classification embeds it verbatim.
// test/tool-contract.test.mjs asserts
//
//   (1) the clause below is itself consistent with
//       apps/api/internal/middleware/project_scope.go (the status it quotes is
//       the status RespondProjectScopeDenied answers with, and it passes the
//       same claim rules the free prose does), and
//   (2) every tool whose observed routes have that classification contains the
//       clause verbatim, and carries no clause belonging to another one.
//
// A tool cannot then be given a scope claim that disagrees with its routes
// without either changing the shared clause (one place, checked against Go) or
// failing (2). The surrounding prose stays free — it explains WHY, and the
// heuristic rules still run over it to catch a sentence that contradicts the
// clause.

// The single status a project-scope violation produces
// (middleware.RespondProjectScopeDenied). Asserted equal to the value read out
// of the Go source, so this file cannot drift away from the server.
export const PROJECT_SCOPE_DENIAL_STATUS = 403;

export const SCOPE_NOTE = {
  // Routes classified scopeTenantWide: the answer spans the tenant, and a
  // project-scoped key is REFUSED rather than answered narrowly.
  tenantWide:
    "テナント単位のAPIキーが必要 — プロジェクトスコープのAPIキーでは" +
    `${PROJECT_SCOPE_DENIAL_STATUS}で拒否される`,

  // Routes classified scopeProjectListNarrowed: the whole body is an
  // enumeration of projects, so the backend narrows it to the key's own
  // project instead of refusing.
  projectListNarrowed:
    "テナント単位のAPIキーではテナントの全プロジェクト、" +
    "プロジェクトスコープのAPIキーではそのプロジェクト1件のみが返る",

  // Routes classified scopeProjectPathParam need no clause here: the project
  // is named by the caller, and what a project-scoped key gets for someone
  // else's project is stated on the project_id argument itself.
} as const;
