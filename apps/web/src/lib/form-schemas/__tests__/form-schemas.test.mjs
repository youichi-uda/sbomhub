// Pins the accept/reject behaviour and the error messages of the five
// react-hook-form + zod forms in apps/web, so the zod 3 → 4 migration
// (GHSA-mrhx-c7xc-m3w5) cannot silently change what the UI accepts or says.
//
// Written and run GREEN against zod 3.25.76 BEFORE the migration; the
// migration had to keep it green.
//
// Why .test.mjs importing .ts: apps/web ships no component test runner (see
// src/components/ui/__tests__/tooltip.test.mjs). The schemas live in modules
// that import nothing but zod, so node's built-in type stripping (Node
// >= 22.18) can load them directly.
//
// Message policy:
//   - A message the UI renders VERBATIM (`errors.<field>.message`) is pinned
//     exactly: cra draft_text / authority, triage state / detail.
//   - A message the UI maps to an i18n key (diff-webhook url_*, llm
//     api_key_required) is pinned exactly, because the key IS the contract.
//   - Every other max-length / enum message is pinned exactly too, so a field
//     that starts rendering its message later inherits the same wording.
//   - Messages that cannot be produced through the rendered form (a missing
//     key — every field is registered — and numeric coercion failures, which
//     the page does not render) are pinned by path only.
//
// Run:
//   node --test apps/web/src/lib/form-schemas/__tests__/form-schemas.test.mjs
import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { zodResolver } from "@hookform/resolvers/zod";

import { reportEditSchema, reportSubmitSchema } from "../cra-report.ts";
import { triageEditSchema } from "../triage-draft.ts";
import {
  criterionClearOverrideSchema,
  criterionOverrideSchema,
} from "../meti-criterion.ts";
import { diffWebhookSchema } from "../diff-webhook.ts";
import { buildLlmSettingsSchema } from "../llm-settings.ts";

/** [path, message] pairs, in issue order. */
function issuesOf(schema, value) {
  const r = schema.safeParse(value);
  assert.equal(r.success, false, `expected rejection of ${JSON.stringify(value).slice(0, 200)}`);
  return r.error.issues.map((i) => [i.path.join("."), i.message]);
}
function pathsOf(schema, value) {
  return issuesOf(schema, value).map(([p]) => p);
}
function accept(schema, value) {
  const r = schema.safeParse(value);
  assert.equal(
    r.success,
    true,
    `expected acceptance, got ${r.success ? "" : JSON.stringify(r.error.issues)}`,
  );
  return r.data;
}
const maxMsg = (n) => `String must contain at most ${n} character(s)`;
const enumMsg = (values, received) =>
  `Invalid enum value. Expected ${values.map((v) => `'${v}'`).join(" | ")}, received '${received}'`;

describe("cra-report: edit form", () => {
  const ok = { draft_text: "x", decision_note: "" };
  test("accepts boundary values", () => {
    assert.deepEqual(accept(reportEditSchema, ok), ok);
    accept(reportEditSchema, { draft_text: "a".repeat(50000), decision_note: "b".repeat(2000) });
  });
  test("draft_text empty → custom message", () => {
    assert.deepEqual(issuesOf(reportEditSchema, { ...ok, draft_text: "" }), [
      ["draft_text", "draft_text is required"],
    ]);
  });
  test("over-length → v3 max message (rendered verbatim for draft_text)", () => {
    assert.deepEqual(
      issuesOf(reportEditSchema, { draft_text: "a".repeat(50001), decision_note: "b".repeat(2001) }),
      [
        ["draft_text", maxMsg(50000)],
        ["decision_note", maxMsg(2000)],
      ],
    );
  });
  test("missing keys rejected", () => {
    assert.deepEqual(pathsOf(reportEditSchema, {}), ["draft_text", "decision_note"]);
  });
});

describe("cra-report: submit form", () => {
  const ok = { authority: "ENISA", submitted_at: "", reference_number: "", notes: "" };
  test("accepts boundary values; submitted_at is free text", () => {
    assert.deepEqual(accept(reportSubmitSchema, ok), ok);
    accept(reportSubmitSchema, {
      authority: "a".repeat(255),
      submitted_at: "2026-01-01T00:00",
      reference_number: "r".repeat(255),
      notes: "n".repeat(5000),
    });
  });
  test("authority empty → custom message", () => {
    assert.deepEqual(issuesOf(reportSubmitSchema, { ...ok, authority: "" }), [
      ["authority", "authority is required"],
    ]);
  });
  test("over-length → v3 max messages", () => {
    assert.deepEqual(
      issuesOf(reportSubmitSchema, {
        authority: "a".repeat(256),
        submitted_at: "",
        reference_number: "r".repeat(256),
        notes: "n".repeat(5001),
      }),
      [
        ["authority", maxMsg(255)],
        ["reference_number", maxMsg(255)],
        ["notes", maxMsg(5000)],
      ],
    );
  });
});

describe("triage: draft edit form", () => {
  const STATES = ["not_affected", "affected", "under_investigation", "resolved"];
  const JUST = [
    "",
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_perimeter",
    "protected_at_runtime",
    "inline_mitigations_already_exist",
  ];
  const ok = { state: "affected", justification: "", detail: "", note: "" };
  test("accepts every state × justification", () => {
    for (const state of STATES) {
      for (const justification of JUST) {
        accept(triageEditSchema, { ...ok, state, justification });
      }
    }
    accept(triageEditSchema, { ...ok, detail: "d".repeat(4000), note: "n".repeat(2000) });
  });
  test("rejections carry the v3 messages (state + detail are rendered verbatim)", () => {
    assert.deepEqual(
      issuesOf(triageEditSchema, {
        state: "x",
        justification: "y",
        detail: "d".repeat(4001),
        note: "n".repeat(2001),
      }),
      [
        ["state", enumMsg(STATES, "x")],
        ["justification", enumMsg(JUST, "y")],
        ["detail", maxMsg(4000)],
        ["note", maxMsg(2000)],
      ],
    );
  });
  test("missing keys rejected", () => {
    assert.deepEqual(pathsOf(triageEditSchema, {}), ["state", "justification", "detail", "note"]);
  });
});

describe("meti: override form", () => {
  const STATUSES = ["achieved", "not_achieved", "needs_review", "not_applicable"];
  test("accepts every status and boundary lengths", () => {
    for (const s of STATUSES) {
      accept(criterionOverrideSchema, {
        override_status: s,
        override_note: "n".repeat(2000),
        improvement_action: "i".repeat(2000),
      });
    }
  });
  test("rejections", () => {
    assert.deepEqual(
      issuesOf(criterionOverrideSchema, {
        override_status: "",
        override_note: "n".repeat(2001),
        improvement_action: "i".repeat(2001),
      }),
      [
        ["override_status", enumMsg(STATUSES, "")],
        ["override_note", maxMsg(2000)],
        ["improvement_action", maxMsg(2000)],
      ],
    );
  });
  // M65 bug 4: the API requires a non-blank reason (400 "override_note is
  // required" after trim), so the form does too.
  test("blank / whitespace-only reason rejected; reason is trimmed", () => {
    for (const override_note of ["", "   ", "\n\t "]) {
      assert.deepEqual(
        issuesOf(criterionOverrideSchema, {
          override_status: "achieved",
          override_note,
          improvement_action: "",
        }),
        [["override_note", "override_note is required"]],
      );
    }
    assert.equal(
      accept(criterionOverrideSchema, {
        override_status: "achieved",
        override_note: "  vendor attestation  ",
        improvement_action: "",
      }).override_note,
      "vendor attestation",
    );
    // The 2000 cap counts the trimmed reason.
    accept(criterionOverrideSchema, {
      override_status: "achieved",
      override_note: ` ${"n".repeat(2000)} `,
      improvement_action: "",
    });
  });
});

describe("meti: clear-override form (trim then 1..4096)", () => {
  const MSG = "note must be 1..4096 characters after trim";
  test("output is trimmed", () => {
    assert.deepEqual(accept(criterionClearOverrideSchema, { note: "  x  " }), { note: "x" });
    assert.deepEqual(
      accept(criterionClearOverrideSchema, { note: ` ${"a".repeat(4096)} ` }).note.length,
      4096,
    );
  });
  test("whitespace-only / empty / too long rejected with the custom message", () => {
    for (const note of ["", "   ", "\n\t", "a".repeat(4097)]) {
      assert.deepEqual(issuesOf(criterionClearOverrideSchema, { note }), [["note", MSG]]);
    }
  });
});

describe("diff-webhook settings form", () => {
  const ok = {
    enabled: true,
    webhook_url: "https://hooks.example.com/x",
    webhook_secret: "",
    format: "json",
    critical_threshold: "1",
    high_threshold: "5",
    license_violation_threshold: "0",
  };
  test("accepts http(s) URLs and coerces thresholds", () => {
    assert.deepEqual(accept(diffWebhookSchema, ok), {
      ...ok,
      critical_threshold: 1,
      high_threshold: 5,
      license_violation_threshold: 0,
    });
    accept(diffWebhookSchema, { ...ok, webhook_url: "http://10.0.0.1:8080/hook", format: "slack" });
    // The scheme check is a prefix regex, not URL parsing: kept exactly.
    accept(diffWebhookSchema, { ...ok, webhook_url: "https://" });
  });
  test("optional url/secret default to empty string; disabled + empty url accepted", () => {
    const { webhook_url: _u, webhook_secret: _s, ...rest } = ok;
    const out = accept(diffWebhookSchema, { ...rest, enabled: false });
    assert.equal(out.webhook_url, "");
    assert.equal(out.webhook_secret, "");
  });
  test("empty threshold coerces to 0 (Number(\"\") === 0)", () => {
    assert.equal(accept(diffWebhookSchema, { ...ok, critical_threshold: "" }).critical_threshold, 0);
    assert.equal(accept(diffWebhookSchema, { ...ok, high_threshold: " 2 " }).high_threshold, 2);
  });
  test("enabled with blank url → url_required", () => {
    for (const webhook_url of ["", "   "]) {
      assert.deepEqual(issuesOf(diffWebhookSchema, { ...ok, webhook_url }), [
        ["webhook_url", "url_required"],
      ]);
    }
  });
  test("non-http(s) schemes → url_protocol, enabled or not (security: no loosening)", () => {
    for (const enabled of [true, false]) {
      for (const webhook_url of [
        "javascript:alert(1)",
        "data:text/html,x",
        "file:///etc/passwd",
        "ftp://example.com/x",
        "HTTPS://example.com", // case-sensitive prefix, as before
        " https://example.com", // leading whitespace is not trimmed for this check
        "example.com/hook",
        "//example.com/hook",
      ]) {
        assert.deepEqual(
          issuesOf(diffWebhookSchema, { ...ok, enabled, webhook_url }),
          [["webhook_url", "url_protocol"]],
          webhook_url,
        );
      }
    }
  });
  test("threshold rejections (negative, fractional, non-numeric, infinite)", () => {
    const disabled = { ...ok, enabled: false, webhook_url: "" };
    for (const v of ["-1", "1.5", "abc", "Infinity", "-Infinity", "1e999"]) {
      // Rejected, and only on this field (the issue COUNT is not pinned:
      // "-Infinity" fails both int() and min(0) under zod 3).
      assert.deepEqual(
        [...new Set(pathsOf(diffWebhookSchema, { ...disabled, critical_threshold: v }))],
        ["critical_threshold"],
        v,
      );
    }
  });
  test("integers beyond 2^53 are accepted, as zod 3 int() did (Codex R1 Medium)", () => {
    // zod 3's int() is Number.isInteger; zod 4's is Number.isSafeInteger.
    for (const v of ["9007199254740992", "1e20"]) {
      assert.equal(
        typeof accept(diffWebhookSchema, { ...ok, critical_threshold: v }).critical_threshold,
        "number",
        v,
      );
    }
  });
  test("an aborting threshold failure suppresses the url check, as in zod 3 (Codex R1 Low)", () => {
    // NaN is a type failure: zod 3 aborted the object and skipped the
    // refinement, so only the threshold failed. Same for an invalid format.
    assert.deepEqual(pathsOf(diffWebhookSchema, { ...ok, webhook_url: "", critical_threshold: "abc" }), [
      "critical_threshold",
    ]);
    assert.deepEqual(pathsOf(diffWebhookSchema, { ...ok, webhook_url: "", format: "xml" }), ["format"]);
  });
  test("url issue still reported alongside a threshold issue", () => {
    // The form shows both at once; the refinement must not be skipped
    // because a sibling field failed with a VALUE error. "1e999" /
    // "Infinity" coerce to ±Infinity, which zod 3 failed in int()
    // (non-aborting), so the URL error still showed (Codex R2 Low). Only
    // reachable through programmatic form state: Chrome sanitizes a typed
    // "1e999" in <input type=number> to "" (observed), which coerces to 0. Distinct [path(, url
    // message)] pairs: the issue COUNT per threshold is not pinned
    // ("-Infinity" fails two checks under zod 3).
    const distinct = (value) => [
      ...new Map(
        issuesOf(diffWebhookSchema, value).map(([p, m]) => [
          p,
          p === "webhook_url" ? [p, m] : [p],
        ]),
      ).values(),
    ];
    for (const v of ["-1", "1.5", "1e999", "Infinity", "-Infinity"]) {
      assert.deepEqual(
        distinct({ ...ok, webhook_url: "", critical_threshold: v }),
        [["critical_threshold"], ["webhook_url", "url_required"]],
        v,
      );
      assert.deepEqual(
        distinct({ ...ok, webhook_url: "javascript:x", high_threshold: v }),
        [["high_threshold"], ["webhook_url", "url_protocol"]],
        v,
      );
    }
  });
  test("an infinite value in a NON-threshold field is a plain type failure (Codex R3 Low)", () => {
    // Must not reach the refinement (zod 3 skipped it; reaching it threw on
    // webhook_url.trim()).
    for (const [field, v] of [["webhook_url", Infinity], ["enabled", Infinity], ["webhook_secret", -Infinity]]) {
      const r = diffWebhookSchema.safeParse({ ...ok, enabled: true, webhook_url: "", [field]: v });
      assert.equal(r.success, false, field);
      assert.deepEqual([...new Set(r.error.issues.map((i) => i.path.join(".")))], [field], field);
    }
  });
  test("format enum", () => {
    assert.deepEqual(issuesOf(diffWebhookSchema, { ...ok, format: "xml" }), [
      ["format", enumMsg(["json", "slack"], "xml")],
    ]);
  });
});

describe("llm settings form", () => {
  const PROVIDERS = ["openai", "anthropic", "gemini", "azure_openai", "ollama"];
  const empty = {
    api_key: "",
    model: "",
    azure_endpoint: "",
    azure_deployment: "",
    ollama_url: "",
  };
  test("key required for non-ollama providers when none is configured", () => {
    const s = buildLlmSettingsSchema(PROVIDERS, true);
    for (const provider of PROVIDERS.filter((p) => p !== "ollama")) {
      for (const api_key of ["", "***", undefined]) {
        assert.deepEqual(issuesOf(s, { ...empty, provider, api_key }), [
          ["api_key", "api_key_required"],
        ]);
      }
      accept(s, { ...empty, provider, api_key: "sk-real" });
    }
    accept(s, { ...empty, provider: "ollama" });
  });
  test("placeholder accepted once a key is configured; defaults fill blanks", () => {
    const s = buildLlmSettingsSchema(PROVIDERS, false);
    assert.deepEqual(accept(s, { provider: "openai" }), { provider: "openai", ...empty });
    accept(s, { ...empty, provider: "anthropic", api_key: "***" });
  });
  test("endpoint fields are free text (no client-side URL check, as before)", () => {
    // Backend egress policy owns endpoint validation; the form never had a
    // URL check here and must not grow a looser or different one silently.
    const s = buildLlmSettingsSchema(PROVIDERS, false);
    for (const v of ["", "http://localhost:11434", "not a url", "javascript:alert(1)"]) {
      accept(s, { ...empty, provider: "azure_openai", azure_endpoint: v, ollama_url: v });
    }
  });
  test("unknown provider rejected", () => {
    assert.deepEqual(issuesOf(buildLlmSettingsSchema(PROVIDERS, true), { ...empty, provider: "nope" }), [
      ["provider", enumMsg(PROVIDERS, "nope")],
    ]);
  });
});

describe("malformed value types keep zod 3's messages (Codex R1 Low)", () => {
  // Only reachable through programmatic form state (reset/setValue), since
  // HTML controls produce strings — but these fields render the message
  // verbatim. Expected texts were read from zod 3 (the zod/v3 subpath).
  const STATES = ["not_affected", "affected", "under_investigation", "resolved"];
  // First issue per field = what zodResolver hands react-hook-form (default
  // criteriaMode "firstError") = what the UI renders. Compared that way
  // because zod 4 also runs a length check (min/max) on an ARRAY input after
  // the type failure (arrays have `length`); that extra issue never surfaces.
  const firstPerField = (schema, value) => {
    const seen = new Map();
    for (const [p, m] of issuesOf(schema, value)) if (!seen.has(p)) seen.set(p, m);
    return [...seen];
  };
  test("string fields", () => {
    for (const [v, t] of [[1, "number"], [null, "null"], [[], "array"], [true, "boolean"], [{}, "object"], [NaN, "nan"], [new Date(0), "date"]]) {
      assert.deepEqual(firstPerField(reportEditSchema, { draft_text: v, decision_note: "" }), [
        ["draft_text", `Expected string, received ${t}`],
      ]);
      assert.deepEqual(
        firstPerField(reportSubmitSchema, { authority: v, submitted_at: "", reference_number: "", notes: "" }),
        [["authority", `Expected string, received ${t}`]],
      );
      assert.deepEqual(firstPerField(triageEditSchema, { state: "affected", justification: "", detail: v, note: "" }), [
        ["detail", `Expected string, received ${t}`],
      ]);
    }
    assert.deepEqual(firstPerField(reportEditSchema, { decision_note: "" }), [["draft_text", "Required"]]);
    // zod 3 classified any thenable (callable then + catch) as "promise" (Codex R2 Low).
    const thenable = { then() {}, catch() {} };
    assert.deepEqual(firstPerField(reportEditSchema, { draft_text: thenable, decision_note: "" }), [
      ["draft_text", "Expected string, received promise"],
    ]);
    // ...checked BEFORE the built-in classes (Codex R4 Low).
    const thenableDate = Object.assign(new Date(0), { then() {}, catch() {} });
    assert.deepEqual(firstPerField(reportEditSchema, { draft_text: thenableDate, decision_note: "" }), [
      ["draft_text", "Expected string, received promise"],
    ]);
  });
  test("enum fields", () => {
    const exp = STATES.map((v) => `'${v}'`).join(" | ");
    for (const [v, t] of [[1, "number"], [null, "null"], [[], "array"], [NaN, "nan"], [new Date(0), "date"]]) {
      assert.deepEqual(issuesOf(triageEditSchema, { state: v, justification: "", detail: "", note: "" }), [
        ["state", `Expected ${exp}, received ${t}`],
      ]);
    }
    assert.deepEqual(issuesOf(triageEditSchema, { justification: "", detail: "", note: "" }), [["state", "Required"]]);
  });
});

// ---------------------------------------------------------------------------
// Through zodResolver: what react-hook-form actually receives. The resolver
// is upgraded together with zod, and it decides which issue becomes
// `errors.<field>.message` and which values reach onSubmit. `type` (the zod
// issue code) is deliberately NOT pinned: no form reads it, and zod 4
// renamed several codes.
// ---------------------------------------------------------------------------
const RESOLVER_OPTS = { fields: {}, shouldUseNativeValidation: false };
async function resolve(schema, values) {
  const r = await zodResolver(schema)(values, undefined, RESOLVER_OPTS);
  const messages = Object.fromEntries(
    Object.entries(r.errors).map(([k, v]) => [k, v.message]),
  );
  return { values: r.values, messages };
}

describe("zodResolver contract", () => {
  test("cra edit: first message per field", async () => {
    assert.deepEqual(
      await resolve(reportEditSchema, { draft_text: "", decision_note: "x".repeat(2001) }),
      {
        values: {},
        messages: { draft_text: "draft_text is required", decision_note: maxMsg(2000) },
      },
    );
  });
  test("cra submit: authority over-length", async () => {
    const { messages } = await resolve(reportSubmitSchema, {
      authority: "a".repeat(256),
      submitted_at: "",
      reference_number: "",
      notes: "",
    });
    assert.deepEqual(messages, { authority: maxMsg(255) });
  });
  test("triage: state + detail messages", async () => {
    const { messages } = await resolve(triageEditSchema, {
      state: "bogus",
      justification: "",
      detail: "d".repeat(4001),
      note: "",
    });
    assert.deepEqual(messages, {
      state: enumMsg(["not_affected", "affected", "under_investigation", "resolved"], "bogus"),
      detail: maxMsg(4000),
    });
  });
  test("meti clear-override: submitted value is the TRIMMED note", async () => {
    assert.deepEqual(await resolve(criterionClearOverrideSchema, { note: "  why  " }), {
      values: { note: "why" },
      messages: {},
    });
    assert.deepEqual((await resolve(criterionClearOverrideSchema, { note: "  " })).messages, {
      note: "note must be 1..4096 characters after trim",
    });
  });
  test("meti override: blank reason is flagged, so the PUT is never sent", async () => {
    const { values, messages } = await resolve(criterionOverrideSchema, {
      override_status: "not_applicable",
      override_note: "  ",
      improvement_action: "",
    });
    assert.deepEqual(values, {});
    assert.deepEqual(messages, { override_note: "override_note is required" });
  });
  test("meti override: status + note flagged", async () => {
    const { messages } = await resolve(criterionOverrideSchema, {
      override_status: "",
      override_note: "n".repeat(2001),
      improvement_action: "",
    });
    assert.deepEqual(Object.keys(messages), ["override_status", "override_note"]);
  });
  test("diff-webhook: url key + threshold flagged together; numbers reach onSubmit", async () => {
    const base = {
      enabled: true,
      webhook_url: "",
      webhook_secret: "",
      format: "json",
      critical_threshold: "-1",
      high_threshold: "5",
      license_violation_threshold: "0",
    };
    const bad = await resolve(diffWebhookSchema, base);
    assert.deepEqual(Object.keys(bad.messages).sort(), ["critical_threshold", "webhook_url"]);
    assert.equal(bad.messages.webhook_url, "url_required");
    assert.equal(
      (await resolve(diffWebhookSchema, { ...base, critical_threshold: "1", webhook_url: "javascript:alert(1)" }))
        .messages.webhook_url,
      "url_protocol",
    );
    const good = await resolve(diffWebhookSchema, {
      ...base,
      critical_threshold: "2",
      webhook_url: "https://example.com/h",
    });
    assert.deepEqual(good, {
      values: { ...base, critical_threshold: 2, high_threshold: 5, license_violation_threshold: 0, webhook_url: "https://example.com/h" },
      messages: {},
    });
  });
  test("llm: api_key_required key", async () => {
    const s = buildLlmSettingsSchema(["openai", "ollama"], true);
    assert.deepEqual((await resolve(s, { provider: "openai", api_key: "***" })).messages, {
      api_key: "api_key_required",
    });
  });
});
