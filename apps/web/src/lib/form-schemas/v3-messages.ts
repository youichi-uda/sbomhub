// zod 3 default error texts that the web forms render, reproduced under zod 4.
//
// zod 4 reworded its default messages ("String must contain at most 4000
// character(s)" → "Too big: expected string to have <=4000 characters",
// "Invalid enum value. Expected 'a' | 'b', received 'x'" → "Invalid option:
// expected one of \"a\"|\"b\""). Several forms render `errors.<field>.message`
// verbatim (cra draft_text / authority, triage state / detail), so the zod 3
// texts are a user-visible contract; ./__tests__/form-schemas.test.mjs pins
// them. Every max-length and enum check in these schemas goes through these
// helpers so a field that starts rendering its message keeps the same words.
//
// Imported with an explicit `.ts` extension so `node --test` (type stripping,
// no resolver) can load the schema modules directly.

/** zod 3 `.max(n)` message for strings. */
export function maxChars(n: number): { error: string } {
  return { error: `String must contain at most ${n} character(s)` };
}

/** zod 3's name for a value's type, as used in "received <type>". */
function v3TypeName(input: unknown): string {
  if (input === null) return "null";
  if (Array.isArray(input)) return "array";
  if (input instanceof Date) return "date";
  if (input instanceof Map) return "map";
  if (input instanceof Set) return "set";
  if (
    (typeof Promise !== "undefined" && input instanceof Promise) ||
    (typeof input === "object" &&
      typeof (input as { then?: unknown }).then === "function" &&
      typeof (input as { catch?: unknown }).catch === "function")
  ) {
    return "promise"; // zod 3 treats any thenable with catch() as a promise
  }
  if (typeof input === "number" && Number.isNaN(input)) return "nan";
  return typeof input;
}

/**
 * zod 3 messages for a wrong-typed string: "Required" when missing,
 * "Expected string, received <type>" otherwise. Pass to z.string(...).
 */
export const stringError = {
  error: (issue: { input?: unknown }) =>
    issue.input === undefined
      ? "Required"
      : `Expected string, received ${v3TypeName(issue.input)}`,
};

/** zod 3 `z.enum(values)` messages: invalid option, missing value, wrong type. */
export function enumError(values: readonly string[]) {
  const expected = values.map((v) => `'${v}'`).join(" | ");
  return {
    error: (issue: { input?: unknown }) => {
      const input = issue.input;
      if (input === undefined) return "Required";
      if (typeof input === "string") {
        return `Invalid enum value. Expected ${expected}, received '${input}'`;
      }
      return `Expected ${expected}, received ${v3TypeName(input)}`;
    },
  };
}
