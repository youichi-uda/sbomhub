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
      return `Expected ${expected}, received ${input === null ? "null" : typeof input}`;
    },
  };
}
