// zod 4 building blocks that keep the zod 3 contract of this server.
//
// The server moved from zod 3.25 to zod 4 for GHSA-mrhx-c7xc-m3w5 (fixed only
// in zod >= 4.6.6). Two zod 4 defaults would otherwise have changed what MCP
// clients are told and what the server accepts; test/schema-equivalence.test.mjs
// compares tools/list to the zod 3 capture byte-for-byte and pins both.
import { z } from "zod";

// zod 3's uuid() accepted ANY 8-4-4-4-12 hex string. zod 4's uuid() enforces
// RFC 9562 version/variant bits, and its z.guid() (which keeps the zod 3
// acceptance) advertises an extra `pattern` in tools/list. A plain refinement
// plus `format: "uuid"` metadata reproduces the zod 3 acceptance, error
// message and advertised schema exactly. Postgres' uuid type accepts every id
// this does, so tightening here would refuse ids the backend can hold.
const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function uuidString() {
  return z
    .string()
    .refine((s) => GUID.test(s), { error: "Invalid uuid" })
    .meta({ format: "uuid" });
}

// zod 3 (through the SDK's vendored zod-to-json-schema) advertised every tool
// input object with `additionalProperties: false`. zod 4's toJSONSchema, in
// the "input" mode the SDK uses, omits it for a default (strip) object. The
// metadata restores the advertised flag ONLY: runtime parsing stays strip —
// unknown keys are dropped, not refused — exactly as under zod 3. A
// z.strictObject would start refusing calls that clients send today.
export function toolInput<Shape extends z.ZodRawShape>(shape: Shape) {
  return z.object(shape).meta({ additionalProperties: false });
}
