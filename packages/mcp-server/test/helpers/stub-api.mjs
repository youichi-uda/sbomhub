// Hermetic stand-in for the SBOMHub API.
//
// These tests exist to catch the class of defect fixed in bad1b8c: a tool
// DESCRIPTION that says something the tool does not do. The only way to check
// that mechanically is to observe what the server actually sends, so every
// request the MCP server issues is recorded here (method, path, query, body,
// headers) and asserted against.
//
// Constraints this file is built under:
//   - no docker, no port from the workspace's reserved set: the listener binds
//     127.0.0.1:0 and the kernel picks an ephemeral port, so any number of these
//     can run concurrently (including alongside other agents' containers);
//   - no outbound network: the MCP server is started with SBOMHUB_API_URL
//     pointing at this stub, and `redirect: "error"` in the client means it
//     cannot be talked into leaving it (error-paths.test.mjs pins that).
import http from "node:http";
import { once } from "node:events";

// A path segment that is a UUID is a route parameter. Echo registers the MCP
// per-project routes as `/api/v1/mcp/projects/:id/...`, and
// apps/api/internal/middleware/project_scope.go keys its authority table by
// that REGISTERED path — so an observed concrete path has to be folded back to
// the same shape before it can be looked up. Doing it by shape (rather than by
// a hardcoded list of routes) means a new per-project route is folded too.
const UUID_SEGMENT =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function toRoutePattern(pathname) {
  return pathname
    .split("/")
    .map((seg) => (UUID_SEGMENT.test(seg) ? ":id" : seg))
    .join("/");
}

export function routeKeyOf(method, pathname) {
  return `${method} ${toRoutePattern(pathname)}`;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function parseJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

/**
 * Start the stub. Returns a handle whose `routes` / `use` swap the responder
 * between tests, so one listener (and one MCP server subprocess) serves a whole
 * test file.
 */
export async function startStubApi() {
  /** @type {Array<object>} */
  const requests = [];
  let handler = () => undefined;
  let inFlight = 0;
  let lastArrivalAt = 0;

  const server = http.createServer((req, res) => {
    inFlight += 1;
    res.on("close", () => {
      inFlight -= 1;
    });
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      lastArrivalAt = Date.now();
      const raw = Buffer.concat(chunks).toString("utf8");
      const url = new URL(req.url, "http://stub.invalid");
      const record = {
        method: req.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams.entries()),
        search: url.search,
        headers: req.headers,
        rawBody: raw,
        body: raw ? parseJson(raw) : undefined,
        routeKey: routeKeyOf(req.method, url.pathname),
      };
      requests.push(record);

      let reply;
      try {
        reply = handler(record, requests.length - 1);
      } catch (err) {
        reply = {
          status: 599,
          body: { error: `stub handler threw: ${err && err.message}` },
        };
      }
      if (reply === undefined || reply === null) {
        // Unrouted. Answering 404 (rather than hanging or crashing) keeps the
        // failure legible: the tool reports the error in-band and the
        // `requests` assertion names the route that was not expected.
        reply = {
          status: 404,
          body: { error: `stub: no route registered for ${record.routeKey}` },
        };
      }

      const status = reply.status ?? 200;
      const headers = { "Content-Type": "application/json", ...reply.headers };
      const payload =
        reply.raw !== undefined ? reply.raw : JSON.stringify(reply.body ?? null);
      res.writeHead(status, headers);
      res.end(payload);
    });
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    /** Install a raw responder: (record) => {status, body, headers, raw}. */
    use(fn) {
      handler = fn;
    },
    /** Install a responder keyed by "<METHOD> <registered path>". */
    routes(map) {
      handler = (record, index) => {
        const entry = map[record.routeKey];
        if (entry === undefined) return undefined;
        return typeof entry === "function" ? entry(record, index) : entry;
      };
    },
    /**
     * Wait until at least `n` requests have been recorded.
     *
     * A tool that fans out with Promise.all resolves as soon as ONE leg
     * rejects, while its siblings are still in flight. Comparing the request
     * log at that moment is a race — and worse, the stragglers would land in
     * the NEXT test's log after reset(). Both directions of that race were
     * reproduced in a stress run (Codex R1, Medium).
     */
    async waitFor(n, timeoutMs = 5000) {
      const deadline = Date.now() + timeoutMs;
      while (requests.length < n) {
        if (Date.now() > deadline) {
          throw new Error(
            `timed out waiting for ${n} requests; saw ${requests.length}: ` +
              requests.map((r) => r.routeKey).join(", ")
          );
        }
        await sleep(2);
      }
    },
    /**
     * Wait until nothing has arrived for `idleMs` and no response is still
     * open. Used after each tool call: it makes "exactly these requests" mean
     * exactly, by giving an unexpected extra request time to show up, and
     * guarantees no straggler can leak past the next reset().
     *
     * The window is measured from the LATER of the last arrival and this call,
     * so it always waits at least `idleMs`. Without that, a test asserting
     * that NO request was sent would return instantly (nothing has arrived, so
     * the log has been "idle" since the epoch) and would pass even if the
     * request it forbids were about to land.
     */
    async quiet(idleMs = 25, timeoutMs = 5000) {
      const calledAt = Date.now();
      const deadline = calledAt + timeoutMs;
      for (;;) {
        const idleFor = Date.now() - Math.max(lastArrivalAt, calledAt);
        if (inFlight === 0 && idleFor >= idleMs) return;
        if (Date.now() > deadline) {
          throw new Error(
            `stub never went quiet: inFlight=${inFlight}, last arrival ${idleFor}ms ago`
          );
        }
        await sleep(5);
      }
    },
    reset() {
      requests.length = 0;
      lastArrivalAt = 0;
      handler = () => undefined;
    },
    async close() {
      server.closeAllConnections?.();
      server.close();
      await once(server, "close");
    },
  };
}
