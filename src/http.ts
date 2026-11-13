/**
 * Stateless Streamable HTTP: one server and transport per request, no session ids.
 *
 * Works the same on a long-running process and on serverless hosts (Vercel,
 * Cloudflare Workers, Deno Deploy), because nothing has to survive between calls.
 * The only thing worth keeping warm is the 24-hour Garmin bearer token, held in a
 * process-wide TokenProvider.
 */
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { timingSafeEqual } from "node:crypto";
import { TokenProvider, resolveApiKey } from "./auth.js";
import { GarminClient } from "./client.js";
import { buildServer } from "./server.js";

export interface FetchHandlerOptions {
  apiKey?: string;
  apiKeyFile?: string;
  /** Clients must send `Authorization: Bearer <bearerToken>`. Required: this is your health data. */
  bearerToken: string;
  /** Path(s) the handler answers on. Default "/mcp". */
  path?: string | string[];
}

export function createFetchHandler(opts: FetchHandlerOptions): (request: Request) => Promise<Response> {
  if (!opts.bearerToken) throw new Error("bearerToken is required for HTTP mode");
  const expected = Buffer.from(opts.bearerToken);
  const paths = new Set(Array.isArray(opts.path) ? opts.path : [opts.path ?? "/mcp"]);
  let garmin: Promise<GarminClient> | undefined;
  const client = () =>
    (garmin ??= resolveApiKey(opts).then((apiKey) => new GarminClient(new TokenProvider({ apiKey }))));

  return async (request) => {
    const url = new URL(request.url);
           // Accept the secret either as `Authorization: Bearer <token>` on /mcp, or as the
       // last path segment (/mcp/<token>) for clients that cannot send custom headers.
       let fromPath: string | undefined;
       if (!paths.has(url.pathname)) {
         const slash = url.pathname.lastIndexOf("/");
         const base = url.pathname.slice(0, slash);
         const segment = url.pathname.slice(slash + 1);
         if (slash <= 0 || !paths.has(base) || !segment) return new Response("Not found", { status: 404 });
         try {
           fromPath = decodeURIComponent(segment);
         } catch {
           return new Response("Not found", { status: 404 });
         }
       }
       const given = Buffer.from(fromPath ?? request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "");
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      return new Response("Unauthorized", { status: 401, headers: { "WWW-Authenticate": "Bearer" } });
    }
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = buildServer(await client());
    await server.connect(transport);
    try {
      return await transport.handleRequest(request);
    } finally {
      // Nothing to keep: the next request builds its own.
      void transport.close().catch(() => {});
    }
  };
}
