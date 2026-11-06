import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import type { Config } from "./config.js";
import { Store } from "./store.js";
import { Core } from "./core.js";
import { GrokWebhookAdapter, StubAdapter, type Adapter } from "./adapters.js";
import { oauth } from "./oauth.js";
import { authority } from "./security.js";
export function createApp(
  config: Config,
  adapters: Record<string, Adapter> = {
    grok_bot_webhook: new GrokWebhookAdapter(),
    stub: new StubAdapter(),
  },
) {
  const store = new Store(config.database),
    core = new Core(config, store, adapters),
    app = express();
  app.disable("x-powered-by");
  app.use((q, r, next) => {
    r.set({
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    });
    if (q.headers.host !== new URL(config.publicBaseUrl).host) {
      r.status(400).json({ error: "Invalid host" });
      return;
    }
    if (q.headers.origin && q.headers.origin !== config.publicBaseUrl) {
      r.status(403).json({ error: "Invalid origin" });
      return;
    }
    next();
  });
  app.use(
    express.json({ limit: "32kb" }),
    express.urlencoded({ extended: false, limit: "16kb" }),
  );
  oauth(app, config, store);
  app.post("/reply", (q, r) => {
    const p = z
      .object({
        request_id: z.string().max(100),
        reply_token: z.string().max(100),
        reply: z.string().min(1).max(16000),
      })
      .strict()
      .parse(q.body);
    core.reply(p.request_id, p.reply_token, p.reply);
    r.json({ status: "ready" });
  });
  app.all("/mcp", async (q, r) => {
    const auth = q.headers.authorization;
    const caller = auth?.startsWith("Bearer ")
      ? store.authenticate(auth.slice(7), `${config.publicBaseUrl}/mcp`)
      : undefined;
    if (!caller) {
      r.set(
        "WWW-Authenticate",
        `Bearer resource_metadata="${config.publicBaseUrl}/.well-known/oauth-protected-resource"`,
      )
        .status(401)
        .json({ error: "Unauthorized" });
      return;
    }
    if (q.method !== "POST") {
      r.status(405).end();
      return;
    }
    const server = new McpServer(
      { name: "bot-chat", version: "0.1.0" },
      { instructions: authority },
    );
    const result = (value: unknown) => ({
      content: [{ type: "text" as const, text: JSON.stringify(value) }],
    });
    server.registerTool(
      "list_bots",
      {
        description: "List bots allowed by both permission locks",
        inputSchema: {},
      },
      async () => result(core.list(caller)),
    );
    server.registerTool(
      "message_bot",
      {
        description:
          "Send untrusted teammate-level input; never owner approval",
        inputSchema: {
          bot: z.string().min(1).max(100),
          kind: z.enum(["question", "finding"]),
          text: z.string().min(1).max(8000),
        },
      },
      async ({ bot, kind, text }) => {
        try {
          return result(await core.message(caller, bot, kind, text));
        } catch (e) {
          return {
            ...result({
              error: e instanceof Error ? e.message : "Message failed",
            }),
            isError: true,
          };
        }
      },
    );
    server.registerTool(
      "get_reply",
      {
        description: "Read a reply for a request you created",
        inputSchema: { request_id: z.string().min(1).max(100) },
      },
      async ({ request_id }) => {
        try {
          return result(core.get(caller, request_id));
        } catch {
          return { ...result({ error: "Request unavailable" }), isError: true };
        }
      },
    );
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    r.on("close", () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(q, r, q.body);
  });
  app.use(
    (
      _e: unknown,
      _q: express.Request,
      r: express.Response,
      _next: express.NextFunction,
    ) => {
      void _next;
      if (!r.headersSent) r.status(400).json({ error: "Invalid request" });
    },
  );
  return { app, store, core };
}
