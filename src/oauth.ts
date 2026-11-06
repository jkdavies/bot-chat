import type { Express, Request, Response } from "express";
import { z } from "zod";
import { publicIPv4 } from "./network.js";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { Config } from "./config.js";
import { Store } from "./store.js";
import {
  escapeHtml as esc,
  token,
  hash,
  verifyPassword,
  readSecretFile,
} from "./security.js";
const metadata = z.object({
  client_name: z.string().min(1).max(100),
  redirect_uris: z.array(z.string().url()).min(1).max(10),
  token_endpoint_auth_method: z.literal("none").default("none"),
  grant_types: z
    .array(z.enum(["authorization_code", "refresh_token"]))
    .optional(),
  response_types: z.array(z.literal("code")).optional(),
  client_id: z.string().optional(),
});
type Metadata = z.infer<typeof metadata>;
function validRedirect(s: string) {
  const u = new URL(s);
  return (
    !u.username &&
    !u.password &&
    !u.hash &&
    (u.protocol === "https:" ||
      (u.protocol === "http:" &&
        ["127.0.0.1", "[::1]", "localhost"].includes(u.hostname)))
  );
}
function page(res: Response, body: string) {
  res
    .type("html")
    .send(
      `<!doctype html><html lang="en"><meta charset="utf-8"><title>bot-chat</title><body>${body}</body></html>`,
    );
}
export function oauth(app: Express, c: Config, s: Store) {
  const base = c.publicBaseUrl,
    resource = `${base}/mcp`,
    sessions = new Map<string, { csrf: string; expires: number }>(),
    pending = new Map<
      string,
      { params: Record<string, string>; client: Metadata; expires: number }
    >();
  app.use((q, r, next) => {
    for (const [key, v] of sessions)
      if (v.expires < Date.now()) sessions.delete(key);
    for (const [key, v] of pending)
      if (v.expires < Date.now()) pending.delete(key);
    if (sessions.size > 1000 || pending.size > 1000) {
      r.status(503).json({ error: "Try later" });
      return;
    }
    next();
  });
  const ownerHash = readSecretFile(c.ownerHashFile).trim();
  const session = (req: Request) => {
    const cookie = req.headers.cookie
      ?.split(";")
      .map((x) => x.trim())
      .find((x) => x.startsWith("owner="))
      ?.slice(6);
    const v = cookie ? sessions.get(hash(cookie)) : undefined;
    return v && v.expires > Date.now() ? v : undefined;
  };
  const failures = new Map<string, { count: number; at: number }>();
  app.get("/.well-known/oauth-protected-resource", (_q, r) =>
    r.json({
      resource,
      authorization_servers: [base],
      scopes_supported: ["bots", "offline_access"],
    }),
  );
  app.get("/.well-known/oauth-authorization-server", (_q, r) =>
    r.json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["bots", "offline_access"],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    }),
  );
  app.post("/register", (q, r) => {
    const m = metadata.parse(q.body);
    if (!m.redirect_uris.every(validRedirect))
      throw Error("Invalid registration");
    const id = token();
    s.db.prepare("INSERT INTO clients VALUES(?,?)").run(id, JSON.stringify(m));
    r.status(201).json({ ...m, client_id: id });
  });
  async function client(id: string) {
    const row = s.db
      .prepare("SELECT metadata FROM clients WHERE id=?")
      .get(id) as { metadata: string } | undefined;
    if (row) return metadata.parse(JSON.parse(row.metadata));
    const u = new URL(id);
    if (
      u.protocol !== "https:" ||
      u.username ||
      u.password ||
      u.hash ||
      isIP(u.hostname)
    )
      throw Error("Invalid client");
    const ips = (await lookup(u.hostname, { all: true })).filter(
      (x) => x.family === 4 && publicIPv4(x.address),
    );
    if (
      !ips.length ||
      ips.some((x) => x.family !== 4 || !publicIPv4(x.address))
    )
      throw Error("Invalid client");
    // Pin DNS resolution through a custom HTTPS request; disallow redirects and private addresses.
    const { request } = await import("node:https");
    const body = await new Promise<string>((resolve, reject) => {
      const req = request(
        u,
        {
          family: 4,
          lookup: (_host, _opts, cb) => cb(null, ips[0].address, 4),
          timeout: 5000,
          headers: { Accept: "application/json" },
        },
        (res) => {
          if (res.statusCode !== 200) {
            res.resume();
            reject(Error("Invalid client"));
            return;
          }
          let body = "";
          res.on("data", (chunk) => {
            body += chunk;
            if (body.length > 16384) req.destroy(Error("Too large"));
          });
          res.on("end", () => resolve(body));
        },
      );
      req.on("timeout", () => req.destroy(Error("Timeout")));
      req.on("error", reject);
      req.end();
    });
    const m = metadata.parse(JSON.parse(body));
    if (m.client_id !== id || !m.redirect_uris.every(validRedirect))
      throw Error("Invalid client");
    return m;
  }
  app.get("/authorize", async (q, r) => {
    const p = z
      .object({
        client_id: z.string(),
        redirect_uri: z.string(),
        response_type: z.literal("code"),
        code_challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
        code_challenge_method: z.literal("S256"),
        resource: z.literal(resource),
        state: z.string().max(2048).optional(),
        scope: z.string().default("bots"),
      })
      .parse(q.query);
    if (p.scope.split(" ").some((x) => !["bots", "offline_access"].includes(x)))
      throw Error("Invalid scope");
    const m = await client(p.client_id);
    if (!m.redirect_uris.includes(p.redirect_uri))
      throw Error("Invalid redirect");
    const id = token();
    pending.set(hash(id), {
      params: p,
      client: m,
      expires: Date.now() + 300000,
    });
    page(
      r,
      `<h1>Authorize ${esc(m.client_name)}</h1><p>Message opted-in bots and read their replies. This client receives teammate-level authority only.</p><form method="post" action="/consent"><input type="hidden" name="pending" value="${id}"><label>Owner password <input type="password" name="password" required maxlength="1024"></label><button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form>`,
    );
  });
  function password(req: Request) {
    const key = req.socket.remoteAddress ?? "unknown",
      now = Date.now();
    for (const [k, v] of failures) if (now - v.at > 900000) failures.delete(k);
    if (failures.size > 1000) throw Error("Try later");
    let f = failures.get(key);
    if (!f || now - f.at > 900000) {
      f = { count: 0, at: now };
      failures.set(key, f);
    }
    if (f.count >= 10) throw Error("Try later");
    f.count++;
    if (!verifyPassword(String(req.body.password ?? ""), ownerHash))
      throw Error("Unauthorized");
    f.count = 0;
  }
  app.post("/consent", (q, r) => {
    password(q);
    const key = hash(String(q.body.pending)),
      p = pending.get(key);
    pending.delete(key);
    if (!p || p.expires < Date.now()) throw Error("Expired consent");
    const redirect = new URL(p.params.redirect_uri);
    redirect.searchParams.set("iss", base);
    if (p.params.state) redirect.searchParams.set("state", p.params.state);
    if (q.body.decision !== "approve") {
      redirect.searchParams.set("error", "access_denied");
      r.redirect(redirect.href);
      return;
    }
    let caller = s.caller(p.params.client_id);
    if (caller?.revoked) throw Error("Revoked client");
    if (
      !caller &&
      s.db
        .prepare("SELECT id FROM callers WHERE name=?")
        .get(p.client.client_name)
    )
      throw Error("Caller name already used");
    if (!caller)
      caller = s.createCaller(
        p.client.client_name,
        "oauth",
        c.bots.filter((b) => b.optedIn).map((b) => b.id),
        p.params.client_id,
      );
    if (!s.active(caller)) throw Error("Disabled client");
    const code = s.grant(
      "code",
      caller.id,
      p.params.client_id,
      resource,
      60000,
      {
        challenge: p.params.code_challenge,
        redirect: p.params.redirect_uri,
        scope: p.params.scope,
      },
    );
    redirect.searchParams.set("code", code);
    r.redirect(redirect.href);
  });
  app.post("/token", (q, r) => {
    r.set("Cache-Control", "no-store");
    if (!q.is("application/x-www-form-urlencoded")) {
      r.status(400).json({ error: "invalid_request" });
      return;
    }
    const type =
      q.body.grant_type === "authorization_code"
        ? "code"
        : q.body.grant_type === "refresh_token"
          ? "refresh"
          : null;
    if (!type) {
      r.status(400).json({ error: "unsupported_grant_type" });
      return;
    }
    const result = s.db.transaction(() => {
      const raw = String(
          q.body[type === "code" ? "code" : "refresh_token"] ?? "",
        ),
        g = s.take(raw, type, true);
      if (
        !g ||
        g.client !== q.body.client_id ||
        g.resource !== q.body.resource ||
        !s.active(s.caller(g.caller))
      )
        return null;
      const data = JSON.parse(g.data) as {
        challenge?: string;
        redirect?: string;
        scope: string;
      };
      if (
        type === "code" &&
        (!/^[A-Za-z0-9._~-]{43,128}$/.test(String(q.body.code_verifier)) ||
          hash(String(q.body.code_verifier)) !== data.challenge ||
          q.body.redirect_uri !== data.redirect)
      )
        return null;
      return {
        access_token: s.grant(
          "access",
          g.caller,
          g.client,
          resource,
          c.accessTtlSeconds * 1000,
        ),
        token_type: "Bearer",
        expires_in: c.accessTtlSeconds,
        scope: data.scope,
        ...(data.scope.split(" ").includes("offline_access")
          ? {
              refresh_token: s.grant(
                "refresh",
                g.caller,
                g.client,
                resource,
                30 * 86400000,
                data,
              ),
            }
          : {}),
      };
    })();
    if (!result) {
      r.status(400).json({ error: "invalid_grant" });
      return;
    }
    r.json(result);
  });
  app.get("/admin", (q, r) => {
    const sess = session(q);
    if (!sess) {
      page(
        r,
        '<h1>Owner sign-in</h1><form method="post" action="/admin/login"><input type="password" name="password" required maxlength="1024"><button>Sign in</button></form>',
      );
      return;
    }
    const callers = s.db
      .prepare("SELECT id,name,enabled,revoked,allowed FROM callers")
      .all() as {
      id: string;
      name: string;
      enabled: number;
      revoked: number;
      allowed: string;
    }[];
    page(
      r,
      `<h1>Callers</h1>${callers.map((x) => `<p>${esc(x.name)} enabled=${x.enabled} revoked=${x.revoked} bots=${esc(x.allowed)}</p><form method="post" action="/admin/caller"><input type="hidden" name="csrf" value="${sess.csrf}"><input type="hidden" name="id" value="${esc(x.id)}"><input name="allowed" placeholder="Comma-separated bot ids"><button name="action" value="allow">Set bots</button><button name="action" value="disable">Disable</button><button name="action" value="enable">Enable</button><button name="action" value="revoke">Revoke</button><button name="action" value="rotate">Rotate API token</button></form>`).join("")}<form method="post" action="/admin/mint"><input type="hidden" name="csrf" value="${sess.csrf}"><input name="name" required maxlength="100" placeholder="Caller name"><input name="allowed" placeholder="Comma-separated bot ids"><button>Mint API token</button></form>`,
    );
  });
  app.post("/admin/login", (q, r) => {
    password(q);
    const raw = token();
    sessions.set(hash(raw), { csrf: token(), expires: Date.now() + 1800000 });
    r.setHeader(
      "Set-Cookie",
      `owner=${raw}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=1800${base.startsWith("https:") ? "; Secure" : ""}`,
    );
    r.redirect("/admin");
  });
  function csrf(q: Request) {
    const v = session(q);
    if (
      !v ||
      q.body.csrf !== v.csrf ||
      (q.headers.origin && q.headers.origin !== base)
    )
      throw Error("Unauthorized");
  }
  function allowed(q: Request) {
    const ids = String(q.body.allowed ?? "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    if (ids.some((id) => !c.bots.some((b) => b.id === id)))
      throw Error("Unknown bot");
    return ids;
  }
  app.post("/admin/mint", (q, r) => {
    csrf(q);
    const name = z.string().trim().min(1).max(100).parse(q.body.name);
    if (s.db.prepare("SELECT id FROM callers WHERE name=?").get(name))
      throw Error("Name already used");
    const caller = s.createCaller(name, "api_token", allowed(q));
    page(
      r,
      `<h1>Save this token now; shown once</h1><code>${s.mintApi(caller)}</code>`,
    );
  });
  app.post("/admin/caller", (q, r) => {
    csrf(q);
    const caller = s.caller(String(q.body.id));
    if (!caller) throw Error("Unknown caller");
    switch (q.body.action) {
      case "allow":
        s.db
          .prepare("UPDATE callers SET allowed=? WHERE id=?")
          .run(JSON.stringify(allowed(q)), caller.id);
        break;
      case "disable":
        s.db.prepare("UPDATE callers SET enabled=0 WHERE id=?").run(caller.id);
        break;
      case "enable":
        s.db
          .prepare("UPDATE callers SET enabled=1 WHERE id=? AND revoked=0")
          .run(caller.id);
        break;
      case "revoke":
        s.db
          .prepare("UPDATE callers SET revoked=1,secret_hash=NULL WHERE id=?")
          .run(caller.id);
        s.db.prepare("DELETE FROM grants WHERE caller=?").run(caller.id);
        break;
      case "rotate":
        if (caller.kind !== "api_token" || !s.active(caller))
          throw Error("Unavailable");
        page(
          r,
          `<h1>Save this token now; shown once</h1><code>${s.mintApi(caller)}</code>`,
        );
        return;
      default:
        throw Error("Unknown action");
    }
    r.redirect("/admin");
  });
}
