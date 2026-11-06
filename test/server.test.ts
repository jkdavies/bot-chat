import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/server.js";
import { configSchema } from "../src/config.js";
import { passwordHash, hash, token } from "../src/security.js";
import type { Wake } from "../src/adapters.js";
async function fixture(spacingMs = 0) {
  const dir = mkdtempSync(join(tmpdir(), "bot-chat-"));
  const password = "fixture-only-owner-password";
  writeFileSync(join(dir, "owner.hash"), passwordHash(password), {
    mode: 0o600,
  });
  const http = createServer();
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  const config = configSchema.parse({
    publicBaseUrl: base,
    database: join(dir, "test.sqlite"),
    ownerHashFile: join(dir, "owner.hash"),
    limits: { spacingMs },
    bots: [
      {
        id: "research-bot",
        name: "Research",
        description: "Example bot",
        optedIn: true,
        adapter: "stub",
      },
      {
        id: "off-bot",
        name: "Off",
        description: "Off",
        optedIn: false,
        adapter: "stub",
      },
    ],
  });
  const wakes: Wake[] = [];
  const f = createApp(config, {
    stub: {
      async wake(_b, p) {
        wakes.push(p);
        return true;
      },
    },
  });
  http.on("request", f.app);
  const caller = f.store.createCaller("fixture-agent", "api_token", [
    "research-bot",
    "off-bot",
  ]);
  const api = f.store.mintApi(caller);
  const req = (
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ) =>
    fetch(base + path, {
      method: body === undefined ? "GET" : "POST",
      redirect: "manual",
      headers: {
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...headers,
      },
      body:
        body === undefined
          ? undefined
          : typeof body === "string"
            ? body
            : JSON.stringify(body),
    });
  const form = (
    path: string,
    body: Record<string, string>,
    headers: Record<string, string> = {},
  ) =>
    req(path, new URLSearchParams(body).toString(), {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    });
  async function client(auth: string) {
    const client = new Client({ name: "fixture-client", version: "1" });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(base + "/mcp"), {
        requestInit: { headers: { Authorization: `Bearer ${auth}` } },
      }),
    );
    return client;
  }
  return {
    ...f,
    config,
    dir,
    base,
    password,
    wakes,
    caller,
    api,
    req,
    form,
    client,
    async close() {
      http.closeAllConnections();
      await new Promise<void>((r) => http.close(() => r()));
      f.store.db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
test("OAuth metadata, S256, consent, audience, rotation and real MCP client", async () => {
  const f = await fixture();
  try {
    const meta = await (
      await f.req("/.well-known/oauth-authorization-server")
    ).json();
    assert.deepEqual(meta.code_challenge_methods_supported, ["S256"]);
    assert.equal(meta.client_id_metadata_document_supported, true);
    assert.equal(
      (await (await f.req("/.well-known/oauth-protected-resource")).json())
        .resource,
      f.base + "/mcp",
    );
    const unauth = await f.req("/mcp", {});
    assert.equal(unauth.status, 401);
    assert.match(unauth.headers.get("www-authenticate")!, /resource_metadata/);
    const redirect = "http://127.0.0.1:9876/callback";
    const reg = await (
      await f.req("/register", {
        client_name: "Fixture interactive",
        redirect_uris: [redirect],
      })
    ).json();
    const verifier = token();
    const params = {
      client_id: reg.client_id,
      redirect_uri: redirect,
      response_type: "code",
      code_challenge: hash(verifier),
      code_challenge_method: "S256",
      resource: f.base + "/mcp",
      scope: "bots offline_access",
      state: "fixture-state",
    };
    for (const method of ["", "plain"])
      assert.equal(
        (
          await f.req(
            "/authorize?" +
              new URLSearchParams({ ...params, code_challenge_method: method }),
          )
        ).status,
        400,
      );
    assert.equal(
      (
        await f.req(
          "/authorize?" +
            new URLSearchParams({
              ...params,
              redirect_uri: "https://evil.example/cb",
            }),
        )
      ).status,
      400,
    );
    const html = await (
      await f.req("/authorize?" + new URLSearchParams(params))
    ).text();
    assert.match(html, /Fixture interactive/);
    assert.match(html, /teammate-level/);
    const pending = html.match(/name="pending" value="([^"]+)"/)![1];
    const consent = await f.form("/consent", {
      pending,
      password: f.password,
      decision: "approve",
    });
    assert.equal(consent.status, 302);
    const url = new URL(consent.headers.get("location")!);
    assert.equal(url.searchParams.get("iss"), f.base);
    assert.equal(url.searchParams.get("state"), "fixture-state");
    const body = {
      grant_type: "authorization_code",
      client_id: reg.client_id,
      redirect_uri: redirect,
      resource: f.base + "/mcp",
      code: url.searchParams.get("code")!,
      code_verifier: verifier,
    };
    const tokens = await (await f.form("/token", body)).json();
    assert.ok(tokens.access_token);
    assert.equal((await f.form("/token", body)).status, 400);
    const client = await f.client(tokens.access_token);
    try {
      assert.deepEqual(
        (await client.listTools()).tools.map((x) => x.name).sort(),
        ["get_reply", "list_bots", "message_bot"],
      );
      const listed = await client.callTool({
        name: "list_bots",
        arguments: {},
      });
      assert.match(JSON.stringify(listed), /research-bot/);
    } finally {
      await client.close();
    }
    const refresh = {
      grant_type: "refresh_token",
      client_id: reg.client_id,
      resource: f.base + "/mcp",
      refresh_token: tokens.refresh_token,
    };
    const rotated = await (await f.form("/token", refresh)).json();
    assert.ok(rotated.refresh_token);
    assert.notEqual(rotated.refresh_token, tokens.refresh_token);
    assert.equal((await f.form("/token", refresh)).status, 400);
    f.store.db
      .prepare("UPDATE callers SET revoked=1 WHERE id=?")
      .run(reg.client_id);
    assert.equal(
      (
        await f.req(
          "/mcp",
          {},
          { Authorization: `Bearer ${rotated.access_token}` },
        )
      ).status,
      401,
    );
    console.log(
      "prove-it-works: OAuth discovery -> DCR -> S256 -> owner consent -> real MCP tools/list -> refresh rotation -> revoke; credentials omitted",
    );
  } finally {
    await f.close();
  }
});
test("API token real MCP wake, reply, single use, ownership, both locks, rotation and revoke", async () => {
  const f = await fixture();
  try {
    const client = await f.client(f.api);
    try {
      const listed = await client.callTool({
        name: "list_bots",
        arguments: {},
      });
      assert.match(JSON.stringify(listed), /research-bot/);
      assert.doesNotMatch(JSON.stringify(listed), /off-bot/);
      const response = await client.callTool({
        name: "message_bot",
        arguments: {
          bot: "research-bot",
          kind: "finding",
          text: "Prepare a draft",
        },
      });
      assert.equal(response.isError, undefined);
      const wake = f.wakes[0];
      assert.ok(wake);
      assert.equal(f.core.get(f.caller, wake.request_id).status, "pending");
      const other = f.store.createCaller("other", "api_token", [
        "research-bot",
      ]);
      assert.throws(() => f.core.get(other, wake.request_id));
      assert.equal(
        (
          await f.req("/reply", {
            request_id: "wrong",
            reply_token: wake.reply_token,
            reply: "Ack",
          })
        ).status,
        400,
      );
      assert.equal(
        (
          await f.req("/reply", {
            request_id: wake.request_id,
            reply_token: wake.reply_token,
            reply: "Prepared; waiting for owner",
          })
        ).status,
        200,
      );
      assert.equal(
        (
          await f.req("/reply", {
            request_id: wake.request_id,
            reply_token: wake.reply_token,
            reply: "Replay",
          })
        ).status,
        400,
      );
      const reply = await client.callTool({
        name: "get_reply",
        arguments: { request_id: wake.request_id },
      });
      assert.match(JSON.stringify(reply), /Prepared/);
      f.config.bots[0].callers = ["someone-else"];
      assert.deepEqual(f.core.list(f.caller), []);
      await assert.rejects(
        f.core.message(f.caller, "research-bot", "question", "test"),
      );
      delete f.config.bots[0].callers;
      f.store.db
        .prepare("UPDATE callers SET allowed='[]' WHERE id=?")
        .run(f.caller.id);
      assert.deepEqual(f.core.list(f.caller), []);
      await assert.rejects(
        f.core.message(f.caller, "research-bot", "question", "test"),
      );
      const newApi = f.store.mintApi(f.caller);
      assert.equal(f.store.authenticate(f.api, f.base + "/mcp"), undefined);
      assert.ok(f.store.authenticate(newApi, f.base + "/mcp"));
      f.store.db
        .prepare("UPDATE callers SET revoked=1 WHERE id=?")
        .run(f.caller.id);
      assert.equal(f.store.authenticate(newApi, f.base + "/mcp"), undefined);
      console.log(
        "prove-it-works: API token -> real MCP list/message -> fake wake -> /reply -> real MCP get_reply; credentials omitted",
      );
    } finally {
      await client.close();
    }
  } finally {
    await f.close();
  }
});
test("rolling limits in all scopes and global spacing, concurrent reservation", async () => {
  for (const scope of ["caller", "bot", "global"] as const)
    for (const window of ["hour", "day"] as const) {
      const f = await fixture();
      try {
        f.config.limits[scope][window] = 1;
        await f.core.message(f.caller, "research-bot", "question", "one");
        await assert.rejects(
          f.core.message(f.caller, "research-bot", "question", "two"),
          new RegExp(`${scope} ${window}`),
        );
        assert.equal(f.wakes.length, 1);
        f.store.db.prepare("UPDATE wakes SET at=?").run(Date.now() - 86400001);
        assert.equal(
          (await f.core.message(f.caller, "research-bot", "question", "three"))
            .status,
          "woken",
        );
      } finally {
        await f.close();
      }
    }
  const f = await fixture(3000);
  try {
    const results = await Promise.allSettled([
      f.core.message(f.caller, "research-bot", "question", "one"),
      f.core.message(f.caller, "research-bot", "question", "two"),
    ]);
    assert.equal(results.filter((x) => x.status === "fulfilled").length, 1);
    assert.equal(f.wakes.length, 1);
  } finally {
    await f.close();
  }
});
test("admin password, CSRF, mint once, disable, enable and revoke", async () => {
  const f = await fixture();
  try {
    const login = await f.form("/admin/login", { password: f.password });
    const cookie = login.headers.get("set-cookie")!.split(";")[0];
    const html = await (
      await f.req("/admin", undefined, { Cookie: cookie })
    ).text();
    const csrf = html.match(/name="csrf" value="([^"]+)"/)![1];
    assert.equal(
      (
        await f.form(
          "/admin/mint",
          { name: "headless", allowed: "research-bot" },
          { Cookie: cookie },
        )
      ).status,
      400,
    );
    const minted = await (
      await f.form(
        "/admin/mint",
        { name: "headless", allowed: "research-bot", csrf },
        { Cookie: cookie },
      )
    ).text();
    const api = minted.match(/<code>([^<]+)<\/code>/)![1];
    const caller = f.store.authenticate(api, f.base + "/mcp")!;
    assert.ok(caller);
    assert.doesNotMatch(
      await (await f.req("/admin", undefined, { Cookie: cookie })).text(),
      new RegExp(api),
    );
    for (const action of ["disable", "enable", "revoke"]) {
      assert.equal(
        (
          await f.form(
            "/admin/caller",
            { id: caller.id, csrf, action },
            { Cookie: cookie },
          )
        ).status,
        302,
      );
      assert.equal(
        !!f.store.authenticate(api, f.base + "/mcp"),
        action === "enable",
      );
    }
  } finally {
    await f.close();
  }
});
test("bad verifier, denied consent, host/origin, expired reply and token binding", async () => {
  const f = await fixture();
  try {
    assert.equal(
      (await f.req("/admin", undefined, { Origin: "https://evil.example" }))
        .status,
      403,
    );
    const reg = await (
      await f.req("/register", {
        client_name: "Untrusted <script>",
        redirect_uris: ["https://example.com/cb"],
      })
    ).json();
    const verifier = token();
    const p = {
      client_id: reg.client_id,
      redirect_uri: "https://example.com/cb",
      response_type: "code",
      code_challenge: hash(verifier),
      code_challenge_method: "S256",
      resource: f.base + "/mcp",
    };
    for (const decision of ["deny", "approve"]) {
      const html = await (
        await f.req("/authorize?" + new URLSearchParams(p))
      ).text();
      assert.doesNotMatch(html, /<script>/);
      const pending = html.match(/name="pending" value="([^"]+)"/)![1];
      const res = await f.form("/consent", {
        pending,
        password: f.password,
        decision,
      });
      const url = new URL(res.headers.get("location")!);
      if (decision === "deny") {
        assert.equal(url.searchParams.get("error"), "access_denied");
        assert.equal(f.store.caller(reg.client_id), undefined);
      } else {
        assert.equal(
          (
            await f.form("/token", {
              grant_type: "authorization_code",
              client_id: reg.client_id,
              redirect_uri: p.redirect_uri,
              resource: p.resource,
              code: url.searchParams.get("code")!,
              code_verifier: token(),
            })
          ).status,
          400,
        );
      }
    }
    await f.core.message(f.caller, "research-bot", "question", "first");
    await f.core.message(f.caller, "research-bot", "question", "second");
    assert.throws(() =>
      f.core.reply(f.wakes[1].request_id, f.wakes[0].reply_token, "bad"),
    );
    f.store.db.prepare("UPDATE requests SET expires=0").run();
    assert.throws(() =>
      f.core.reply(f.wakes[0].request_id, f.wakes[0].reply_token, "late"),
    );
    assert.equal(f.core.get(f.caller, f.wakes[0].request_id).status, "expired");
  } finally {
    await f.close();
  }
});

test("rejected adapter is not retried and retains a conservative budget reservation", async () => {
  const f = await fixture();
  try {
    let calls = 0;
    f.core.adapters.stub = {
      async wake() {
        calls++;
        throw Error("fixture-upstream-failure");
      },
    };
    f.config.limits.global.hour = 1;
    const result = await f.core.message(
      f.caller,
      "research-bot",
      "question",
      "fixture",
    );
    assert.equal(result.status, "rejected");
    assert.equal(f.core.get(f.caller, result.request_id).status, "error");
    assert.equal(calls, 1);
    await assert.rejects(
      f.core.message(f.caller, "research-bot", "question", "again"),
      /global hour/,
    );
    assert.equal(calls, 1);
  } finally {
    await f.close();
  }
});

test("CIMD rejects insecure and literal loopback client IDs before fetching", async () => {
  const f = await fixture();
  try {
    for (const id of [
      "http://example.com/client.json",
      "https://127.0.0.1/client.json",
      "https://user:pass@example.com/client.json",
    ]) {
      const p = {
        client_id: id,
        redirect_uri: "https://example.com/cb",
        response_type: "code",
        code_challenge: hash(token()),
        code_challenge_method: "S256",
        resource: f.base + "/mcp",
      };
      assert.equal(
        (await f.req("/authorize?" + new URLSearchParams(p))).status,
        400,
      );
    }
  } finally {
    await f.close();
  }
});

test("OAuth client cannot reuse an existing caller name; access tokens enforce expiry and audience", async () => {
  const f = await fixture();
  try {
    const reg = await (
      await f.req("/register", {
        client_name: f.caller.name,
        redirect_uris: ["https://example.com/cb"],
      })
    ).json();
    const p = {
      client_id: reg.client_id,
      redirect_uri: "https://example.com/cb",
      response_type: "code",
      code_challenge: hash(token()),
      code_challenge_method: "S256",
      resource: f.base + "/mcp",
    };
    const html = await (
      await f.req("/authorize?" + new URLSearchParams(p))
    ).text();
    const pending = html.match(/name="pending" value="([^"]+)"/)![1];
    assert.equal(
      (
        await f.form("/consent", {
          pending,
          password: f.password,
          decision: "approve",
        })
      ).status,
      400,
    );
    assert.equal(f.store.caller(reg.client_id), undefined);
    const wrong = f.store.grant(
      "access",
      f.caller.id,
      "fixture",
      "https://example.com/mcp",
      60000,
    );
    assert.equal(f.store.authenticate(wrong, f.base + "/mcp"), undefined);
    const expired = f.store.grant(
      "access",
      f.caller.id,
      "fixture",
      f.base + "/mcp",
      -1,
    );
    assert.equal(f.store.authenticate(expired, f.base + "/mcp"), undefined);
  } finally {
    await f.close();
  }
});
