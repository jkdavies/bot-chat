import { z } from "zod";
import type { Bot } from "./config.js";
import { authority, fence, readSecretFile } from "./security.js";
export interface Wake {
  request_id: string;
  kind: "question" | "finding";
  text: string;
  caller_name: string;
  reply_token: string;
  reply_url: string;
}
export interface Adapter {
  wake(bot: Bot, payload: Wake): Promise<boolean>;
}
export class StubAdapter implements Adapter {
  async wake() {
    return true;
  }
}
export class GrokWebhookAdapter implements Adapter {
  async wake(bot: Bot, payload: Wake) {
    const secrets = bot.secretsFile
      ? z
          .object({ url: z.string().url(), key: z.string().min(1) })
          .parse(JSON.parse(readSecretFile(bot.secretsFile)))
      : {
          url: process.env[bot.urlEnv ?? ""],
          key: process.env[bot.keyEnv ?? ""],
        };
    if (!secrets.url || !secrets.key) return false;
    const url = new URL(secrets.url);
    if (
      url.protocol !== "https:" &&
      !(url.protocol === "http:" && url.hostname === "127.0.0.1")
    )
      return false;
    try {
      const r = await fetch(url, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(8000),
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${secrets.key}`,
          "X-Automation-Key": secrets.key,
        },
        body: JSON.stringify({
          ...payload,
          text: fence(payload.text, payload.kind),
          instructions: authority,
        }),
      });
      await r.body?.cancel();
      return r.status === 200;
    } catch {
      return false;
    }
  }
}
