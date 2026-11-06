import { z } from "zod";
const budget = z.object({
  hour: z.number().int().positive(),
  day: z.number().int().positive(),
});
export const configSchema = z
  .object({
    publicBaseUrl: z.string().url(),
    bind: z.string().default("127.0.0.1"),
    port: z.number().int().min(0).max(65535).default(3000),
    database: z.string().default("data/bot-chat.sqlite"),
    ownerHashFile: z.string(),
    accessTtlSeconds: z.number().int().min(60).max(3600).default(600),
    replyTtlSeconds: z.number().int().positive().default(3600),
    limits: z
      .object({
        caller: budget.default({ hour: 10, day: 40 }),
        bot: budget.default({ hour: 20, day: 80 }),
        global: budget.default({ hour: 30, day: 120 }),
        spacingMs: z.number().int().nonnegative().default(3000),
      })
      .default({
        caller: { hour: 10, day: 40 },
        bot: { hour: 20, day: 80 },
        global: { hour: 30, day: 120 },
        spacingMs: 3000,
      }),
    bots: z.array(
      z.object({
        id: z.string().regex(/^[a-z0-9-]+$/),
        name: z.string().min(1).max(100),
        description: z.string().max(500),
        optedIn: z.boolean().default(false),
        callers: z.array(z.string()).optional(),
        kinds: z
          .array(z.enum(["question", "finding"]))
          .default(["question", "finding"]),
        adapter: z.enum(["grok_bot_webhook", "stub"]),
        urlEnv: z.string().optional(),
        keyEnv: z.string().optional(),
        secretsFile: z.string().optional(),
      }),
    ),
  })
  .superRefine((c, ctx) => {
    const u = new URL(c.publicBaseUrl);
    if (
      c.publicBaseUrl !== u.origin ||
      u.pathname !== "/" ||
      u.search ||
      u.hash ||
      u.username ||
      u.password ||
      (u.protocol !== "https:" &&
        !(
          u.protocol === "http:" &&
          ["127.0.0.1", "localhost"].includes(u.hostname)
        ))
    )
      ctx.addIssue({
        code: "custom",
        message:
          "Base URL must be an HTTPS origin (HTTP loopback allowed for development)",
      });
    if (new Set(c.bots.map((b) => b.id)).size !== c.bots.length)
      ctx.addIssue({ code: "custom", message: "Duplicate bot ids" });
  });
export type Config = z.infer<typeof configSchema>;
export type Bot = Config["bots"][number];
