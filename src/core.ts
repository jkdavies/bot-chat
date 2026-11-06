import type { Config, Bot } from "./config.js";
import type { Adapter } from "./adapters.js";
import { Store, type Caller } from "./store.js";
import { hash, token } from "./security.js";
export class Core {
  constructor(
    readonly config: Config,
    readonly store: Store,
    readonly adapters: Record<string, Adapter>,
  ) {}
  allowed(c: Caller, b: Bot) {
    return (
      this.store.active(this.store.caller(c.id)) &&
      b.optedIn &&
      (JSON.parse(this.store.caller(c.id)!.allowed) as string[]).includes(
        b.id,
      ) &&
      (!b.callers || b.callers.includes(c.name))
    );
  }
  list(c: Caller) {
    return this.config.bots
      .filter((b) => this.allowed(c, b))
      .map((b) => ({
        id: b.id,
        name: b.name,
        description: b.description,
        kinds: b.kinds,
      }));
  }
  async message(
    c: Caller,
    bot: string,
    kind: "question" | "finding",
    text: string,
  ) {
    const b = this.config.bots.find((b) => b.id === bot || b.name === bot);
    if (!b || !this.allowed(c, b) || !b.kinds.includes(kind))
      throw Error("Bot unavailable");
    const now = Date.now(),
      id = token(),
      replyToken = token();
    this.store.db.transaction(() => {
      const fresh = this.store.caller(c.id)!;
      for (const [scope, where, args, budget] of [
        [
          "caller",
          "caller=?",
          [c.id],
          {
            hour: fresh.hour ?? this.config.limits.caller.hour,
            day: fresh.day ?? this.config.limits.caller.day,
          },
        ],
        ["bot", "bot=?", [b.id], this.config.limits.bot],
        ["global", "1=1", [], this.config.limits.global],
      ] as const) {
        for (const [window, ms] of [
          ["hour", 3600000],
          ["day", 86400000],
        ] as const) {
          const count = (
            this.store.db
              .prepare(`SELECT count(*) n FROM wakes WHERE ${where} AND at>?`)
              .get(...args, now - ms) as { n: number }
          ).n;
          if (count >= budget[window])
            throw Error(`${scope} ${window} limit reached`);
        }
      }
      const last = this.store.db
        .prepare("SELECT max(at) at FROM wakes")
        .get() as { at: number | null };
      if (last.at !== null && now - last.at < this.config.limits.spacingMs)
        throw Error("global minimum spacing reached");
      this.store.db
        .prepare("INSERT INTO wakes VALUES(?,?,?)")
        .run(c.id, b.id, now);
      this.store.db
        .prepare("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)")
        .run(
          id,
          c.id,
          b.id,
          kind,
          now,
          now + this.config.replyTtlSeconds * 1000,
          hash(replyToken),
          null,
          "pending",
        );
      this.store.db
        .prepare("INSERT INTO audit VALUES(?,?,?,?,?,?,?,?,?,?)")
        .run(
          now,
          c.name,
          b.id,
          id,
          kind,
          hash(text),
          text.length,
          "pending",
          "pending",
          0,
        );
    })();
    let accepted = false;
    try {
      accepted = await this.adapters[b.adapter].wake(b, {
        request_id: id,
        kind,
        text,
        caller_name: c.name,
        reply_token: replyToken,
        reply_url: `${this.config.publicBaseUrl}/reply`,
      });
    } catch {
      /* Secrets and upstream errors never escape. */
    }
    this.store.db
      .prepare("UPDATE audit SET wake_status=?,duration=? WHERE request_id=?")
      .run(accepted ? "woken" : "rejected", Date.now() - now, id);
    if (!accepted)
      this.store.db
        .prepare(
          "UPDATE requests SET status='error',reply_hash=NULL WHERE id=?",
        )
        .run(id);
    // Failed or uncertain wakes retain the reservation: no retry can amplify spend.
    return { request_id: id, status: accepted ? "woken" : "rejected" };
  }
  reply(id: string, raw: string, reply: string) {
    return this.store.db.transaction(() => {
      const result = this.store.db
        .prepare(
          "UPDATE requests SET reply=?,reply_hash=NULL,status='ready' WHERE id=? AND reply_hash=? AND expires>? AND status='pending'",
        )
        .run(reply, id, hash(raw), Date.now());
      if (result.changes !== 1) throw Error("Invalid reply");
      this.store.db
        .prepare("UPDATE audit SET reply_status='ready' WHERE request_id=?")
        .run(id);
    })();
  }
  get(c: Caller, id: string) {
    if (!this.store.active(this.store.caller(c.id)))
      throw Error("Unauthorized");
    const r = this.store.db
      .prepare(
        "SELECT kind,status,reply,expires FROM requests WHERE id=? AND caller=?",
      )
      .get(id, c.id) as
      | { kind: string; status: string; reply: string | null; expires: number }
      | undefined;
    if (!r) throw Error("Request unavailable");
    return {
      status: r.expires < Date.now() ? "expired" : r.status,
      kind: r.kind,
      ...(r.status === "ready" && r.expires >= Date.now()
        ? { reply: r.reply }
        : {}),
    };
  }
}
