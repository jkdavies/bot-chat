import Database from "better-sqlite3";
import { mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { token, hash } from "./security.js";
export interface Caller {
  id: string;
  name: string;
  kind: string;
  secret_hash: string | null;
  allowed: string;
  enabled: number;
  revoked: number;
  hour: number | null;
  day: number | null;
}
export class Store {
  db: Database.Database;
  constructor(path: string) {
    if (path !== ":memory:")
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new Database(path);
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.db.pragma("journal_mode = DELETE");
    this.db.exec(`
 CREATE TABLE IF NOT EXISTS callers(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,secret_hash TEXT,allowed TEXT NOT NULL,enabled INTEGER DEFAULT 1,revoked INTEGER DEFAULT 0,hour INTEGER,day INTEGER);
 CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,metadata TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS grants(hash TEXT PRIMARY KEY,type TEXT NOT NULL,caller TEXT NOT NULL,client TEXT NOT NULL,resource TEXT NOT NULL,expires INTEGER NOT NULL,data TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,caller TEXT NOT NULL,bot TEXT NOT NULL,kind TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,reply_hash TEXT,reply TEXT,status TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS wakes(caller TEXT,bot TEXT,at INTEGER);
 CREATE INDEX IF NOT EXISTS wakes_at ON wakes(at);
 CREATE TABLE IF NOT EXISTS audit(at INTEGER,caller_name TEXT,bot TEXT,request_id TEXT,kind TEXT,digest TEXT,length INTEGER,wake_status TEXT,reply_status TEXT,duration INTEGER);
 `);
  }
  caller(id: string) {
    return this.db.prepare("SELECT * FROM callers WHERE id=?").get(id) as
      Caller | undefined;
  }
  createCaller(name: string, kind: string, allowed: string[], id = token()) {
    this.db
      .prepare("INSERT INTO callers(id,name,kind,allowed) VALUES(?,?,?,?)")
      .run(id, name, kind, JSON.stringify(allowed));
    return this.caller(id)!;
  }
  mintApi(caller: Caller) {
    const raw = token();
    this.db
      .prepare("UPDATE callers SET secret_hash=? WHERE id=?")
      .run(hash(raw), caller.id);
    return raw;
  }
  active(c: Caller | undefined): c is Caller {
    return !!c && !!c.enabled && !c.revoked;
  }
  grant(
    type: string,
    caller: string,
    client: string,
    resource: string,
    ttl: number,
    data: unknown = {},
  ) {
    const raw = token();
    this.db
      .prepare("INSERT INTO grants VALUES(?,?,?,?,?,?,?)")
      .run(
        hash(raw),
        type,
        caller,
        client,
        resource,
        Date.now() + ttl,
        JSON.stringify(data),
      );
    return raw;
  }
  take(raw: string, type: string, consume = false) {
    return this.db.transaction(() => {
      const g = this.db
        .prepare("SELECT * FROM grants WHERE hash=? AND type=? AND expires>?")
        .get(hash(raw), type, Date.now()) as
        | { caller: string; client: string; resource: string; data: string }
        | undefined;
      if (g && consume)
        this.db.prepare("DELETE FROM grants WHERE hash=?").run(hash(raw));
      return g;
    })();
  }
  authenticate(raw: string, resource: string) {
    const a = this.db
      .prepare("SELECT * FROM callers WHERE secret_hash=? AND kind=?")
      .get(hash(raw), "api_token") as Caller | undefined;
    const g = this.take(raw, "access");
    const c =
      a ?? (g?.resource === resource ? this.caller(g.caller) : undefined);
    return this.active(c) ? c : undefined;
  }
}
