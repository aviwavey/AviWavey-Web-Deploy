import { createHash, randomBytes } from "node:crypto";
import { neon } from "@neondatabase/serverless";
import type { Product } from "./domain.js";
import type { SessionIssuer } from "./ports.js";

const digest = (token: string) => createHash("sha256").update(token).digest("base64url");

export class DatabaseSessionIssuer implements SessionIssuer {
  private readonly sql;
  constructor(databaseUrl: string, private readonly cookieName: string, private readonly production: boolean) { this.sql = neon(databaseUrl); }

  async issue(input: { userId: string; product: Product; remember: boolean }) {
    const token = randomBytes(32).toString("base64url");
    const id = crypto.randomUUID();
    const lifetimeSeconds = input.remember ? 60 * 60 * 24 * 30 : 60 * 60 * 12;
    const expiresAt = new Date(Date.now() + lifetimeSeconds * 1000);
    await this.sql`INSERT INTO sessions (id,user_id,token_hash,expires_at) VALUES (${id},${input.userId},${digest(token)},${expiresAt.toISOString()})`;
    const secure = this.production ? "; Secure" : "";
    return { cookie: `${this.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax${secure}; Max-Age=${lifetimeSeconds}`, expiresAt };
  }

  async authenticate(token?: string) {
    if (!token) return undefined;
    const rows = await this.sql`SELECT id,user_id FROM sessions WHERE token_hash=${digest(token)} AND revoked_at IS NULL AND expires_at>CURRENT_TIMESTAMP LIMIT 1`;
    return rows[0] ? { sessionId: String(rows[0].id), userId: String(rows[0].user_id) } : undefined;
  }

  async revoke(sessionId: string) { await this.sql`UPDATE sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=${sessionId}`; }
}

export function cookieValue(header: string | undefined, name: string) {
  return cookieValues(header, name)[0];
}

export function cookieValues(header: string | undefined, name: string) {
  const values: string[] = [];
  for (const item of (header ?? "").split(";")) {
    const [key, ...parts] = item.trim().split("=");
    if (key === name) values.push(parts.join("="));
  }
  return values;
}
