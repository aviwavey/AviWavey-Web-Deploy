import { neon } from "@neondatabase/serverless";
import type { Credential, IdentityAccount, Product } from "./domain.js";
import type { IdentityRepository } from "./ports.js";

type Row = Record<string, unknown>;
const text = (value: unknown) => typeof value === "string" ? value : undefined;

export class NeonIdentityRepository implements IdentityRepository {
  private readonly sql;
  constructor(databaseUrl: string) { this.sql = neon(databaseUrl); }

  private async hydrate(row?: Row): Promise<IdentityAccount | undefined> {
    if (!row) return undefined;
    const memberships = await this.sql`SELECT product FROM product_memberships WHERE user_id = ${String(row.id)} AND status = 'active'`;
    const telephone = await this.sql`SELECT verified_at FROM contacts WHERE user_id = ${String(row.id)} AND kind = 'telephone' LIMIT 1`;
    return {
      id: String(row.id), status: row.status as IdentityAccount["status"],
      firstName: text(row.first_name), lastName: text(row.last_name), username: text(row.username),
      primaryEmail: text(row.primary_email), profilePictureKey: text(row.profile_picture_key),
      telephonePresent: telephone.length > 0,
      telephoneVerified: Boolean(telephone[0]?.verified_at), assurance: row.assurance_level as IdentityAccount["assurance"],
      memberships: memberships.map((item) => String(item.product) as Product),
    };
  }

  private async byWhere(fragment: "id" | "email" | "provider", a: string, b?: string) {
    let rows: Row[];
    if (fragment === "id") rows = await this.sql`SELECT u.*, c.normalized_value AS primary_email FROM users u LEFT JOIN contacts c ON c.user_id=u.id AND c.kind='email' AND c.is_primary=TRUE WHERE u.id=${a} LIMIT 1` as Row[];
    else if (fragment === "email") rows = await this.sql`SELECT u.*, c.normalized_value AS primary_email FROM users u JOIN contacts c ON c.user_id=u.id AND c.kind='email' WHERE c.normalized_value=${a} LIMIT 1` as Row[];
    else rows = await this.sql`SELECT u.*, c.normalized_value AS primary_email FROM users u JOIN credentials cr ON cr.user_id=u.id LEFT JOIN contacts c ON c.user_id=u.id AND c.kind='email' AND c.is_primary=TRUE WHERE cr.kind=${a} AND cr.provider_subject=${b ?? ""} AND cr.revoked_at IS NULL LIMIT 1` as Row[];
    return this.hydrate(rows[0]);
  }

  async findUserByVerifiedEmail(email: string) {
    const rows = await this.sql`SELECT u.*, c.normalized_value AS primary_email FROM users u JOIN contacts c ON c.user_id=u.id AND c.kind='email' WHERE c.normalized_value=${email} AND c.verified_at IS NOT NULL LIMIT 1` as Row[];
    return this.hydrate(rows[0]);
  }
  findUserByEmail(email: string) { return this.byWhere("email", email); }
  findUserByProvider(provider: "google" | "apple", subject: string) { return this.byWhere("provider", provider, subject); }
  findUserById(id: string) { return this.byWhere("id", id); }

  async createUser(input: { firstName: string; lastName: string; email: string; product: Product; emailVerified: boolean }) {
    const id = crypto.randomUUID();
    const contactId = crypto.randomUUID();
    await this.sql`INSERT INTO users (id,status,first_name,last_name) VALUES (${id},'active',${input.firstName},${input.lastName})`;
    await this.sql`INSERT INTO contacts (id,user_id,kind,normalized_value,verified_at,is_primary) VALUES (${contactId},${id},'email',${input.email},${input.emailVerified ? new Date().toISOString() : null},TRUE)`;
    await this.sql`INSERT INTO product_memberships (user_id,product,status) VALUES (${id},${input.product},'active')`;
    return (await this.findUserById(id))!;
  }

  async saveCredential(credential: Credential & { secretHash?: string }) {
    await this.sql`INSERT INTO credentials (id,user_id,kind,provider_subject,secret_hash,label) VALUES (${credential.id},${credential.userId},${credential.kind},${credential.providerSubject ?? null},${credential.secretHash ?? null},${credential.accountLabel ?? null}) ON CONFLICT (kind,provider_subject) DO NOTHING`;
  }

  async credentialsForUser(userId: string) {
    const rows = await this.sql`SELECT id,user_id,kind,provider_subject,label,revoked_at FROM credentials WHERE user_id=${userId}`;
    return rows.map((row) => ({ id: String(row.id), userId: String(row.user_id), kind: row.kind as Credential["kind"], providerSubject: text(row.provider_subject), accountLabel: text(row.label), revokedAt: row.revoked_at ? new Date(String(row.revoked_at)) : undefined }));
  }

  async addMembership(userId: string, product: Product) {
    await this.sql`INSERT INTO product_memberships (user_id,product,status) VALUES (${userId},${product},'active') ON CONFLICT (user_id,product) DO UPDATE SET status='active'`;
  }

  async passwordCredentialForUser(userId: string) {
    const rows = await this.sql`SELECT id,user_id,kind,label,secret_hash FROM credentials WHERE user_id=${userId} AND kind='password' AND revoked_at IS NULL LIMIT 1`;
    const row = rows[0]; if (!row?.secret_hash) return undefined;
    return { id: String(row.id), userId: String(row.user_id), kind: "password" as const, accountLabel: text(row.label), secretHash: String(row.secret_hash) };
  }

  async completeProfile(userId: string, input: { username: string; telephone: string; profilePictureKey: string }) {
    const username = input.username.trim();
    if (!username) throw new Error("USERNAME_REQUIRED");
    const usernameOwner = await this.sql`SELECT id FROM users WHERE LOWER(username)=LOWER(${username}) AND id<>${userId} LIMIT 1`;
    if (usernameOwner[0]) throw new Error("USERNAME_ALREADY_IN_USE");
    const telephone = input.telephone.trim();
    if (!telephone) throw new Error("TELEPHONE_REQUIRED");
    const existing = await this.sql`SELECT user_id FROM contacts WHERE kind='telephone' AND normalized_value=${telephone} LIMIT 1`;
    if (existing[0] && String(existing[0].user_id) !== userId) throw new Error("CONTACT_ALREADY_IN_USE");
    await this.sql`DELETE FROM contacts WHERE user_id=${userId} AND kind='telephone' AND normalized_value<>${telephone}`;
    await this.sql`INSERT INTO contacts (id,user_id,kind,normalized_value,verified_at,is_primary) VALUES (${crypto.randomUUID()},${userId},'telephone',${telephone},NULL,TRUE) ON CONFLICT (kind,normalized_value) DO UPDATE SET is_primary=TRUE`;
    await this.sql`UPDATE users SET username=${username},profile_picture_key=${input.profilePictureKey},profile_completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=${userId}`;
    return (await this.findUserById(userId))!;
  }
}
