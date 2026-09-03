import { randomInt } from "node:crypto";
import { neon } from "@neondatabase/serverless";
import type { TrueMarkConfig } from "./config.js";
import { ScryptPasswordHasher } from "./passwords.js";

const code = () => String(randomInt(0, 1_000_000)).padStart(6, "0");

export class ContactVerificationService {
  private readonly sql;
  private readonly hasher = new ScryptPasswordHasher();
  constructor(private readonly config: TrueMarkConfig) { this.sql = neon(config.databaseUrl); }

  async startTelephone(userId: string, telephone: string) {
    if (!this.config.sms) throw new Error("SMS_PROVIDER_NOT_CONFIGURED");
    const value = telephone.replace(/[\s()-]/g, "");
    if (!/^\+[1-9]\d{7,14}$/.test(value)) throw new Error("INVALID_TELEPHONE");
    const recent = await this.sql`SELECT 1 FROM contact_verification_challenges WHERE user_id=${userId} AND kind='telephone' AND created_at>CURRENT_TIMESTAMP-INTERVAL '60 seconds' LIMIT 1`;
    if (recent[0]) throw new Error("CHALLENGE_RATE_LIMITED");
    const otp = code();
    await this.sql`INSERT INTO contact_verification_challenges (id,user_id,kind,destination,secret_hash,expires_at) VALUES (${crypto.randomUUID()},${userId},'telephone',${value},${await this.hasher.hash(otp)},CURRENT_TIMESTAMP+INTERVAL '10 minutes')`;
    const body = new URLSearchParams({ To: value, From: this.config.sms.from, Body: `Your AVI Wavey verification code is ${otp}. It expires in 10 minutes.` });
    const authorization = Buffer.from(`${this.config.sms.accountId}:${this.config.sms.authToken}`).toString("base64");
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${this.config.sms.accountId}/Messages.json`, { method: "POST", headers: { Authorization: `Basic ${authorization}`, "Content-Type": "application/x-www-form-urlencoded" }, body });
    if (!response.ok) throw new Error("SMS_DELIVERY_FAILED");
  }

  async verifyTelephone(userId: string, telephone: string, otp: string) {
    const value = telephone.replace(/[\s()-]/g, "");
    const rows = await this.sql`SELECT id,secret_hash,attempts FROM contact_verification_challenges WHERE user_id=${userId} AND kind='telephone' AND destination=${value} AND consumed_at IS NULL AND expires_at>CURRENT_TIMESTAMP ORDER BY created_at DESC LIMIT 1`;
    const challenge = rows[0];
    if (!challenge || Number(challenge.attempts) >= 5 || !await this.hasher.verify(otp, String(challenge.secret_hash))) {
      if (challenge) await this.sql`UPDATE contact_verification_challenges SET attempts=attempts+1 WHERE id=${String(challenge.id)}`;
      throw new Error("INVALID_OR_EXPIRED_CODE");
    }
    await this.sql`UPDATE contact_verification_challenges SET consumed_at=CURRENT_TIMESTAMP WHERE id=${String(challenge.id)}`;
    const existing = await this.sql`SELECT id FROM contacts WHERE user_id=${userId} AND kind='telephone' LIMIT 1`;
    if (existing[0]) await this.sql`UPDATE contacts SET normalized_value=${value},verified_at=CURRENT_TIMESTAMP,is_primary=TRUE WHERE id=${String(existing[0].id)}`;
    else await this.sql`INSERT INTO contacts (id,user_id,kind,normalized_value,verified_at,is_primary) VALUES (${crypto.randomUUID()},${userId},'telephone',${value},CURRENT_TIMESTAMP,TRUE)`;
  }
}
