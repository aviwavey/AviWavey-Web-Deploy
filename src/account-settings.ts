import { neon } from "@neondatabase/serverless";

const phone = (value: string) => value.replace(/[\s()-]/g, "");

export class AccountSettingsService {
  private readonly sql;
  constructor(databaseUrl: string) { this.sql = neon(databaseUrl); }

  async read(userId: string) {
    const rows = await this.sql`
      SELECT u.id,u.first_name,u.last_name,u.username,u.profile_picture_key,u.assurance_level,
        email.normalized_value AS email,
        telephone.normalized_value AS private_telephone,
        p.display_name,p.bio,p.profile_picture_key AS public_picture,p.contact_email,p.contact_telephone,p.use_private_telephone
      FROM users u
      LEFT JOIN contacts email ON email.user_id=u.id AND email.kind='email' AND email.is_primary=TRUE
      LEFT JOIN contacts telephone ON telephone.user_id=u.id AND telephone.kind='telephone' AND telephone.is_primary=TRUE
      LEFT JOIN public_profiles p ON p.user_id=u.id
      WHERE u.id=${userId} LIMIT 1`;
    const row = rows[0];
    if (!row) throw new Error("ACCOUNT_NOT_FOUND");
    return {
      private: {
        id: String(row.id), firstName: String(row.first_name ?? ""), lastName: String(row.last_name ?? ""),
        username: String(row.username ?? ""), email: String(row.email ?? ""), telephone: String(row.private_telephone ?? ""),
        profilePicture: String(row.profile_picture_key ?? ""), assurance: String(row.assurance_level ?? "basic_account"),
      },
      public: {
        displayName: String(row.display_name ?? row.username ?? ""), bio: String(row.bio ?? ""),
        profilePicture: String(row.public_picture ?? row.profile_picture_key ?? ""), contactEmail: String(row.contact_email ?? ""),
        contactTelephone: String(row.contact_telephone ?? ""), usePrivateTelephone: Boolean(row.use_private_telephone),
      },
    };
  }

  async updatePublic(userId: string, input: { displayName: string; bio: string; profilePicture?: string; contactEmail: string; contactTelephone: string; usePrivateTelephone: boolean }) {
    await this.sql`INSERT INTO public_profiles (user_id,display_name,bio,profile_picture_key,contact_email,contact_telephone,use_private_telephone)
      VALUES (${userId},${input.displayName},${input.bio},${input.profilePicture || null},${input.contactEmail || null},${input.contactTelephone || null},${input.usePrivateTelephone})
      ON CONFLICT (user_id) DO UPDATE SET display_name=EXCLUDED.display_name,bio=EXCLUDED.bio,
      profile_picture_key=COALESCE(EXCLUDED.profile_picture_key,public_profiles.profile_picture_key),contact_email=EXCLUDED.contact_email,
      contact_telephone=EXCLUDED.contact_telephone,use_private_telephone=EXCLUDED.use_private_telephone,updated_at=CURRENT_TIMESTAMP`;
    return this.read(userId);
  }

  async updatePrivateTelephone(userId: string, rawTelephone: string) {
    const value = phone(rawTelephone);
    if (!/^\+[1-9]\d{7,14}$/.test(value)) throw new Error("INVALID_TELEPHONE");
    const collision = await this.sql`SELECT user_id FROM contacts WHERE kind='telephone' AND normalized_value=${value} AND user_id<>${userId} LIMIT 1`;
    if (collision[0]) throw new Error("CONTACT_ALREADY_IN_USE");
    await this.sql`DELETE FROM contacts WHERE user_id=${userId} AND kind='telephone'`;
    await this.sql`INSERT INTO contacts (id,user_id,kind,normalized_value,verified_at,is_primary) VALUES (${crypto.randomUUID()},${userId},'telephone',${value},NULL,TRUE)`;
    return this.read(userId);
  }
}
