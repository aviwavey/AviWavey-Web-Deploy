export type Product = "avi" | "aura";
export type CredentialKind = "password" | "google" | "apple" | "passkey";
export type AssuranceLevel = "basic_account" | "verified_contact" | "verified_person" | "institutional_credential" | "elevated_assurance";

export interface IdentityAccount {
  id: string;
  status: "pending" | "active" | "restricted" | "closed";
  firstName?: string;
  lastName?: string;
  username?: string;
  primaryEmail?: string;
  telephonePresent: boolean;
  telephoneVerified: boolean;
  profilePictureKey?: string;
  assurance: AssuranceLevel;
  memberships: Product[];
}

export interface Credential {
  id: string;
  userId: string;
  kind: CredentialKind;
  providerSubject?: string;
  /** Human-recognisable account/email context. Never used as a provider subject. */
  accountLabel?: string;
  revokedAt?: Date;
}

export interface RecoveryInventory {
  verifiedEmail: boolean;
  verifiedTelephone: boolean;
  unusedRecoveryCodes: number;
  activeCredentials: CredentialKind[];
}

export const profileComplete = (account: IdentityAccount) => Boolean(
  account.username && account.telephonePresent && account.profilePictureKey,
);

export const canEnterProduct = (account: IdentityAccount, product: Product) =>
  account.status === "active" && account.memberships.includes(product) && profileComplete(account);
