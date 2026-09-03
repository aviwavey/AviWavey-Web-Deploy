import type { Credential, CredentialKind, IdentityAccount, Product } from "./domain.js";

export interface IdentityRepository {
  findUserByVerifiedEmail(email: string): Promise<IdentityAccount | undefined>;
  findUserByEmail(email: string): Promise<IdentityAccount | undefined>;
  findUserByProvider(provider: "google" | "apple", subject: string): Promise<IdentityAccount | undefined>;
  findUserById(id: string): Promise<IdentityAccount | undefined>;
  createUser(input: { firstName: string; lastName: string; email: string; product: Product; emailVerified: boolean }): Promise<IdentityAccount>;
  saveCredential(credential: Credential & { secretHash?: string }): Promise<void>;
  credentialsForUser(userId: string): Promise<Credential[]>;
  addMembership(userId: string, product: Product): Promise<void>;
  passwordCredentialForUser(userId: string): Promise<(Credential & { secretHash: string }) | undefined>;
  completeProfile(userId: string, input: { username: string; telephone: string; profilePictureKey: string }): Promise<IdentityAccount>;
}

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(password: string, storedHash: string): Promise<boolean>;
}

export interface SessionIssuer {
  issue(input: { userId: string; product: Product; remember: boolean }): Promise<{ cookie: string; expiresAt: Date }>;
  revoke(sessionId: string): Promise<void>;
}

export interface ProviderIdentity {
  provider: "google" | "apple";
  subject: string;
  verifiedEmail: string;
  firstName?: string;
  lastName?: string;
}

export interface PasskeyVerifier {
  registrationOptions(userId: string, accountLabel: string): Promise<unknown>;
  verifyRegistration(userId: string, response: unknown): Promise<{ credentialId: string; publicKey: Uint8Array; signCount: number }>;
  authenticationOptions(accountHint?: string): Promise<unknown>;
  verifyAuthentication(response: unknown): Promise<{ userId: string; credentialId: string; nextSignCount: number }>;
}

export const credentialHasUsableSubject = (kind: CredentialKind, subject?: string) =>
  kind === "password" || Boolean(subject?.trim());
