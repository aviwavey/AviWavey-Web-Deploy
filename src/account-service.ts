import type { Credential, Product } from "./domain.js";
import { profileComplete } from "./domain.js";
import type { IdentityRepository, PasswordHasher, ProviderIdentity, SessionIssuer } from "./ports.js";

const normalizeEmail = (email: string) => email.trim().toLowerCase();

export class AccountService {
  constructor(
    private readonly identities: IdentityRepository,
    private readonly passwords: PasswordHasher,
    private readonly sessions: SessionIssuer,
    private readonly newId: () => string,
  ) {}

  async register(input: { firstName: string; lastName: string; email: string; password: string; product: Product; termsAccepted: boolean }) {
    if (!input.termsAccepted) throw new Error("LEGAL_CONSENT_REQUIRED");
    if (input.password.length < 12) throw new Error("PASSWORD_TOO_SHORT");
    const email = normalizeEmail(input.email);
    if (await this.identities.findUserByEmail(email)) throw new Error("ACCOUNT_ALREADY_EXISTS");
    const user = await this.identities.createUser({ firstName: input.firstName.trim(), lastName: input.lastName.trim(), email, product: input.product, emailVerified: false });
    await this.identities.saveCredential({ id: this.newId(), userId: user.id, kind: "password", accountLabel: email, secretHash: await this.passwords.hash(input.password) });
    const session = await this.sessions.issue({ userId: user.id, product: input.product, remember: false });
    return { session, profileComplete: profileComplete(user) };
  }

  async login(input: { email: string; password: string; product: Product; remember: boolean }) {
    const user = await this.identities.findUserByEmail(normalizeEmail(input.email));
    if (!user || user.status !== "active") throw new Error("AUTHENTICATION_FAILED");
    const credential = await this.identities.passwordCredentialForUser(user.id);
    if (!credential || !await this.passwords.verify(input.password, credential.secretHash)) throw new Error("AUTHENTICATION_FAILED");
    await this.identities.addMembership(user.id, input.product);
    const session = await this.sessions.issue({ userId: user.id, product: input.product, remember: input.remember });
    return { session, profileComplete: profileComplete(user) };
  }

  async finishProviderSignIn(identity: ProviderIdentity, product: Product) {
    let user = await this.identities.findUserByProvider(identity.provider, identity.subject);
    if (!user) {
      const possibleExistingUser = await this.identities.findUserByVerifiedEmail(normalizeEmail(identity.verifiedEmail));
      user = possibleExistingUser ?? await this.identities.createUser({ firstName: identity.firstName ?? "", lastName: identity.lastName ?? "", email: normalizeEmail(identity.verifiedEmail), product, emailVerified: true });
      const credential: Credential = { id: this.newId(), userId: user.id, kind: identity.provider, providerSubject: identity.subject, accountLabel: normalizeEmail(identity.verifiedEmail) };
      await this.identities.saveCredential(credential);
    }
    await this.identities.addMembership(user.id, product);
    const session = await this.sessions.issue({ userId: user.id, product, remember: true });
    return { session, profileComplete: profileComplete(user) };
  }

  async linkProvider(authenticatedUserId: string, identity: ProviderIdentity) {
    const linkedElsewhere = await this.identities.findUserByProvider(identity.provider, identity.subject);
    if (linkedElsewhere && linkedElsewhere.id !== authenticatedUserId) throw new Error("PROVIDER_ALREADY_LINKED");
    await this.identities.saveCredential({ id: this.newId(), userId: authenticatedUserId, kind: identity.provider, providerSubject: identity.subject, accountLabel: normalizeEmail(identity.verifiedEmail) });
  }
}
