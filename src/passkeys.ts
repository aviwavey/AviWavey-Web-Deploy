import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import type { TrueMarkConfig } from "./config.js";

export const registrationOptions = (config: TrueMarkConfig, user: { id: string; email: string; displayName: string }, existingCredentialIds: string[]) =>
  generateRegistrationOptions({
    rpID: config.passkeys.rpId,
    rpName: config.passkeys.rpName,
    userID: new TextEncoder().encode(user.id),
    userName: user.email,
    userDisplayName: user.displayName,
    attestationType: "none",
    excludeCredentials: existingCredentialIds.map((id) => ({ id })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });

export const authenticationOptions = (config: TrueMarkConfig) => generateAuthenticationOptions({
  rpID: config.passkeys.rpId,
  userVerification: "preferred",
});

export async function verifyPasskeyRegistration(config: TrueMarkConfig, response: Parameters<typeof verifyRegistrationResponse>[0]["response"], expectedChallenge: string) {
  return verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: config.passkeys.origins, expectedRPID: config.passkeys.rpId });
}

export async function verifyPasskeyAuthentication(config: TrueMarkConfig, response: Parameters<typeof verifyAuthenticationResponse>[0]["response"], expectedChallenge: string, credential: Parameters<typeof verifyAuthenticationResponse>[0]["credential"]) {
  return verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin: config.passkeys.origins, expectedRPID: config.passkeys.rpId, credential });
}
