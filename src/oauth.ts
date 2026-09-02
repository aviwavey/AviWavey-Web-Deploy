import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify } from "jose";
import type { TrueMarkConfig } from "./config.js";
import type { Product } from "./domain.js";

export function googleAuthorizationUrl(config: TrueMarkConfig, input: { product: Product; state: string; codeChallenge: string; nonce: string }) {
  const client = config.google.clients[input.product];
  const target = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  target.search = new URLSearchParams({
    client_id: client.clientId,
    redirect_uri: config.google.redirectUri.toString(),
    response_type: "code",
    scope: "openid email profile",
    state: input.state,
    nonce: input.nonce,
    code_challenge: input.codeChallenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();
  return target;
}

export function appleAuthorizationUrl(config: TrueMarkConfig, state: string, nonce: string) {
  if (!config.apple) throw new Error("Apple sign-in is not configured.");
  const target = new URL("https://appleid.apple.com/auth/authorize");
  target.search = new URLSearchParams({
    client_id: config.apple.clientId,
    redirect_uri: config.apple.redirectUri.toString(),
    response_type: "code id_token",
    response_mode: "form_post",
    scope: "name email",
    state,
    nonce,
  }).toString();
  return target;
}

export async function appleClientSecret(config: TrueMarkConfig, now = Math.floor(Date.now() / 1000)) {
  if (!config.apple) throw new Error("Apple sign-in is not configured.");
  const key = await importPKCS8(config.apple.privateKey, "ES256");
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: config.apple.keyId })
    .setIssuer(config.apple.teamId)
    .setSubject(config.apple.clientId)
    .setAudience("https://appleid.apple.com")
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

const googleKeys = createRemoteJWKSet(new URL("https://www.googleapis.com/oauth2/v3/certs"));

export async function exchangeGoogleCode(config: TrueMarkConfig, product: Product, code: string, verifier: string, expectedNonce: string) {
  const client = config.google.clients[product];
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: client.clientId, client_secret: client.clientSecret, redirect_uri: config.google.redirectUri.toString(), grant_type: "authorization_code", code_verifier: verifier }),
  });
  const token = await response.json() as { id_token?: string; error?: string };
  if (!response.ok || !token.id_token) {
    if (token.error === "invalid_client") throw new Error("GOOGLE_CLIENT_CONFIGURATION_ERROR");
    if (token.error === "invalid_grant") throw new Error("GOOGLE_AUTHORIZATION_EXPIRED");
    throw new Error("GOOGLE_TOKEN_EXCHANGE_FAILED");
  }
  const verified = await jwtVerify(token.id_token, googleKeys, { issuer: ["https://accounts.google.com", "accounts.google.com"], audience: client.clientId });
  const claims = verified.payload;
  if (claims.nonce !== expectedNonce || !claims.sub || !claims.email || claims.email_verified !== true) throw new Error("GOOGLE_IDENTITY_INVALID");
  return { provider: "google" as const, subject: claims.sub, verifiedEmail: String(claims.email), firstName: typeof claims.given_name === "string" ? claims.given_name : undefined, lastName: typeof claims.family_name === "string" ? claims.family_name : undefined };
}
