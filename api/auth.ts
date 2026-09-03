import { createHash, randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { SignJWT, jwtVerify } from "jose";
import { AccountService } from "../src/account-service.js";
import { loadConfig } from "../src/config.js";
import { ContactVerificationService } from "../src/contact-verification.js";
import { parseProduct, publicAuthError, validatedReturnPath } from "../src/http-contract.js";
import { NeonIdentityRepository } from "../src/neon-repository.js";
import { appleAuthorizationUrl, exchangeGoogleCode, googleAuthorizationUrl } from "../src/oauth.js";
import { ScryptPasswordHasher } from "../src/passwords.js";
import { cookieValue, DatabaseSessionIssuer } from "../src/sessions.js";
import { profileComplete } from "../src/domain.js";
import { AccountSettingsService } from "../src/account-settings.js";

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const tempCookie = (name: string, value: string, maxAge = 600) => `${name}=${value}; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const clearCookie = (name: string, path = "/api/auth") => `${name}=; Path=${path}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
const string = (value: unknown) => typeof value === "string" ? value.trim() : "";
type UploadedFile = { size: number; type: string; arrayBuffer(): Promise<ArrayBuffer> };
const uploadedFile = (value: unknown): value is UploadedFile => Boolean(
  value && typeof value === "object" &&
  typeof (value as UploadedFile).size === "number" &&
  typeof (value as UploadedFile).type === "string" &&
  typeof (value as UploadedFile).arrayBuffer === "function",
);

const json = (response: ServerResponse, status: number, body: unknown, headers?: Record<string, string | string[]>) => {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  for (const [name, value] of Object.entries(headers ?? {})) response.setHeader(name, value);
  response.end(JSON.stringify(body));
};

async function jsonBody(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown> : {};
}

async function formBody(request: IncomingMessage, absoluteUrl: string) {
  const init = { method: request.method, headers: request.headers as HeadersInit, body: Readable.toWeb(request) as ReadableStream, duplex: "half" } as RequestInit & { duplex: string };
  return new Request(absoluteUrl, init).formData();
}

export default async function handler(request: IncomingMessage, response: ServerResponse) {
  try {
    const config = loadConfig();
    const requestUrl = new URL(request.url ?? "/api/auth", config.baseUrl);
    const routedPath = requestUrl.searchParams.get("path");
    if (routedPath) requestUrl.pathname = `/api/auth/${routedPath.replace(/^\/+/, "")}`;
    const identities = new NeonIdentityRepository(config.databaseUrl);
    const sessions = new DatabaseSessionIssuer(config.databaseUrl, config.sessionCookieName, config.production);
    const accounts = new AccountService(identities, new ScryptPasswordHasher(), sessions, () => crypto.randomUUID());
    const contacts = new ContactVerificationService(config);
    const settings = new AccountSettingsService(config.databaseUrl);
    const current = () => sessions.authenticate(cookieValue(request.headers.cookie, config.sessionCookieName));

    if (request.method === "GET" && requestUrl.pathname.endsWith("/health")) {
      const database = new NeonIdentityRepository(config.databaseUrl);
      await database.findUserById("health-check");
      return json(response, 200, { service: "TrueMarkGate", ready: true, database: "connected", products: ["avi", "aura"], providers: ["email", "google", ...(config.apple ? ["apple"] : []), "passkey"] });
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/config")) {
      return json(response, 200, { providers: { email: true, google: true, apple: Boolean(config.apple), passkey: true }, profileCompletionRequired: true, recoveryAvailable: true });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/register")) {
      const body = await jsonBody(request);
      const result = await accounts.register({ firstName: string(body.firstName), lastName: string(body.lastName), email: string(body.email), password: string(body.password), product: parseProduct(body.product), termsAccepted: body.termsAccepted === true });
      return json(response, 201, { authenticated: true, profileComplete: result.profileComplete }, { "Set-Cookie": result.session.cookie });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/login")) {
      const body = await jsonBody(request);
      const result = await accounts.login({ email: string(body.email), password: string(body.password), product: parseProduct(body.product), remember: body.remember === true });
      return json(response, 200, { authenticated: true, profileComplete: result.profileComplete }, { "Set-Cookie": result.session.cookie });
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/start")) {
      const product = parseProduct(requestUrl.searchParams.get("product"));
      const provider = requestUrl.searchParams.get("provider") ?? "google";
      if (provider !== "google" && provider !== "apple") return json(response, 400, { code: "INVALID_PROVIDER", message: "Choose Google or Apple." });
      if (provider === "apple" && !config.apple) return json(response, 503, { code: "PROVIDER_NOT_CONFIGURED", message: "Apple sign-in is not available yet." });
      const returnTo = validatedReturnPath(product, requestUrl.searchParams.get("returnTo") ?? undefined);
      const verifier = b64(randomBytes(32));
      const challenge = b64(createHash("sha256").update(verifier).digest());
      const nonce = b64(randomBytes(24));
      const state = await new SignJWT({ product, provider, returnTo, nonce }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("10m").setJti(b64(randomBytes(16))).sign(config.sessionSigningKey);
      response.setHeader("Set-Cookie", [tempCookie("avi_oauth_state", state), tempCookie("avi_oauth_verifier", verifier)]);
      response.statusCode = 302;
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Location", provider === "google" ? googleAuthorizationUrl(config, { product, state, codeChallenge: challenge, nonce }).toString() : appleAuthorizationUrl(config, state, nonce).toString());
      return response.end();
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/callback")) {
      const state = requestUrl.searchParams.get("state") ?? "";
      if (!state || state !== cookieValue(request.headers.cookie, "avi_oauth_state")) throw new Error("OAUTH_STATE_INVALID");
      const verifiedState = await jwtVerify(state, config.sessionSigningKey);
      const product = parseProduct(verifiedState.payload.product);
      if (verifiedState.payload.provider !== "google") throw new Error("OAUTH_PROVIDER_INVALID");
      const identity = await exchangeGoogleCode(config, product, requestUrl.searchParams.get("code") ?? "", cookieValue(request.headers.cookie, "avi_oauth_verifier") ?? "", String(verifiedState.payload.nonce ?? ""));
      const result = await accounts.finishProviderSignIn(identity, product);
      const returnTo = validatedReturnPath(product, String(verifiedState.payload.returnTo ?? ""));
      response.statusCode = 302;
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Set-Cookie", [result.session.cookie, clearCookie("avi_oauth_state"), clearCookie("avi_oauth_verifier")]);
      response.setHeader("Location", new URL(result.profileComplete ? returnTo : product === "avi" ? "/complete-profile" : "/AuraAI/complete-profile/", config.baseUrl).toString());
      return response.end();
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/session")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 200, { authenticated: false });
      const user = await identities.findUserById(authenticated.userId);
      if (!user) return json(response, 200, { authenticated: false });
      const completed = profileComplete(user);
      return json(response, 200, { authenticated: true, profileComplete: completed, name: [user.firstName, user.lastName].filter(Boolean).join(" "), email: user.primaryEmail, picture: user.profilePictureKey, memberships: user.memberships, assurance: user.assurance });
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/settings")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      return json(response, 200, await settings.read(authenticated.userId));
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/settings/public")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const form = await formBody(request, requestUrl.toString());
      const photo = form.get("profilePicture");
      let picture: string | undefined;
      if (uploadedFile(photo) && photo.size > 0) {
        if (photo.size > 2_000_000 || !photo.type.startsWith("image/")) return json(response, 400, { code: "INVALID_PROFILE_PICTURE", message: "Choose an image smaller than 2 MB." });
        picture = `data:${photo.type};base64,${Buffer.from(await photo.arrayBuffer()).toString("base64")}`;
      }
      const updated = await settings.updatePublic(authenticated.userId, {
        displayName: string(form.get("displayName")), bio: string(form.get("bio")).slice(0, 500), profilePicture: picture,
        contactEmail: string(form.get("contactEmail")), contactTelephone: string(form.get("contactTelephone")),
        usePrivateTelephone: form.get("usePrivateTelephone") === "true",
      });
      return json(response, 200, updated);
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/settings/private/contact")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const body = await jsonBody(request);
      return json(response, 200, await settings.updatePrivateTelephone(authenticated.userId, string(body.telephone)));
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/contact/telephone/start")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const body = await jsonBody(request);
      await contacts.startTelephone(authenticated.userId, string(body.telephone));
      return json(response, 202, { sent: true });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/contact/telephone/verify")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const body = await jsonBody(request);
      await contacts.verifyTelephone(authenticated.userId, string(body.telephone), string(body.code));
      return json(response, 200, { verified: true });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/profile/complete")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const contentType = String(request.headers["content-type"] ?? "");
      let username = ""; let telephone = ""; let picture = "";
      if (contentType.includes("application/json")) {
        const body = await jsonBody(request);
        username = string(body.username); telephone = string(body.telephone); picture = string(body.profilePicture);
        const match = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(picture);
        if (!match || Buffer.from(match[2], "base64").byteLength > 2_000_000) return json(response, 400, { code: "PROFILE_PICTURE_REQUIRED", message: "Choose a JPEG, PNG or WebP image smaller than 2 MB." });
      } else {
        const form = await formBody(request, requestUrl.toString());
        const photo = form.get("profilePicture");
        if (!uploadedFile(photo) || photo.size === 0 || photo.size > 2_000_000 || !photo.type.startsWith("image/")) return json(response, 400, { code: "PROFILE_PICTURE_REQUIRED", message: "Choose an image smaller than 2 MB." });
        username = string(form.get("username")); telephone = string(form.get("telephone"));
        picture = `data:${photo.type};base64,${Buffer.from(await photo.arrayBuffer()).toString("base64")}`;
      }
      const user = await identities.completeProfile(authenticated.userId, { username, telephone, profilePictureKey: picture });
      return json(response, 200, { completed: profileComplete(user), telephoneVerified: user.telephoneVerified });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/logout")) {
      const authenticated = await current();
      if (authenticated) await sessions.revoke(authenticated.sessionId);
      return json(response, 200, { authenticated: false }, { "Set-Cookie": clearCookie(config.sessionCookieName, "/") });
    }
    return json(response, 404, { code: "AUTH_ROUTE_NOT_FOUND", message: "This authentication route is not available." });
  } catch (error) {
    const configurationError = error instanceof Error && error.message.startsWith("Missing required configuration:");
    if (!configurationError) {
      const publicError = publicAuthError(error);
      if (publicError.body.code !== "AUTHENTICATION_FAILED" || publicError.status !== 401) return json(response, publicError.status, publicError.body);
    }
    return json(response, configurationError ? 503 : 401, { code: configurationError ? "SERVICE_NOT_CONFIGURED" : "AUTHENTICATION_FAILED", message: configurationError ? "TrueMarkGate is awaiting secure deployment configuration." : "We could not complete that sign-in request." });
  }
}
