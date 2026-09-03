import { createSecretKey } from "node:crypto";

const required = (name: string, environment = process.env): string => {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`Missing required configuration: ${name}`);
  return value;
};

const url = (name: string, environment = process.env) => new URL(required(name, environment));
const first = (environment: NodeJS.ProcessEnv, names: string[], fallback?: string) => {
  for (const name of names) {
    const value = environment[name]?.trim();
    if (value) return value;
  }
  if (fallback) return fallback;
  throw new Error(`Missing required configuration: ${names[0]}`);
};

export interface TrueMarkConfig {
  production: boolean;
  baseUrl: URL;
  databaseUrl: string;
  sessionCookieName: string;
  sessionSigningKey: ReturnType<typeof createSecretKey>;
  products: {
    avi: { origin: URL; returnPaths: readonly string[] };
    aura: { origin: URL; returnPaths: readonly string[] };
  };
  google: {
    redirectUri: URL;
    clients: Record<"avi" | "aura", { clientId: string; clientSecret: string }>;
  };
  apple?: { clientId: string; teamId: string; keyId: string; privateKey: string; redirectUri: URL };
  passkeys: { rpId: string; rpName: string; origins: string[] };
  email?: { apiKey: string; from: string };
  sms?: { accountId: string; authToken: string; from: string };
}

export function loadConfig(environment = process.env): TrueMarkConfig {
  const secret = first(environment, ["SESSION_SIGNING_SECRET", "AUTH_SESSION_SECRET"]);
  if (secret.length < 32) throw new Error("SESSION_SIGNING_SECRET must contain at least 32 characters.");
  const baseUrl = new URL(first(environment, ["TRUEMARK_BASE_URL", "AUTH_BASE_URL"], "https://aviwavey.com"));
  return {
    production: environment.NODE_ENV === "production",
    baseUrl,
    databaseUrl: required("DATABASE_URL", environment),
    sessionCookieName: environment.SESSION_COOKIE_NAME?.trim() || "avi_session",
    sessionSigningKey: createSecretKey(Buffer.from(secret)),
    products: {
      avi: { origin: new URL(environment.AVI_ORIGIN?.trim() || baseUrl.origin), returnPaths: ["/dashboard", "/complete-profile", "/home"] },
      aura: { origin: new URL(environment.AURA_ORIGIN?.trim() || baseUrl.origin), returnPaths: ["/AuraAI/dashboard/", "/AuraAI/complete-profile/", "/AuraAI/"] },
    },
    google: {
      redirectUri: new URL(environment.GOOGLE_REDIRECT_URI?.trim() || "/api/auth/callback", baseUrl),
      clients: {
        avi: {
          clientId: required("GOOGLE_AVI_CLIENT_ID", environment),
          clientSecret: required("GOOGLE_AVI_CLIENT_SECRET", environment),
        },
        aura: {
          clientId: required("GOOGLE_AURA_CLIENT_ID", environment),
          clientSecret: required("GOOGLE_AURA_CLIENT_SECRET", environment),
        },
      },
    },
    apple: environment.APPLE_CLIENT_ID?.trim() ? {
      clientId: required("APPLE_CLIENT_ID", environment), teamId: required("APPLE_TEAM_ID", environment),
      keyId: required("APPLE_KEY_ID", environment), privateKey: required("APPLE_PRIVATE_KEY", environment).replace(/\\n/g, "\n"),
      redirectUri: url("APPLE_REDIRECT_URI", environment),
    } : undefined,
    passkeys: {
      rpId: environment.PASSKEY_RP_ID?.trim() || baseUrl.hostname, rpName: environment.PASSKEY_RP_NAME?.trim() || "AVI Wavey",
      origins: (environment.PASSKEY_ORIGINS?.trim() || baseUrl.origin).split(",").map((origin) => new URL(origin.trim()).origin),
    },
    email: environment.EMAIL_PROVIDER_API_KEY?.trim() ? { apiKey: required("EMAIL_PROVIDER_API_KEY", environment), from: required("EMAIL_FROM", environment) } : undefined,
    sms: environment.SMS_PROVIDER_ACCOUNT_ID?.trim() ? { accountId: required("SMS_PROVIDER_ACCOUNT_ID", environment), authToken: required("SMS_PROVIDER_AUTH_TOKEN", environment), from: required("SMS_FROM", environment) } : undefined,
  };
}
