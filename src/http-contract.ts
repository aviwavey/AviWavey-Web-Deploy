import type { Product } from "./domain.js";

export const products = new Set<Product>(["avi", "aura"]);
export const providers = new Set(["google", "apple"] as const);

const allowedReturnPaths: Record<Product, readonly string[]> = {
  avi: ["/dashboard", "/complete-profile", "/home"],
  aura: ["/AuraAI/dashboard/", "/AuraAI/complete-profile/", "/AuraAI/"],
};

export function validatedReturnPath(product: Product, requested?: string): string {
  const fallback = product === "avi" ? "/dashboard" : "/AuraAI/dashboard/";
  if (!requested || !allowedReturnPaths[product].includes(requested)) return fallback;
  return requested;
}

export function parseProduct(value: unknown): Product {
  if (value === "avi" || value === "aura") return value;
  throw new Error("INVALID_PRODUCT");
}

export function publicAuthError(error: unknown): { status: number; body: { message: string; code: string } } {
  const code = error instanceof Error ? error.message : "AUTHENTICATION_FAILED";
  if (code === "LEGAL_CONSENT_REQUIRED" || code === "PASSWORD_TOO_SHORT" || code === "INVALID_PRODUCT") {
    return { status: 400, body: { code, message: "Please check the information and try again." } };
  }
  if (code === "EXPLICIT_LINK_REQUIRED") {
    return { status: 409, body: { code, message: "Sign in to your existing account first, then link this sign-in method in account security." } };
  }
  if (code === "USERNAME_REQUIRED") return { status: 400, body: { code, message: "Choose a username." } };
  if (code === "USERNAME_ALREADY_IN_USE") return { status: 409, body: { code, message: "That username is already in use. Please choose another." } };
  if (code === "CONTACT_ALREADY_IN_USE") return { status: 409, body: { code, message: "That telephone number is already connected to another account." } };
  if (code === "TELEPHONE_VERIFICATION_REQUIRED") {
    return { status: 409, body: { code, message: "Verify this telephone number before completing your profile." } };
  }
  if (["INVALID_TELEPHONE", "INVALID_OR_EXPIRED_CODE"].includes(code)) {
    return { status: 400, body: { code, message: code === "INVALID_TELEPHONE" ? "Enter a telephone number with its country code." : "That verification code is invalid or expired." } };
  }
  if (code === "CHALLENGE_RATE_LIMITED") {
    return { status: 429, body: { code, message: "Please wait before requesting another code." } };
  }
  if (code === "SMS_PROVIDER_NOT_CONFIGURED" || code === "SMS_DELIVERY_FAILED") {
    return { status: 503, body: { code, message: "Telephone verification is temporarily unavailable." } };
  }
  return { status: 401, body: { code: "AUTHENTICATION_FAILED", message: "We could not complete that sign-in request." } };
}
