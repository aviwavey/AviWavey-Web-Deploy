export type SocialKey = { kid: string; sealed: string };
export function createSocialKey(secret: Uint8Array): SocialKey;
export function socialPublicKey(record: SocialKey, secret: Uint8Array): { kty?: string; n?: string; e?: string; kid: string; use: string; alg: string };
export function socialToken(record: SocialKey, secret: Uint8Array, accountId: string, now?: number, community?: { username: string; displayName: string }): string;
