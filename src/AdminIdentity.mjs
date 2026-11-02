import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';

export const adminIssuer = 'https://aviwavey.com/admin';
export const adminAudience = 'avi-social-link-admin';
const keyPurpose = 'avi-admin-social-signing-v1';
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const encryptionKey = secret => {
  if (!secret || secret.byteLength < 32) throw new Error('Shared account signing configuration is unavailable.');
  return createHash('sha256').update(keyPurpose).update(secret).digest();
};

// This key uses an administrator-only secret, independent of public login.
// Only the public key is shared with the moderation service.
export function createAdminKey(secret) {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = randomUUID(), iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey(secret), iv);
  cipher.setAAD(Buffer.from(keyPurpose + ':' + kid));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(privateKey.export({ format: 'jwk' }))), cipher.final()]);
  return { kid, sealed: Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url') };
}

function openKey(record, secret) {
  const bytes = Buffer.from(record.sealed, 'base64url');
  if (bytes.length < 29) throw new Error('Invalid signing key.');
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey(secret), bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from(keyPurpose + ':' + record.kid));
  decipher.setAuthTag(bytes.subarray(12, 28));
  const jwk = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8'));
  return createPrivateKey({ key: jwk, format: 'jwk' });
}

export function adminPublicKey(record, secret) {
  const key = createPublicKey(openKey(record, secret)).export({ format: 'jwk' });
  return { kty: key.kty, n: key.n, e: key.e, kid: record.kid, use: 'sig', alg: 'RS256' };
}

export function adminToken(record, secret, accountId, now = Date.now()) {
  if (typeof accountId !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(accountId)) throw new Error('An authenticated account is required.');
  const issued = Math.floor(now / 1000);
  // This identifier is never returned in public feed, Realm or chat records.
  const subject = 'admin:' + accountId;
  const unsigned = encode({ kid: record.kid, typ: 'JWT', alg: 'RS256' }) + '.' + encode({
    iss: adminIssuer, aud: adminAudience, sub: subject, iat: issued, nbf: issued, exp: issued + 60, purpose: 'administration', permissions: ['avi:safety.review'], jti: randomUUID(),
  });
  return unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), openKey(record, secret)).toString('base64url');
}
