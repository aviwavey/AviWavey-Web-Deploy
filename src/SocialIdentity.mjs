import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';

export const socialIssuer = 'https://aviwavey.com';
export const socialAudience = 'avi-social-link';
const keyPurpose = 'avi-social-link-signing-v1';
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const encryptionKey = secret => {
  if (!secret || secret.byteLength < 32) throw new Error('Shared account signing configuration is unavailable.');
  return createHash('sha256').update(keyPurpose).update(secret).digest();
};

// The existing account service owns the signing key. Convex receives only the
// public JWK. A database backup alone cannot reveal the encrypted private key.
export function createSocialKey(secret) {
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

export function socialPublicKey(record, secret) {
  const key = createPublicKey(openKey(record, secret)).export({ format: 'jwk' });
  return { kty: key.kty, n: key.n, e: key.e, kid: record.kid, use: 'sig', alg: 'RS256' };
}

export function socialToken(record, secret, accountId, now = Date.now(), community) {
  if (typeof accountId !== 'string' || !accountId || accountId.length > 256) throw new Error('An authenticated account is required.');
  const issued = Math.floor(now / 1000);
  // This identifier is never returned in public feed, Realm or chat records.
  const subject = 'avw:' + createHash('sha256').update('social-link:' + accountId).digest('hex');
  const unsigned = encode({ kid: record.kid, typ: 'JWT', alg: 'RS256' }) + '.' + encode({
    ...(community ? { community: { username: community.username, displayName: community.displayName } } : {}),
    iss: socialIssuer, aud: socialAudience, sub: subject, iat: issued, nbf: issued, exp: issued + 120, jti: randomUUID(),
  });
  return unsigned + '.' + sign('RSA-SHA256', Buffer.from(unsigned), openKey(record, secret)).toString('base64url');
}
