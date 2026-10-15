import { createPrivateKey, createPublicKey, sign, randomUUID } from 'node:crypto';
const headers = { 'cache-control': 'no-store, private', 'x-content-type-options': 'nosniff', vary: 'Cookie' };
const reply = (value, status = 200) => Response.json(value, { status, headers });

// Authenticate only through the existing TrueMarkGate session adapter. Browser
// account IDs, email addresses and preview identity headers are never accepted.
export async function directorySession(request, { issuer, audience, privateJwk, keyId, authenticate }) {
 const url = new URL(request.url);
 const publicKeys = url.pathname === '/api/directory-session/jwks';
 if (!publicKeys && url.pathname !== '/api/directory-session/token') return reply({ detail: 'Not found.' }, 404);
 if (request.method !== (publicKeys ? 'GET' : 'POST')) return reply({ detail: 'Method not allowed.' }, 405);
 if (!publicKeys && (request.headers.get('origin') !== url.origin || request.headers.get('sec-fetch-site') === 'cross-site'))
  return reply({ detail: 'Open this from your signed-in AVI Wavey account.' }, 403);
 try {
  let user;
  if (!publicKeys) {
   user = await authenticate(request);
   if (!user || typeof user.id !== 'string' || !user.id) return reply({ detail: 'Sign in with your AVI Wavey account.' }, 401);
  }
  if (!issuer || !audience || !keyId || !privateJwk) return reply({ detail: 'Directory access is not configured yet.' }, 503);
  const origin = new URL(issuer);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash) throw new Error('Invalid issuer');
  const input = JSON.parse(privateJwk);
  if (input.kty !== 'RSA') throw new Error('RSA signing key required');
  const key = createPrivateKey({ key: input, format: 'jwk' });
  if ((key.asymmetricKeyDetails?.modulusLength || 0) < 2048) throw new Error('Signing key too small');
  const exported = createPublicKey(key).export({ format: 'jwk' });
  if (publicKeys) return reply({ keys: [{ kty: 'RSA', n: exported.n, e: exported.e, use: 'sig', alg: 'RS256', kid: keyId }] });
  const now = Math.floor(Date.now() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const head = encode({ alg: 'RS256', typ: 'JWT', kid: keyId });
  const claims = encode({ iss: issuer, aud: audience, sub: user.id, iat: now, nbf: now, exp: now + 120, jti: randomUUID(), scope: 'directories:use' });
  const message = `${head}.${claims}`;
  const signature = sign('RSA-SHA256', Buffer.from(message), key).toString('base64url');
  return reply({ access_token: `${message}.${signature}`, token_type: 'Bearer', expires_in: 120 });
 } catch { return reply({ detail: 'Directory access is temporarily unavailable.' }, 503); }
}
