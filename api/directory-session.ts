import type { IncomingMessage, ServerResponse } from 'node:http';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { directorySession } from '../src/DirectorySessionBridge.mjs';

// Install beside the existing TrueMarkGate backend, never in the Sites handler.
export default async function handler(incoming: IncomingMessage, outgoing: ServerResponse) {
 try {
  const config = loadConfig();
  const url = new URL(incoming.url || '/', config.baseUrl);
  const route = url.searchParams.get('route');
  if (route !== null) url.pathname = '/api/directory-session/' + route;
  url.search = '';
  const requestHeaders = new Headers();
  for (const [key, value] of Object.entries(incoming.headers)) if (value !== undefined) requestHeaders.set(key, Array.isArray(value) ? value.join(',') : value);
  const request = new Request(url, { method: incoming.method || 'GET', headers: requestHeaders });
  const result = await directorySession(request, {
   issuer: process.env.DIRECTORY_TOKEN_ISSUER, audience: process.env.DIRECTORY_TOKEN_AUDIENCE,
   privateJwk: process.env.DIRECTORY_SIGNING_PRIVATE_JWK, keyId: process.env.DIRECTORY_SIGNING_KEY_ID,
   authenticate: async () => {
    const sessions = new DatabaseSessionIssuer(config.databaseUrl, config.sessionCookieName, config.production);
    const identities = new NeonIdentityRepository(config.databaseUrl);
    for (const token of cookieValues(incoming.headers.cookie, config.sessionCookieName)) {
     const session = await sessions.authenticate(token);
     if (session && await identities.findUserById(session.userId)) return { id: session.userId };
    }
   },
  });
  outgoing.statusCode = result.status;
  result.headers.forEach((value, key) => outgoing.setHeader(key, value));
  outgoing.end(await result.text());
 } catch {
  outgoing.statusCode = 503;outgoing.setHeader('content-type', 'application/json');outgoing.setHeader('cache-control', 'no-store, private');
  outgoing.end(JSON.stringify({ detail: 'The shared account connection is temporarily unavailable.' }));
 }
}
