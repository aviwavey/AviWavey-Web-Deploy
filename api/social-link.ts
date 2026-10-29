import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { neon } from '@neondatabase/serverless';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { createSocialKey, socialPublicKey, socialToken, type SocialKey } from '../src/SocialIdentity.mjs';
import { socialGateway } from '../src/SocialGateway.mjs';

// This is the existing, user-approved free Convex project. An override is only
// accepted by the gateway when it is a genuine HTTPS Convex deployment origin.
const serviceUrl = process.env.SOCIAL_LINK_CONVEX_URL || 'https://aware-otter-964.convex.cloud';
let cachedKey: { record: SocialKey; until: number } | undefined;

export default async function handler(incoming: IncomingMessage, outgoing: ServerResponse) {
  const send = (status: number, value: unknown) => {
    outgoing.statusCode = status; outgoing.setHeader('content-type', 'application/json');
    outgoing.setHeader('cache-control', 'no-store, private'); outgoing.setHeader('x-content-type-options', 'nosniff');
    outgoing.end(JSON.stringify(value));
  };
  try {
    const config = loadConfig(), url = new URL(incoming.url || '/', config.baseUrl);
    const route = url.searchParams.get('route');
    const path = route === null ? url.pathname.split('/').pop() : route;
    const secret = new Uint8Array(config.sessionSigningKey.export());
    const key = async(): Promise<SocialKey> => {
      if (cachedKey && cachedKey.until > Date.now()) return cachedKey.record;
      const sql = neon(config.databaseUrl);
      await sql`CREATE TABLE IF NOT EXISTS avw_service_signing_keys(service text PRIMARY KEY, kid text NOT NULL, sealed text NOT NULL, created_at timestamptz NOT NULL DEFAULT now())`;
      let rows = await sql`SELECT kid,sealed FROM avw_service_signing_keys WHERE service='social-link'`;
      if (!rows.length) {
        const candidate = createSocialKey(secret);
        await sql`INSERT INTO avw_service_signing_keys(service,kid,sealed) VALUES('social-link',${candidate.kid},${candidate.sealed}) ON CONFLICT(service) DO NOTHING`;
        // Use the committed winner if two cold starts generated a key together.
        rows = await sql`SELECT kid,sealed FROM avw_service_signing_keys WHERE service='social-link'`;
      }
      if (!rows[0]) throw new Error('No shared signing key.');
      const record = { kid: String(rows[0].kid), sealed: String(rows[0].sealed) };
      socialPublicKey(record, secret); // Validate decryption before caching.
      cachedKey = { record, until: Date.now() + 60000 };
      return record;
    };
    if (path === 'keys' && incoming.method === 'GET') return send(200, { keys: [socialPublicKey(await key(), secret)] });
    if (!['command', 'session'].includes(path || '')) return send(404, { error: 'Not found.' });
    const authenticate = async() => {
      const sessions = new DatabaseSessionIssuer(config.databaseUrl, config.sessionCookieName, config.production);
      const identities = new NeonIdentityRepository(config.databaseUrl);
      for (const token of cookieValues(incoming.headers.cookie, config.sessionCookieName)) {
        const session = await sessions.authenticate(token);
        if (!session) continue;
        const user = await identities.findUserById(session.userId);
        if (user?.status === 'active') return { id: session.userId };
      }
    };
    if (path === 'session') {
      if (incoming.method !== 'POST') return send(405, { error: 'Method not allowed.' });
      if (incoming.headers.origin !== config.baseUrl.origin || incoming.headers['sec-fetch-site'] === 'cross-site') return send(403, { error: 'Upload from your signed-in AVI Wavey account.' });
      const account = await authenticate();
      if (!account) return send(401, { error: 'Sign in to upload a voice note.' });
      const upload = new URL(serviceUrl);
      if (upload.protocol !== 'https:' || !upload.hostname.endsWith('.convex.cloud') || upload.username || upload.password || upload.pathname !== '/' || upload.search || upload.hash) return send(503, { error: 'Social Link needs its service connection configured.' });
      upload.hostname = upload.hostname.replace(/\.convex\.cloud$/, '.convex.site'); upload.pathname = '/voice';
      return send(200, { token: socialToken(await key(), secret, account.id), expiresIn: 120, uploadUrl: upload.toString() });
    }
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(',') : value);
    const method = incoming.method || 'GET';
    const init = { method, headers, ...(method === 'GET' || method === 'HEAD' ? {} : { body: Readable.toWeb(incoming), duplex: 'half' }) } as RequestInit & { duplex?: string };
    const result = await socialGateway(new Request(url, init), { origin: config.baseUrl.origin, authenticate, issueToken: async id => socialToken(await key(), secret, id), serviceUrl });
    outgoing.statusCode = result.status; result.headers.forEach((value, name) => outgoing.setHeader(name, value)); outgoing.end(await result.text());
  } catch { send(503, { error: 'Social Link could not connect. Please retry; your draft is still available.' }); }
}
