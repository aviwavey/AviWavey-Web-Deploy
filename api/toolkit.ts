import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { toolkitBridge } from '../src/ToolkitBridge.mjs';

// Uses the existing AVW login; service credentials never reach the browser.
export default async function handler(incoming: IncomingMessage, outgoing: ServerResponse) {
  const controller = new AbortController();
  const close = () => { if (!outgoing.writableFinished) controller.abort(); };
  outgoing.on('close', close);
  try {
    const config = loadConfig();
    const url = new URL(incoming.url || '/', config.baseUrl);
    const route = url.searchParams.get('route');
    if (route !== null) url.pathname = '/api/toolkit/' + route;
    url.search = '';
    const headers = new Headers();
    for (const [key, value] of Object.entries(incoming.headers)) {
      if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(',') : value);
    }
    const method = incoming.method || 'GET';
    const request = new Request(url, { method, headers, signal: controller.signal,
      ...(method !== 'GET' && method !== 'HEAD' ? { body: Readable.toWeb(incoming), duplex: 'half' } : {}),
    } as RequestInit);
    const result = await toolkitBridge(request, {
      secret: process.env.TOOLKIT_SERVICE_TOKEN,
      speechUrl: process.env.TOOLKIT_SPEECH_URL,
      authenticate: async () => {
        const sessions = new DatabaseSessionIssuer(config.databaseUrl, config.sessionCookieName, config.production);
        const identities = new NeonIdentityRepository(config.databaseUrl);
        for (const token of cookieValues(incoming.headers.cookie, config.sessionCookieName)) {
          const session = await sessions.authenticate(token);
          if (!session) continue;
          const user = await identities.findUserById(session.userId);
          if (user) return { id: session.userId };
        }
      },
    });
    outgoing.statusCode = result.status;
    result.headers.forEach((value, key) => outgoing.setHeader(key, value));
    if (result.body) await pipeline(Readable.fromWeb(result.body as Parameters<typeof Readable.fromWeb>[0]), outgoing);
    else outgoing.end();
  } catch {
    if (outgoing.headersSent || outgoing.destroyed) { outgoing.destroy(); return; }
    outgoing.statusCode = 503;
    outgoing.setHeader('content-type', 'application/json');
    outgoing.setHeader('cache-control', 'no-store, private');
    outgoing.end(JSON.stringify({ detail: 'The Toolkit connection is temporarily unavailable.' }));
  } finally { outgoing.off('close', close); }
}
