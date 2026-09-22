import { createHash, createHmac, randomUUID } from 'node:crypto';

const runtime = 'https://aura-ai-lucid-personal.aviwavey.workers.dev';
const origins = new Set(['https://aviwavey.com', 'https://www.aviwavey.com']);
const headers = { 'cache-control': 'no-store, private', 'x-content-type-options': 'nosniff' };
const error = (detail, status) => Response.json({ detail }, { status, headers });
export function permittedRoute(method, path) {
  return (method === 'GET' && ['/api/aura/models', '/api/aura/chats', '/api/aura/voices'].includes(path))
    || (['GET', 'PUT'].includes(method) && path === '/api/aura/projects')
    || (['GET', 'POST'].includes(method) && path === '/api/aura/privacy')
    || (method === 'POST' && ['/api/aura/respond', '/api/aura/speech'].includes(path))
    || (['PUT', 'DELETE'].includes(method) && /^\/api\/aura\/chats\/[a-zA-Z0-9_-]{1,100}$/.test(path));
}

// Only the server adapter supplies authenticate; browser identity headers and
// JSON owner fields are never used. Keep raw cookies on the existing login host.
export async function proxyProductionLucid(request, { secret, authenticate, fetcher = fetch }) {
  const path = new URL(request.url).pathname;
  if (!permittedRoute(request.method, path)) return error('Not found.', 404);
  const origin = request.headers.get('origin');
  if (request.headers.get('sec-fetch-site') === 'cross-site' || (origin && !origins.has(origin))
    || (request.method !== 'GET' && !origins.has(origin))) return error('Open this request in your signed-in Aura page.', 403);
  if (request.method !== 'GET' && !/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type') || '')) return error('Send JSON from your Aura dashboard.', 415);
  let account;
  try { account = await authenticate(); } catch { return error('Sign-in is temporarily unavailable.', 503); }
  if (!account || !/^[a-zA-Z0-9_-]{1,120}$/.test(account.id || '')) return error('Sign in to your Aura account to continue.', 401);
  if (!account.profileComplete) return error('Complete your account profile to continue.', 403);
  if (!secret || secret.length < 32) return error('The production chat connection is not configured yet.', 503);
  let body = '';
  if (request.body) {
    const reader = request.body.getReader(); const chunks = []; let size = 0;
    try {
      while (true) {
        const { value, done } = await reader.read(); if (done) break;
        size += value.byteLength;
        if (size > 650000) { await reader.cancel(); return error('This request is too large.', 413); }
        chunks.push(value);
      }
      body = Buffer.concat(chunks).toString('utf8');
    } finally { reader.releaseLock(); }
  }
  const subject = 'truemark:' + account.id;
  const timestamp = String(Date.now()), nonce = randomUUID();
  const digest = createHash('sha256').update(body).digest('hex');
  const signature = createHmac('sha256', secret).update([request.method, path, subject, timestamp, nonce, digest].join('\n')).digest('hex');
  try {
    const upstream = await fetcher(new URL(path, runtime), {
      method: request.method, redirect: 'manual', signal: request.signal,
      headers: { 'content-type': 'application/json', 'x-aura-key-id': 'truemark-v1',
        'x-aura-subject': subject, 'x-aura-timestamp': timestamp, 'x-aura-nonce': nonce, 'x-aura-signature': signature,
        'x-aura-privacy': request.headers.get('x-aura-privacy') || '',
        'x-aura-privacy-revision': request.headers.get('x-aura-privacy-revision') || '0' },
      body: request.method === 'GET' ? undefined : body,
    });
    if (upstream.status >= 300 && upstream.status < 400) {
      await upstream.body?.cancel(); return error('The chat connection needs attention.', 502);
    }
    return new Response(upstream.body, { status: upstream.status, headers: {
      ...headers, 'content-type': upstream.headers.get('content-type') || 'application/json', 'x-accel-buffering': 'no',
    } });
  } catch { return error('The chat connection was interrupted. Please try again.', 502); }
}
