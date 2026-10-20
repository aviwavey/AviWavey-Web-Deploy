const headers = { 'cache-control': 'no-store, private', 'x-content-type-options': 'nosniff', vary: 'Cookie' };
const reply = (data, status = 200) => Response.json(data, { status, headers });
export async function toolkitBridge(request, { authenticate, speechUrl, secret, fetcher = fetch }) {
 const url = new URL(request.url);
 if (!['/api/toolkit/capabilities', '/api/toolkit/speech'].includes(url.pathname)) return reply({ detail: 'Not found.' }, 404);
 if (request.method !== (url.pathname.endsWith('/capabilities') ? 'GET' : 'POST')) return reply({ detail: 'Method not allowed.' }, 405);
 if (request.method === 'POST' && (request.headers.get('origin') !== url.origin || request.headers.get('sec-fetch-site') === 'cross-site')) return reply({ detail: 'Open this from your AVI Wavey account.' }, 403);
 try {
  const user = await authenticate(request);
  if (!user?.id) return reply({ detail: 'Sign in with your AVI Wavey account.' }, 401);
  let endpoint;
  if (speechUrl && secret) {
   endpoint = new URL(speechUrl);
   if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw Error('Invalid configuration');
  }
  if (request.method === 'GET') return reply({ textToSpeech: Boolean(endpoint), speechToText: false, remoteWorkflows: false });
  if (!endpoint) return reply({ detail: 'Speech service is awaiting deployment.' }, 503);
  const reader = request.body?.getReader(); let size = 0; const chunks = [];
  if (!reader) return reply({ detail: 'Text is required.' }, 400);
  while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 24000) { await reader.cancel(); return reply({ detail: 'Text is too long.' }, 413); } chunks.push(value); }
  let body; try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { return reply({ detail: 'Invalid request.' }, 400); }
  if (typeof body.text !== 'string' || !body.text.trim() || body.text.length > 5000) return reply({ detail: 'Enter up to 5,000 characters.' }, 400);
  if (body.voice !== undefined && (typeof body.voice !== 'string' || !/^[A-Za-z]{1,40}$/.test(body.voice))) return reply({ detail: 'Invalid voice.' }, 400);
  const response = await fetcher(new URL('/api/upload-text', endpoint), { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(65000), headers: { 'content-type': 'application/json', authorization: 'Bearer ' + secret, 'x-avw-user-id': user.id }, body: JSON.stringify({ text: body.text, voice: body.voice }) });
  if (!response.ok || !response.headers.get('content-type')?.startsWith('audio/wav')) return reply({ detail: 'Speech could not be generated. Please try again.' }, 502);
  return new Response(response.body, { headers: { ...headers, 'content-type': 'audio/wav', 'content-disposition': 'attachment; filename="speech.wav"' } });
 } catch { return reply({ detail: 'Speech is temporarily unavailable.' }, 503); }
}
