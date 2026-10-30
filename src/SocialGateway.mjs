const routes = {
  'messages.profile': ['query', 'messages:profile'], 'messages.configure': ['mutation', 'messages:configure'],
  'messages.inbox': ['query', 'messages:inbox'], 'messages.get': ['query', 'messages:get'], 'messages.start': ['mutation', 'messages:start'],
  'messages.history': ['query', 'messages:history'], 'messages.send': ['mutation', 'messages:send'], 'messages.respond': ['mutation', 'messages:respond'],
  'messages.markRead': ['mutation', 'messages:markRead'], 'messages.saveDraft': ['mutation', 'messages:saveDraft'],
  'messages.organise': ['mutation', 'messages:organise'], 'messages.report': ['mutation', 'messages:report'],
  'capabilities': ['query', 'capabilities:get'],
  'posts.get': ['query', 'posts:get'], 'posts.list': ['query', 'posts:list'], 'posts.create': ['mutation', 'posts:create'],
  'posts.react': ['mutation', 'posts:react'], 'posts.bookmark': ['mutation', 'posts:bookmark'],
  'posts.comments': ['query', 'posts:comments'], 'posts.reply': ['mutation', 'posts:reply'],
  'posts.report': ['mutation', 'posts:report'], 'posts.remove': ['mutation', 'posts:remove'],
  'realms.list': ['query', 'realms:list'], 'realms.memberships': ['query', 'realms:memberships'],
  'realms.create': ['mutation', 'realms:create'], 'realms.join': ['mutation', 'realms:join'],
  'activity.unread': ['query', 'activity:unread'], 'activity.list': ['query', 'activity:list'], 'activity.markRead': ['mutation', 'activity:markRead'],
  'drafts.get': ['query', 'drafts:get'], 'drafts.save': ['mutation', 'drafts:save'], 'drafts.clear': ['mutation', 'drafts:clear'],
  'moderation.queue': ['query', 'moderation:queue'], 'moderation.review': ['mutation', 'moderation:review'],
  'voice.discard': ['mutation', 'voice:discard'],
};
export const socialRoutes = Object.freeze(routes);
const headers = { 'cache-control': 'no-store, private', 'x-content-type-options': 'nosniff', vary: 'Cookie' };
const reply = (status, body) => Response.json(body, { status, headers });

export async function socialGateway(request, { origin, authenticate, issueToken, serviceUrl, fetcher = fetch }) {
  if (request.method !== 'POST') return reply(405, { error: 'Method not allowed.' });
  if (request.headers.get('origin') !== origin || request.headers.get('sec-fetch-site') === 'cross-site') return reply(403, { error: 'Use Social Link from your signed-in AVI Wavey account.' });
  if (!/^application\/json(?:;|$)/i.test(request.headers.get('content-type') || '')) return reply(415, { error: 'Send a JSON request.' });
  let account;
  try { account = await authenticate(); } catch { return reply(503, { error: 'Account verification is temporarily unavailable.' }); }
  if (!account?.id) return reply(401, { error: 'Sign in to use Social Link.' });
  let command;
  try {
    const reader = request.body?.getReader(); let size = 0; const chunks = [];
    if (!reader) return reply(400, { error: 'Choose an action.' });
    try { while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 16384) { await reader.cancel(); return reply(413, { error: 'This request is too large.' }); } chunks.push(value); } } finally { reader.releaseLock(); }
    command = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch { return reply(400, { error: 'Invalid request.' }); }
  if (!command || typeof command !== 'object' || typeof command.action !== 'string' || !Object.hasOwn(routes, command.action)) return reply(404, { error: 'Unknown action.' });
  if (command.args != null && (typeof command.args !== 'object' || Array.isArray(command.args))) return reply(400, { error: 'Invalid action details.' });
  try {
    const endpoint = new URL(serviceUrl);
    if (endpoint.protocol !== 'https:' || !endpoint.hostname.endsWith('.convex.cloud') || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) return reply(503, { error: 'Social Link needs its service connection configured.' });
    const [kind, path] = routes[command.action]; endpoint.pathname = '/api/' + kind;
    const token = await issueToken(account.id, command.action === 'messages.configure' ? account.community : undefined);
    const response = await fetcher(endpoint, { method: 'POST', redirect: 'error', signal: AbortSignal.any([request.signal, AbortSignal.timeout(20000)]), headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token }, body: JSON.stringify({ path, args: command.args || {}, format: 'json' }) });
    if (!response.headers.get('content-type')?.includes('application/json')) return reply(502, { error: 'Social Link returned an unexpected response.' });
    const result = await response.json();
    if (response.ok && result.status === 'success') return reply(200, { value: result.value });
    if (result.errorData?.kind === 'RateLimitExceeded') return reply(429, { error: 'Please pause for a moment before trying again.' });
    return reply(response.status === 401 ? 401 : 400, { error: typeof result.errorData === 'string' ? result.errorData.slice(0, 300) : 'This action could not finish. Please try again.' });
  } catch { return reply(503, { error: 'Social Link could not connect. Your draft has not been discarded.' }); }
}
