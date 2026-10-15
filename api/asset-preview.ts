import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { assetPreviewService } from '../src/AssetPreviewService.mjs';

export default async function handler(incoming: IncomingMessage, outgoing: ServerResponse) {
  try {
    const url = new URL(incoming.url || '/', 'https://localhost');
    const route = url.searchParams.get('route');
    if (route !== null) url.pathname = '/api/asset-preview/' + route;
    url.search = '';
    const result = await assetPreviewService(new Request(url, { method: incoming.method || 'GET' }));
    if (!result) { outgoing.statusCode = 404; outgoing.end(); return; }
    outgoing.statusCode = result.status;
    result.headers.forEach((value: string, key: string) => outgoing.setHeader(key, value));
    if (result.body) await pipeline(Readable.fromWeb(result.body as Parameters<typeof Readable.fromWeb>[0]), outgoing);
    else outgoing.end();
  } catch {
    if (outgoing.headersSent) { outgoing.destroy(); return; }
    outgoing.statusCode = 502;
    outgoing.setHeader('content-type', 'application/json');
    outgoing.end(JSON.stringify({ message: 'The preview is temporarily unavailable. Please retry.' }));
  }
}
