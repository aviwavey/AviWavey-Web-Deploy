export function directorySession(request: Request, options: {
 issuer?: string; audience?: string; privateJwk?: string; keyId?: string;
 authenticate: (request: Request) => Promise<{id: string} | undefined>;
}): Promise<Response>;
