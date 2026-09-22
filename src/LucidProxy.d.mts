export function proxyProductionLucid(request: Request, options: {
  secret?: string;
  authenticate: () => Promise<{ id: string; profileComplete: boolean } | undefined>;
  fetcher?: typeof fetch;
}): Promise<Response>;
