export const socialRoutes: Readonly<Record<string, string[]>>;
export function socialGateway(request: Request, options: { origin: string; authenticate(): Promise<{ id: string } | undefined>; issueToken(id: string): Promise<string>; serviceUrl: string; fetcher?: typeof fetch }): Promise<Response>;
