export function allowedRoute(method:string,path:string):boolean;
export function capitalBridge(request:Request,options:{authenticate:()=>Promise<{id:string}|undefined>;serviceUrl?:string;secret?:string;fetcher?:typeof fetch}):Promise<Response>;
