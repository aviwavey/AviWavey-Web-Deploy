export const moduleKeys:readonly string[];
export type ModuleAccess={version:number;previewAll:boolean;released:string[]};
export function moduleAccess(user:unknown,env?:Record<string,string|undefined>):ModuleAccess;
export function canOpenModule(access:unknown,key:string):boolean;
export function authorizeModules(options:{tokens:string[];authenticate:(token:string)=>Promise<any>;findUser:(id:string)=>Promise<any>;keys:string[];env?:Record<string,string|undefined>}):Promise<{allowed:boolean;status:number}>;
