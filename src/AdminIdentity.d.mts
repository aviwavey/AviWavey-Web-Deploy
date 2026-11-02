export type AdminKey = {kid:string;sealed:string};
export function createAdminKey(secret:Uint8Array):AdminKey;
export function adminPublicKey(record:AdminKey,secret:Uint8Array):Record<string,string>;
export function adminToken(record:AdminKey,secret:Uint8Array,accountId:string,now?:number):string;
