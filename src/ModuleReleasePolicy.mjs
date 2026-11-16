/** Shared server policy. Closed unless explicitly released; preview access uses the stable account ID. */
export const moduleKeys = Object.freeze(["labs-products","labs-beta","labs-research","flow-hub","connect-center","social-link","distribution","licences","credits","publishing","royalties","promotion","showcase","events","assets","atelier","organiser","meetings","correspondence","contracts","commerce","inventory","logistics","tools","cloud","learn","lms","finance","markets","holdings","agreements"]);
const known = new Set(moduleKeys);
export function moduleAccess(user,env={}){
 const active=Boolean(user?.id&&user.status==='active'&&Array.isArray(user.memberships)&&user.memberships.includes('avi'));
 if(!active)return {version:1,previewAll:false,released:[]};
 const owner=typeof env.AVI_MODULE_PREVIEW_OWNER_ID==='string'?env.AVI_MODULE_PREVIEW_OWNER_ID.trim():'';
 const released=[...new Set(String(env.AVI_RELEASED_MODULES||'').split(',').map(x=>x.trim()).filter(x=>known.has(x)))];
 return {version:1,previewAll:Boolean(owner&&user.id===owner),released};
}
export function canOpenModule(access,key){
 return known.has(key)&&access?.version===1&&(access.previewAll===true||Array.isArray(access.released)&&access.released.includes(key));
}
/** Reject ambiguous valid sessions and resolve the account afresh on each request. */
export async function authorizeModules({tokens,authenticate,findUser,keys,env={}}){
 const ids=new Set();
 for(const token of [...new Set(tokens)].slice(0,9)){const session=await authenticate(token);if(session?.userId)ids.add(session.userId);}
 if(ids.size!==1||tokens.length>8)return {allowed:false,status:401};
 const user=await findUser([...ids][0]);
 if(!user||user.status!=='active'||!user.memberships?.includes('avi'))return {allowed:false,status:401};
 const access=moduleAccess(user,env);
 return {allowed:keys.length>0&&keys.every(key=>canOpenModule(access,key)),status:403};
}
