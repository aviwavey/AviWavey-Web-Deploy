import type { IncomingMessage, ServerResponse } from 'node:http';
import { neon } from '@neondatabase/serverless';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { validateTaskState } from '../src/TaskStateValidation.mjs';
export default async function handler(req:IncomingMessage,res:ServerResponse){
 const send=(status:number,data:unknown)=>{res.statusCode=status;res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store, private');res.setHeader('x-content-type-options','nosniff');res.end(JSON.stringify(data));};
 try{
 const config=loadConfig();const url=new URL(req.url||'/',config.baseUrl);const method=req.method||'GET';
 if(!['GET','PUT'].includes(method))return send(405,{error:'Method not allowed.'});
 if(method!=='GET'&&(req.headers.origin!==url.origin||req.headers['sec-fetch-site']==='cross-site'))return send(403,{error:'Open Organiser from your signed-in account.'});
 const sessions=new DatabaseSessionIssuer(config.databaseUrl,config.sessionCookieName,config.production);
 const identities=new NeonIdentityRepository(config.databaseUrl);let owner='';
 for(const token of cookieValues(req.headers.cookie,config.sessionCookieName)){const session=await sessions.authenticate(token);if(session&&await identities.findUserById(session.userId)){owner=session.userId;break;}}
 if(!owner)return send(401,{error:'Sign in to your AVW account to use Organiser.'});
 const sql=neon(config.databaseUrl);

 await sql`CREATE TABLE IF NOT EXISTS avw_tasksync_states(owner_id text PRIMARY KEY,document jsonb NOT NULL,version integer NOT NULL DEFAULT 1)`;
 if(method==='GET'){const rows=await sql`SELECT document,version FROM avw_tasksync_states WHERE owner_id=${owner}`;return send(200,rows.length?{...rows[0].document,version:rows[0].version}:{items:[],logs:[],version:0});}
 let raw='',size=0;for await(const chunk of req){size+=Buffer.byteLength(chunk);if(size>1048576)return send(413,{error:'Task collection is too large.'});raw+=chunk.toString();}
 let data;try{data=validateTaskState(JSON.parse(raw));}catch(e){return send(400,{error:(e as Error).message});}
 const document=JSON.stringify({items:data.items,logs:data.logs});
 const rows=data.version===0?await sql`INSERT INTO avw_tasksync_states(owner_id,document,version) VALUES(${owner},${document}::jsonb,1) ON CONFLICT(owner_id) DO NOTHING RETURNING version`:await sql`UPDATE avw_tasksync_states SET document=${document}::jsonb,version=version+1 WHERE owner_id=${owner} AND version=${data.version} RETURNING version`;
 return rows.length?send(200,rows[0]):send(409,{error:'Tasks changed in another window. Reload before saving.'});
 }catch{return send(503,{error:'Organiser could not connect to account storage. Please retry.'});}
}
