import type { IncomingMessage, ServerResponse } from 'node:http';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import {capitalBridge} from '../src/CapitalBridge.mjs';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
export default async function handler(req:IncomingMessage,res:ServerResponse){
 try{const config=loadConfig();const url=new URL(req.url||'/',config.baseUrl);const route=url.searchParams.get('route');if(route!==null)url.pathname='/api/capital/'+route;url.searchParams.delete('route');
 const headers=new Headers();for(const [k,v] of Object.entries(req.headers))if(v!==undefined)headers.set(k,Array.isArray(v)?v.join(','):v);
 const method=req.method||'GET';let body:Buffer|undefined;
 if(!['GET','HEAD'].includes(method)){const chunks:Buffer[]=[];let size=0;for await(const chunk of req){const b=Buffer.from(chunk);size+=b.length;if(size>4*1024*1024){res.statusCode=413;res.end();return;}chunks.push(b);}body=Buffer.concat(chunks);}
 const request=new Request(url,{method,headers,...(body?{body:new Uint8Array(body)}:{})});
 const response=await capitalBridge(request,{serviceUrl:process.env.CAPITAL_PAYSEQ_URL,secret:process.env.CAPITAL_BRIDGE_SECRET,authenticate:async()=>{
 const sessions=new DatabaseSessionIssuer(config.databaseUrl,config.sessionCookieName,config.production);const identities=new NeonIdentityRepository(config.databaseUrl);
 for(const token of cookieValues(req.headers.cookie,config.sessionCookieName)){const session=await sessions.authenticate(token);if(session&&await identities.findUserById(session.userId))return {id:session.userId};}
 }});res.statusCode=response.status;response.headers.forEach((v,k)=>res.setHeader(k,v));if(response.body)await pipeline(Readable.fromWeb(response.body as Parameters<typeof Readable.fromWeb>[0]),res);else res.end();
 }catch{res.statusCode=503;res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store');res.end(JSON.stringify({detail:'Payment service is temporarily unavailable.'}));}
}
