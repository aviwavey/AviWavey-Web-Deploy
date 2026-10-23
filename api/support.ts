import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { neon } from '@neondatabase/serverless';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import {validateTicket,validateReply} from '../src/SupportValidation.mjs';
export default async function handler(req:IncomingMessage,res:ServerResponse){
 const send=(status:number,data:unknown)=>{res.statusCode=status;res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store, private');res.setHeader('x-content-type-options','nosniff');res.end(JSON.stringify(data));};
 try{const config=loadConfig(),url=new URL(req.url||'/',config.baseUrl),method=req.method||'GET';
 if(!['GET','POST'].includes(method))return send(405,{error:'Method not allowed.'});
 if(method!=='GET'&&(req.headers.origin!==url.origin||req.headers['sec-fetch-site']==='cross-site'))return send(403,{error:'Open Support from your signed-in settings.'});
 const sessions=new DatabaseSessionIssuer(config.databaseUrl,config.sessionCookieName,config.production),identities=new NeonIdentityRepository(config.databaseUrl);let owner='';
 for(const token of cookieValues(req.headers.cookie,config.sessionCookieName)){const session=await sessions.authenticate(token);if(session&&await identities.findUserById(session.userId)){owner=session.userId;break;}}
 if(!owner)return send(401,{error:'Sign in to use Support.'});
 const product=url.searchParams.get('product')||'avi';if(!['avi','aura'].includes(product))return send(400,{error:'Unknown product.'});const sql=neon(config.databaseUrl);
 await sql`CREATE TABLE IF NOT EXISTS platform_support_tickets(id uuid PRIMARY KEY,owner_id text NOT NULL,product text NOT NULL,subject text NOT NULL,description text NOT NULL,category text NOT NULL,reference text NOT NULL DEFAULT '',status text NOT NULL DEFAULT 'open',attachment jsonb,request_key text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(owner_id,product,request_key))`;
 await sql`CREATE TABLE IF NOT EXISTS platform_support_replies(id uuid PRIMARY KEY,ticket_id uuid NOT NULL REFERENCES platform_support_tickets(id),content text NOT NULL,author_kind text NOT NULL DEFAULT 'customer',request_key text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(ticket_id,request_key))`;
 const id=url.searchParams.get('id');if(id&&!/^[0-9a-f-]{36}$/i.test(id))return send(400,{error:'Invalid ticket reference.'});
 if(method==='GET'){
 if(!id)return send(200,await sql`SELECT id,subject,category,reference,status,created_at,updated_at FROM platform_support_tickets WHERE owner_id=${owner} AND product=${product} ORDER BY updated_at DESC LIMIT 200`);
 const rows=await sql`SELECT * FROM platform_support_tickets WHERE id=${id}::uuid AND owner_id=${owner} AND product=${product}`;if(!rows.length)return send(404,{error:'Ticket not found.'});const ticket=rows[0];
 if(url.searchParams.get('attachment')==='1'){const a=ticket.attachment;if(!a)return send(404,{error:'Attachment not found.'});res.statusCode=200;res.setHeader('content-type',a.type);res.setHeader('content-disposition',"attachment; filename*=UTF-8''"+encodeURIComponent(a.name));res.setHeader('cache-control','no-store, private');res.setHeader('x-content-type-options','nosniff');res.end(Buffer.from(a.data,'base64'));return;}
 const comments=await sql`SELECT id,content,author_kind,created_at FROM platform_support_replies WHERE ticket_id=${id}::uuid ORDER BY created_at`;
 return send(200,{...ticket,attachment:ticket.attachment?{name:ticket.attachment.name}:null,comments});
 }
 let raw='',size=0;for await(const chunk of req){size+=Buffer.byteLength(chunk);if(size>2900000)return send(413,{error:'Keep your attachment below 2 MB.'});raw+=chunk.toString();}
 let input;try{input=JSON.parse(raw);}catch{return send(400,{error:'Invalid support request.'});}
 const key=String(req.headers['idempotency-key']||'');if(!/^[\w-]{16,80}$/.test(key))return send(400,{error:'Missing request reference. Please reload Support.'});
 if(id){let content;try{content=validateReply(input);}catch(e){return send(400,{error:(e as Error).message});}
 const rows=await sql`SELECT id,status FROM platform_support_tickets WHERE id=${id}::uuid AND owner_id=${owner} AND product=${product}`;if(!rows.length)return send(404,{error:'Ticket not found.'});if(rows[0].status==='closed')return send(409,{error:'This ticket is closed. Create a new request.'});
 const count=await sql`SELECT count(*)::int AS count FROM platform_support_replies WHERE ticket_id=${id}::uuid AND created_at>now()-interval '1 day'`;if(count[0].count>=30)return send(429,{error:'Please wait before adding more replies.'});
 await sql`INSERT INTO platform_support_replies(id,ticket_id,content,request_key) VALUES(${randomUUID()}::uuid,${id}::uuid,${content},${key}) ON CONFLICT(ticket_id,request_key) DO NOTHING`;
 await sql`UPDATE platform_support_tickets SET updated_at=now() WHERE id=${id}::uuid AND owner_id=${owner} AND product=${product}`;return send(200,{ok:true});
 }
 let ticket;try{ticket=validateTicket(input);}catch(e){return send(400,{error:(e as Error).message});}
 const existing=await sql`SELECT id FROM platform_support_tickets WHERE owner_id=${owner} AND product=${product} AND request_key=${key}`;if(existing.length)return send(200,existing[0]);
 const count=await sql`SELECT count(*)::int AS count FROM platform_support_tickets WHERE owner_id=${owner} AND product=${product} AND created_at>now()-interval '1 day'`;if(count[0].count>=10)return send(429,{error:'You have reached today’s support request limit.'});
 const rows=await sql`INSERT INTO platform_support_tickets(id,owner_id,product,subject,description,category,reference,attachment,request_key) VALUES(${randomUUID()}::uuid,${owner},${product},${ticket.subject},${ticket.description},${ticket.category},${ticket.reference},${ticket.attachment?JSON.stringify(ticket.attachment):null}::jsonb,${key}) ON CONFLICT(owner_id,product,request_key) DO UPDATE SET request_key=EXCLUDED.request_key RETURNING id`;
 return send(201,rows[0]);
 }catch{return send(503,{error:'Support could not connect. Your unsent message is still in the editor.'});}
}
