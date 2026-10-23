import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { neon } from '@neondatabase/serverless';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { validateNote } from '../src/NotesValidation.mjs';
export default async function handler(req:IncomingMessage,res:ServerResponse){
 const send=(status:number,data:unknown)=>{res.statusCode=status;res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store, private');res.setHeader('x-content-type-options','nosniff');res.end(JSON.stringify(data));};
 try{
 const config=loadConfig();const url=new URL(req.url||'/',config.baseUrl);const method=req.method||'GET';
 if(!['GET','POST','PUT','DELETE'].includes(method))return send(405,{error:'Method not allowed.'});
 if(method!=='GET'&&(req.headers.origin!==url.origin||req.headers['sec-fetch-site']==='cross-site'))return send(403,{error:'Open Notes from your signed-in account.'});
 const sessions=new DatabaseSessionIssuer(config.databaseUrl,config.sessionCookieName,config.production);
 const identities=new NeonIdentityRepository(config.databaseUrl);let owner='';
 for(const token of cookieValues(req.headers.cookie,config.sessionCookieName)){const session=await sessions.authenticate(token);if(session&&await identities.findUserById(session.userId)){owner=session.userId;break;}}
 if(!owner)return send(401,{error:'Sign in to your AVW account to use Notes.'});
 const sql=neon(config.databaseUrl);
 await sql`CREATE TABLE IF NOT EXISTS avw_organiser_notes (owner_id text NOT NULL,id text NOT NULL,title text NOT NULL,kind text NOT NULL,parent text,content jsonb NOT NULL DEFAULT '{}',version integer NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(owner_id,id),FOREIGN KEY(owner_id,parent) REFERENCES avw_organiser_notes(owner_id,id))`;
 const id=url.searchParams.get('id');
 if(id&&!/^[\w-]{1,80}$/.test(id))return send(400,{error:'Invalid note.'});
 if(method==='GET'){
 const search=(url.searchParams.get('q')||'').trim().slice(0,200);
 if(id){const rows=await sql`SELECT id,title,kind,parent,content,version,updated_at FROM avw_organiser_notes WHERE owner_id=${owner} AND id=${id}`;return rows.length?send(200,rows[0]):send(404,{error:'Note not found.'});}
 return send(200,await sql`SELECT id,title,kind,parent,version,updated_at,jsonb_build_object('text',left(content->>'text',1200),'transcript',left(content->>'transcript',1200),'pinned',content->'pinned','paper',content->'paper','colour',content->'colour','handwriting',content->'handwriting','thumbnail',content->'thumbnail','duration',content->'duration','peaks',content->'peaks') AS content FROM avw_organiser_notes WHERE owner_id=${owner} AND (kind='folder' OR ${search}='' OR strpos(lower(title||' '||coalesce(content->>'text','')||' '||coalesce(content->>'transcript','')),lower(${search}))>0) ORDER BY updated_at DESC`);
 }
 let raw='';let size=0;for await(const chunk of req){size+=Buffer.byteLength(chunk);if(size>3800000)return send(413,{error:'Note is too large.'});raw+=chunk.toString();}
 let input;try{input=JSON.parse(raw);}catch{return send(400,{error:'Invalid note data.'});}
 if(!input||typeof input!=='object'||Array.isArray(input))return send(400,{error:'Invalid note data.'});
 if(method==='DELETE'){
 if(!id||!Number.isInteger(input.version))return send(400,{error:'Missing note version.'});
 const rows=await sql`DELETE FROM avw_organiser_notes n WHERE owner_id=${owner} AND id=${id} AND version=${input.version} AND NOT EXISTS (SELECT 1 FROM avw_organiser_notes c WHERE c.owner_id=${owner} AND c.parent=${id}) RETURNING id`;
 return rows.length?send(200,{ok:true}):send(409,{error:'Folder must be empty, or this item changed. Reload and try again.'});
 }
 let note;try{note=validateNote(input);}catch(e){return send(400,{error:(e as Error).message});}
 const existing=await sql`SELECT id,kind,parent FROM avw_organiser_notes WHERE owner_id=${owner}` as {id:string;kind:string;parent:string|null}[];
 if(note.parent&&!existing.some(n=>n.id===note.parent&&n.kind==='folder'))return send(400,{error:'Choose an existing folder.'});
 if(method==='POST'&&existing.length>=200)return send(400,{error:'Your Notes limit is 200 items, including folders.'});
 if(note.kind==='folder'&&method==='PUT')return send(400,{error:'Folders cannot be edited in this version.'});
 if(method==='PUT'){
 if(!id||!Number.isInteger(input.version))return send(400,{error:'Missing note version.'});
 const updated=await sql`UPDATE avw_organiser_notes SET title=${note.title},parent=${note.parent},content=${JSON.stringify(note.content)}::jsonb,version=version+1,updated_at=now() WHERE owner_id=${owner} AND id=${id} AND version=${input.version} AND kind=${note.kind} RETURNING id,title,kind,parent,content,version,updated_at`;
 return updated.length?send(200,updated[0]):send(409,{error:'This note changed on another device. Copy your changes before reopening it.'});
 }
 const created=await sql`INSERT INTO avw_organiser_notes(owner_id,id,title,kind,parent,content) VALUES(${owner},${randomUUID()},${note.title},${note.kind},${note.parent},${JSON.stringify(note.content)}::jsonb) RETURNING id,title,kind,parent,content,version,updated_at`;
 send(201,created[0]);
 }catch{send(503,{error:'Notes could not connect to account storage. Your unsaved note is still in the editor.'});}
}
