import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { neon } from '@neondatabase/serverless';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { AccountSettingsService } from '../src/account-settings.js';
import { personaOutcome, allowedMutation, verifiedSelfieUrl } from '../src/IdentityPolicy.mjs';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const QRCode=require('qrcode');const bwip=require('bwip-js');
const version='2026-09-29';
export default async function handler(req:IncomingMessage,res:ServerResponse){
 const send=(status:number,data:unknown)=>{res.statusCode=status;res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store, private');res.setHeader('X-Content-Type-Options','nosniff');res.end(JSON.stringify(data));};
 try{
 const config=loadConfig();const url=new URL(req.url||'/',config.baseUrl);
 if(!['GET','POST'].includes(req.method||''))return send(405,{error:'Method not allowed.'});
 if(req.method==='POST'&&!allowedMutation(req.headers.origin,String(req.headers['sec-fetch-site']||''),config.baseUrl.origin))return send(403,{error:'Open verification from your signed-in account.'});
 const sessions=new DatabaseSessionIssuer(config.databaseUrl,config.sessionCookieName,config.production);
 const identities=new NeonIdentityRepository(config.databaseUrl);let owner='';
 for(const token of cookieValues(req.headers.cookie,config.sessionCookieName)){const session=await sessions.authenticate(token);if(session){const user=await identities.findUserById(session.userId);if(user?.status==='active'){owner=user.id;break;}}}
 if(!owner)return send(401,{error:'Sign in to view your private identity.'});
 const sql=neon(config.databaseUrl);
 await sql`CREATE TABLE IF NOT EXISTS truemark_identity_cards(owner_id text PRIMARY KEY,card_code text UNIQUE NOT NULL,created_at timestamptz NOT NULL DEFAULT now())`;
 await sql`CREATE TABLE IF NOT EXISTS truemark_persona_inquiries(owner_id text NOT NULL,environment_id text NOT NULL,attempt_id text NOT NULL UNIQUE,inquiry_id text UNIQUE,template_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),consented_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(owner_id,environment_id))`;
 await sql`ALTER TABLE truemark_persona_inquiries ADD COLUMN IF NOT EXISTS portrait_consented_at timestamptz`;
 const apiKey=process.env.PERSONA_API_KEY||'',templateId=process.env.PERSONA_TEMPLATE_ID||'',environmentId=process.env.PERSONA_ENVIRONMENT_ID||'',mode=process.env.PERSONA_MODE||'disabled';
 const configured=Boolean(apiKey&&/^itmpl_/.test(templateId)&&/^env_/.test(environmentId)&&['sandbox','production'].includes(mode));
 const persona=async(path:string,method='GET',body?:unknown,key?:string)=>{
  const result=await fetch('https://api.withpersona.com/api/v1/'+path,{method,headers:{Authorization:'Bearer '+apiKey,'Content-Type':'application/json','Persona-Version':version,...(key?{'Idempotency-Key':key}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(15000)});
  if(!result.ok)throw new Error('PERSONA_UNAVAILABLE');if(result.headers.get('Persona-Environment-Id')!==environmentId)throw new Error('PERSONA_ENVIRONMENT_MISMATCH');return result.json();
 };
 const settings=await new AccountSettingsService(config.databaseUrl).read(owner);
 const rows=configured?await sql`SELECT * FROM truemark_persona_inquiries WHERE owner_id=${owner} AND environment_id=${environmentId}`:[];
 let record=rows[0];
 let verifiedPayload:any=null;
 const expected=()=>({owner,inquiryId:String(record.inquiry_id),templateId:String(record.template_id),mode,firstName:settings.private.firstName,lastName:settings.private.lastName});
 const outcome=async()=>{
  if(!configured||!record?.inquiry_id)return {status:configured?'not_started':'unavailable',verified:false,document:false,selfie:false};
  const p=await persona('inquiries/'+encodeURIComponent(String(record.inquiry_id))+'?include=verifications');
  verifiedPayload=p;
  return personaOutcome(p,{owner,inquiryId:String(record.inquiry_id),templateId:String(record.template_id),mode,firstName:settings.private.firstName,lastName:settings.private.lastName});
 };
 if(req.method==='GET'){
  await sql`INSERT INTO truemark_identity_cards(owner_id,card_code) VALUES(${owner},${randomBytes(10).toString('hex').toUpperCase()}) ON CONFLICT(owner_id) DO NOTHING`;
  const cards=await sql`SELECT card_code,created_at FROM truemark_identity_cards WHERE owner_id=${owner}`;
  const card=cards[0],code=String(card.card_code);
  let verification;try{verification=await outcome();}catch{verification={status:'unavailable',verified:false,document:false,selfie:false};}
  let portrait:string|null=null;
  if(record?.portrait_consented_at&&verifiedPayload){
   const imageUrl=verifiedSelfieUrl(verifiedPayload,expected());
   if(imageUrl)try{
    const image=await fetch(imageUrl,{redirect:'error',signal:AbortSignal.timeout(8000)});
    const type=(image.headers.get('content-type')||'').split(';')[0];
    if(image.ok&&['image/jpeg','image/png','image/webp'].includes(type)&&Number(image.headers.get('content-length')||0)<=2000000&&image.body){
     const reader=image.body.getReader();const chunks:Uint8Array[]=[];let size=0;
     try{while(true){const next=await reader.read();if(next.done)break;size+=next.value.length;if(size>2000000)throw new Error('IMAGE_TOO_LARGE');chunks.push(next.value);}portrait='data:'+type+';base64,'+Buffer.concat(chunks).toString('base64');}finally{await reader.cancel();}
    }
   }catch{/* Keep a neutral placeholder if evidence is unavailable or expired. */}
  }
  const barcode=bwip.toSVG({bcid:'code128',text:code,height:10,scale:2,paddingwidth:12,paddingheight:4});
  // Fixed trusted destinations; the fragment keeps the opaque reference out of server request logs.
  const cardUrl=(url.searchParams.get('brand')==='aura'?'https://aviwavey.com/AuraAI/':'https://aviwavey.com/')+'#identity-card='+encodeURIComponent(code);
  const qr=await QRCode.toString(cardUrl,{type:'svg',errorCorrectionLevel:'M',margin:4,color:{dark:'#000000ff',light:'#ffffff00'}});
  return send(200,{accountId:owner,cardCode:code,cardUrl,issuedAt:card.created_at,name:[settings.private.firstName,settings.private.lastName].filter(Boolean).join(' ')||'Legal name not provided',portrait,portraitConsent:Boolean(record?.portrait_consented_at),barcode:'data:image/svg+xml;base64,'+Buffer.from(barcode).toString('base64'),qr:'data:image/svg+xml;base64,'+Buffer.from(qr).toString('base64'),configured,mode,verification});
 }
 let raw='';for await(const chunk of req){raw+=chunk.toString();if(Buffer.byteLength(raw)>2048)return send(413,{error:'Request too large.'});}
 let input;try{input=JSON.parse(raw);}catch{return send(400,{error:'Invalid request.'});}
 if(!input||input.consent!==true)return send(400,{error:'Please consent to Persona processing your identity evidence.'});
 if(!configured)return send(503,{error:'Government ID verification is not available yet. Persona must be configured before documents can be submitted.'});
 if(!record){
  await sql`INSERT INTO truemark_persona_inquiries(owner_id,environment_id,attempt_id,template_id) VALUES(${owner},${environmentId},${randomUUID()},${templateId}) ON CONFLICT(owner_id,environment_id) DO NOTHING`;
  record=(await sql`SELECT * FROM truemark_persona_inquiries WHERE owner_id=${owner} AND environment_id=${environmentId}`)[0];
 }
 if(input.portraitConsent===true){await sql`UPDATE truemark_persona_inquiries SET portrait_consented_at=COALESCE(portrait_consented_at,now()) WHERE owner_id=${owner} AND environment_id=${environmentId}`;}
 if(input.action==='portrait-consent')return send(200,{saved:true});
 if(!record.inquiry_id){
  if(Date.now()-new Date(String(record.created_at)).getTime()>23*3600000)return send(409,{error:'This verification request needs support review before retrying.'});
  const p=await persona('inquiries','POST',{data:{attributes:{'inquiry-template-id':String(record.template_id),'reference-id':owner}}},String(record.attempt_id));
  if(!/^inq_/.test(p.data?.id)||p.data?.attributes?.['reference-id']!==owner)throw new Error('PERSONA_BINDING_MISMATCH');
  await sql`UPDATE truemark_persona_inquiries SET inquiry_id=${p.data.id} WHERE owner_id=${owner} AND environment_id=${environmentId} AND inquiry_id IS NULL`;
  record=(await sql`SELECT * FROM truemark_persona_inquiries WHERE owner_id=${owner} AND environment_id=${environmentId}`)[0];
 }
 const state=await outcome();
 if(['approved','declined','failed','needs_review','completed'].includes(state.status))return send(409,{error:'This inquiry has been submitted. Refresh its status or contact support if it needs review.'});
 const resumed=await persona('inquiries/'+encodeURIComponent(String(record.inquiry_id))+'/resume','POST');
 const token=resumed.meta?.['session-token'];if(typeof token!=='string')throw new Error('PERSONA_SESSION_MISSING');
 return send(200,{inquiryId:record.inquiry_id,sessionToken:token,environmentId,mode});
 }catch{return send(503,{error:'Identity services are temporarily unavailable. No verification has been granted. Please try again.'});}
}
