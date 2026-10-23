import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes, randomUUID, createPrivateKey, sign, createCipheriv } from 'node:crypto';
import { neon } from '@neondatabase/serverless';
import { loadConfig } from '../src/config.js';
import { cookieValues, DatabaseSessionIssuer } from '../src/sessions.js';
import { NeonIdentityRepository } from '../src/neon-repository.js';
import { AccountSettingsService } from '../src/account-settings.js';
import { personaOutcome, allowedMutation, verifiedSelfieUrl, validBirthdate, identityAge } from '../src/IdentityPolicy.mjs';
import { createRequire } from 'node:module';
const require=createRequire(import.meta.url);
const QRCode=require('qrcode');const bwip=require('bwip-js');
import { protectedDetailsMatch, privateGender } from '../src/ProtectedProfilePolicy.mjs';
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
 await sql`ALTER TABLE truemark_identity_cards ADD COLUMN IF NOT EXISTS avid text`;
 await sql`CREATE UNIQUE INDEX IF NOT EXISTS truemark_identity_avid_unique ON truemark_identity_cards(avid)`;
 await sql`CREATE TABLE IF NOT EXISTS truemark_private_details(owner_id text PRIMARY KEY,birthdate text NOT NULL DEFAULT '',gender text NOT NULL DEFAULT '',address text NOT NULL DEFAULT '',updated_at timestamptz NOT NULL DEFAULT now())`;
 await sql`CREATE TABLE IF NOT EXISTS truemark_verified_identity(owner_id text PRIMARY KEY,first_name text NOT NULL,last_name text NOT NULL,birthdate text NOT NULL,address text NOT NULL DEFAULT '',inquiry_id text NOT NULL,verified_at timestamptz NOT NULL DEFAULT now())`;
 await sql`ALTER TABLE truemark_verified_identity ADD COLUMN IF NOT EXISTS gender text NOT NULL DEFAULT ''`;
 await sql`CREATE TABLE IF NOT EXISTS truemark_identity_change_requests(id text PRIMARY KEY,owner_id text NOT NULL,field text NOT NULL,sealed_payload text NOT NULL,status text NOT NULL DEFAULT 'pending_review',created_at timestamptz NOT NULL DEFAULT now())`;
 await sql`ALTER TABLE truemark_private_details ADD COLUMN IF NOT EXISTS first_name text`;
 await sql`ALTER TABLE truemark_private_details ADD COLUMN IF NOT EXISTS last_name text`;
 const privateDetails=(await sql`SELECT birthdate,gender,address,updated_at,first_name,last_name FROM truemark_private_details WHERE owner_id=${owner}`)[0]||{birthdate:'',gender:'',address:''};
 const apiKey=process.env.PERSONA_API_KEY||'',templateId=process.env.PERSONA_TEMPLATE_ID||'',environmentId=process.env.PERSONA_ENVIRONMENT_ID||'',mode=process.env.PERSONA_MODE||'disabled';
 const configured=Boolean(apiKey&&/^itmpl_/.test(templateId)&&/^env_/.test(environmentId)&&['sandbox','production'].includes(mode));
 const persona=async(path:string,method='GET',body?:unknown,key?:string)=>{
  const result=await fetch('https://api.withpersona.com/api/v1/'+path,{method,headers:{Authorization:'Bearer '+apiKey,'Content-Type':'application/json','Persona-Version':version,...(key?{'Idempotency-Key':key}:{})},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(15000)});
  if(!result.ok)throw new Error('PERSONA_UNAVAILABLE');if(result.headers.get('Persona-Environment-Id')!==environmentId)throw new Error('PERSONA_ENVIRONMENT_MISMATCH');return result.json();
 };
 const settings=await new AccountSettingsService(config.databaseUrl).read(owner);
 let identityLock=(await sql`SELECT * FROM truemark_verified_identity WHERE owner_id=${owner}`)[0];
 const legalFirst=String(identityLock?.first_name??privateDetails.first_name??settings.private.firstName);
 const legalLast=String(identityLock?.last_name??privateDetails.last_name??settings.private.lastName);
 const evidenceKey=Buffer.from(process.env.IDENTITY_EVIDENCE_KEY||'','base64');
 const correctionsReady=evidenceKey.length===32&&process.env.IDENTITY_REVIEW_ENABLED==='true';
 const rows=configured?await sql`SELECT * FROM truemark_persona_inquiries WHERE owner_id=${owner} AND environment_id=${environmentId}`:[];
 let record=rows[0];
 let verifiedPayload:any=null;
 const expected=()=>({owner,inquiryId:String(record.inquiry_id),templateId:String(record.template_id),mode,firstName:legalFirst,lastName:legalLast});
 const outcome=async()=>{
  if(!configured||!record?.inquiry_id)return {status:configured?'not_started':'unavailable',verified:false,document:false,selfie:false,nameMatches:false,birthdatePresent:false};
  const p=await persona('inquiries/'+encodeURIComponent(String(record.inquiry_id))+'?include=verifications');
  verifiedPayload=p;
  return personaOutcome(p,{owner,inquiryId:String(record.inquiry_id),templateId:String(record.template_id),mode,firstName:legalFirst,lastName:legalLast});
 };
 const captureLock=async()=>{
  const state=await outcome();
  const dob=verifiedPayload?.data?.attributes?.fields?.birthdate?.value;
  if(mode==='production'&&state.status==='approved'&&state.document&&state.selfie&&state.nameMatches&&state.birthdatePresent&&validBirthdate(dob)&&privateGender(privateDetails.gender)){
   await sql`INSERT INTO truemark_verified_identity(owner_id,first_name,last_name,birthdate,address,gender,inquiry_id) VALUES(${owner},${legalFirst},${legalLast},${dob},${String(privateDetails.address||'')},${String(privateDetails.gender||'')},${String(record.inquiry_id)}) ON CONFLICT(owner_id) DO NOTHING`;
   identityLock=(await sql`SELECT * FROM truemark_verified_identity WHERE owner_id=${owner}`)[0];
  }
  return state;
 };
 if(req.method==='GET'&&(url.searchParams.get('route')==='address-suggestions'||url.pathname.endsWith('/address-suggestions')))return send(200,{available:false,suggestions:[],manualEntry:true});
 if(req.method==='GET'){
  await sql`INSERT INTO truemark_identity_cards(owner_id,card_code) VALUES(${owner},${randomBytes(10).toString('hex').toUpperCase()}) ON CONFLICT(owner_id) DO NOTHING`;
  const cards=await sql`SELECT card_code,created_at,avid FROM truemark_identity_cards WHERE owner_id=${owner}`;
  const card=cards[0],code=String(card.card_code);
  if(!card.avid){const alphabet='0123456789ABCDEFGHJKMNPQRSTVWXYZ';const chars=Array.from(randomBytes(25),b=>alphabet[b%alphabet.length]).join('');const candidate='AW-'+chars.match(/.{5}/g)!.join('-');await sql`UPDATE truemark_identity_cards SET avid=${candidate} WHERE owner_id=${owner} AND avid IS NULL`;card.avid=(await sql`SELECT avid FROM truemark_identity_cards WHERE owner_id=${owner}`)[0].avid;}
  const avid=String(card.avid);
  let verification;try{verification=await captureLock();}catch{verification={status:'unavailable',verified:false,document:false,selfie:false,nameMatches:false,birthdatePresent:false};}
  if(privateDetails.address&&record?.created_at&&privateDetails.updated_at&&new Date(String(privateDetails.updated_at))>new Date(String(record.created_at))){verification={...verification,address:false,verified:false};}
  verification={...verification,address:false,verified:false};
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
  const contacts=await sql`SELECT kind,normalized_value,verified_at FROM contacts WHERE user_id=${owner} AND kind IN ('email','telephone')`;
  const credentials=await identities.credentialsForUser(owner);
  const links=['google','apple'].map(provider=>({provider,configured:provider==='google'||Boolean(config.apple),accounts:credentials.filter(c=>c.kind===provider&&!c.revokedAt).map(c=>({email:c.accountLabel||''}))}));
  const emails=Array.from(new Set([...contacts.filter(c=>c.kind==='email'&&c.verified_at).map(c=>String(c.normalized_value)),...links.flatMap(l=>l.accounts.map(a=>a.email)).filter(Boolean)]));
  const mobile=contacts.find(c=>c.kind==='telephone');
  const protectedAccount={firstName:legalFirst,lastName:legalLast,emails,primaryEmail:settings.private.email,mobile:String(mobile?.normalized_value||''),mobileVerified:Boolean(mobile?.verified_at),links,hasPassword:credentials.some(c=>c.kind==='password'&&!c.revokedAt),smsConfigured:Boolean(config.sms)};
  const fields=verifiedPayload?.data?.attributes?.fields||{};
  const identityVerified=mode==='production'&&verification.status==='approved'&&verification.document&&verification.selfie&&verification.nameMatches&&verification.birthdatePresent;
  const birthdate=String(identityLock?.birthdate||(identityVerified&&validBirthdate(fields.birthdate?.value)?fields.birthdate.value:privateDetails.birthdate)||'');
  const details={birthdate,gender:String(identityLock?.gender??privateDetails.gender??''),address:String(identityLock?.address??privateDetails.address??''),birthdateVerified:Boolean(identityLock),locked:Boolean(identityLock)};
  let signature:string|null=null;
  const signingKey=process.env.IDENTITY_CARD_SIGNING_PRIVATE_KEY;
  if(signingKey){const key=createPrivateKey(signingKey);if(key.asymmetricKeyType!=='ed25519')throw new Error('INVALID_CARD_KEY');signature=sign(null,Buffer.from('AVI-CARD-v1:'+avid+':'+code),key).toString('base64url');}
  const barcode=bwip.toSVG({bcid:'code128',text:code,height:10,scale:2,paddingwidth:12,paddingheight:4});
  // Fixed trusted destinations; the fragment keeps the opaque reference out of server request logs.
  const cardUrl=(url.searchParams.get('brand')==='aura'?'https://aviwavey.com/AuraAI/':'https://aviwavey.com/')+'#identity-card='+encodeURIComponent(code)+(signature?'&avid='+encodeURIComponent(avid)+'&signature='+signature:'');
  const qr=await QRCode.toString(cardUrl,{type:'svg',errorCorrectionLevel:'M',margin:4,color:{dark:'#000000ff',light:'#ffffff00'}});
  const requests=await sql`SELECT id,field,status,created_at FROM truemark_identity_change_requests WHERE owner_id=${owner} ORDER BY created_at DESC LIMIT 10`;
  const changeRequests=requests.map(r=>({id:r.id,field:r.field,status:r.status,createdAt:r.created_at}));
  return send(200,{correctionsReady,changeRequests,accountId:owner,avid,details,protectedAccount,paymentCard:{status:'unissued',number:null,securityCode:null,expiry:null},signatureStatus:signature?'signed':'not_configured',cardCode:code,cardUrl,issuedAt:card.created_at,name:[legalFirst,legalLast].filter(Boolean).join(' ')||'Legal name not provided',portrait,portraitConsent:Boolean(record?.portrait_consented_at),barcode:'data:image/svg+xml;base64,'+Buffer.from(barcode).toString('base64'),qr:'data:image/svg+xml;base64,'+Buffer.from(qr).toString('base64'),configured,mode,verification});
 }
 let raw='';for await(const chunk of req){raw+=chunk.toString();if(Buffer.byteLength(raw)>2800000)return send(413,{error:'Request too large.'});}
 let input;try{input=JSON.parse(raw);}catch{return send(400,{error:'Invalid request.'});}
 if(input?.action==='request-change'){
  if(!correctionsReady)return send(503,{error:'Secure evidence submission and review are not configured yet.'});
  const fields=['legal_name','birthdate','gender','email','mobile','linked_account','address'];
  if(!fields.includes(input.field)||typeof input.requestedValue!=='string'||!input.requestedValue.trim()||input.requestedValue.length>600||typeof input.reason!=='string'||input.reason.trim().length<20||input.reason.length>2000)return send(400,{error:'Select a field, describe the correction and provide a reason of at least 20 characters.'});
  const match=typeof input.evidence==='string'&&/^data:(application\/pdf|image\/jpeg|image\/png);base64,([A-Za-z0-9+/=]+)$/.exec(input.evidence);
  if(!match)return send(400,{error:'Provide a PDF, JPEG or PNG as supporting evidence.'});
  const bytes=Buffer.from(match[2],'base64');
  const valid=match[1]==='application/pdf'?bytes.subarray(0,5).toString()==='%PDF-':match[1]==='image/png'?bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
  if(!valid||bytes.length<16||bytes.length>2000000)return send(400,{error:'Evidence must be a valid PDF, JPEG or PNG smaller than 2 MB.'});
  const pending=await sql`SELECT count(*) AS total FROM truemark_identity_change_requests WHERE owner_id=${owner} AND created_at>now()-interval '24 hours'`;
  if(Number(pending[0].total)>=3)return send(429,{error:'You have submitted several requests today. Please wait before submitting another.'});
  const id=randomUUID(),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',evidenceKey,iv);
  cipher.setAAD(Buffer.from(owner+':'+id));
  const encrypted=Buffer.concat([cipher.update(JSON.stringify({requestedValue:input.requestedValue.trim(),reason:input.reason.trim(),evidence:input.evidence}),'utf8'),cipher.final()]);
  const sealed=JSON.stringify({version:1,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),ciphertext:encrypted.toString('base64')});
  await sql`INSERT INTO truemark_identity_change_requests(id,owner_id,field,sealed_payload) VALUES(${id},${owner},${input.field},${sealed})`;
  return send(202,{id,status:'pending_review'});
 }
 if(input?.action==='save-details'){
  if(configured&&record?.inquiry_id){try{await captureLock();}catch{return send(503,{error:'Verification status could not be checked. Please retry before changing protected details.'});}}
  const first=typeof input.firstName==='string'?input.firstName.trim():legalFirst,last=typeof input.lastName==='string'?input.lastName.trim():legalLast;
  if(!first||!last||first.length>120||last.length>120||typeof input.birthdate!=='string'||(input.birthdate&&!validBirthdate(input.birthdate))||!privateGender(input.gender)||typeof input.address!=='string'||input.address.length>600)return send(400,{error:'Provide your legal name, a valid date of birth and an address no longer than 600 characters.'});
  if(identityLock&&!protectedDetailsMatch(identityLock,{firstName:first,lastName:last,birthdate:input.birthdate,address:input.address.trim(),gender:input.gender}))return send(409,{error:'Verified identity details are locked. Submit an evidence-backed correction request.'});
  if(identityLock)return send(200,{saved:true});
  else{
   const saved=await sql`INSERT INTO truemark_private_details(owner_id,birthdate,gender,address,first_name,last_name) SELECT ${owner},${input.birthdate},${input.gender.trim()},${input.address.trim()},${first},${last} WHERE NOT EXISTS(SELECT 1 FROM truemark_verified_identity WHERE owner_id=${owner}) ON CONFLICT(owner_id) DO UPDATE SET birthdate=EXCLUDED.birthdate,gender=EXCLUDED.gender,address=EXCLUDED.address,first_name=EXCLUDED.first_name,last_name=EXCLUDED.last_name,updated_at=now() WHERE NOT EXISTS(SELECT 1 FROM truemark_verified_identity WHERE owner_id=${owner}) RETURNING owner_id`;
   if(!saved.length)return send(409,{error:'Your identity was verified. Refresh before making further changes.'});
  }
  return send(200,{saved:true});
 }
 if(!privateGender(privateDetails.gender)||!validBirthdate(privateDetails.birthdate)||!legalFirst.trim()||!legalLast.trim())return send(400,{error:'Save your legal name, date of birth and private gender selection before verification.'});
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
