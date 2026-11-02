import { neon, type NeonQueryFunction } from '@neondatabase/serverless';
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { adminCookie, challengeCookie, token, digest, cookie, readCookie, permitted, publicAccount, validSession, matchesEnrollment, requireSameOrigin } from '../src/AdminPolicy.mjs';
import { createAdminKey, adminPublicKey, adminToken } from '../src/AdminIdentity.mjs';

const origin = 'https://aviwavey.com', rpID = 'aviwavey.com';
const service = 'https://aware-otter-964.convex.cloud';
const fail = (message:string,status=400):never => {throw Object.assign(new Error(message),{status});};
let initialized:Promise<void>|undefined;
async function initialize(sql:NeonQueryFunction<false,false>) {
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_accounts(id text PRIMARY KEY,email text NOT NULL UNIQUE,role text NOT NULL CHECK(role IN ('owner','administrator','moderator','support','analyst')),products jsonb NOT NULL DEFAULT '[]',status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE UNIQUE INDEX IF NOT EXISTS avw_admin_single_owner ON avw_admin_accounts(role) WHERE role='owner'`;
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_credentials(id text PRIMARY KEY,owner_id text NOT NULL REFERENCES avw_admin_accounts(id),public_key text NOT NULL,counter bigint NOT NULL,transports jsonb NOT NULL,label text NOT NULL,created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_sessions(id text PRIMARY KEY,owner_id text NOT NULL REFERENCES avw_admin_accounts(id),token_hash text NOT NULL UNIQUE,created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL,last_seen timestamptz NOT NULL DEFAULT now(),revoked_at timestamptz)`;
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_challenges(id text PRIMARY KEY,kind text NOT NULL,payload jsonb NOT NULL,expires_at timestamptz NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_limits(id text PRIMARY KEY,count integer NOT NULL,expires_at timestamptz NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_audit(id text PRIMARY KEY,actor text,event text NOT NULL,target text,created_at timestamptz NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS avw_admin_service_keys(service text PRIMARY KEY,kid text NOT NULL,sealed text NOT NULL)`;
  await sql`CREATE INDEX IF NOT EXISTS avw_admin_challenges_expiry ON avw_admin_challenges(expires_at)`;
  await sql`CREATE INDEX IF NOT EXISTS avw_admin_limits_expiry ON avw_admin_limits(expires_at)`;
  await sql`CREATE INDEX IF NOT EXISTS avw_admin_sessions_owner ON avw_admin_sessions(owner_id)`;
  await sql`CREATE INDEX IF NOT EXISTS avw_admin_audit_actor ON avw_admin_audit(actor,created_at DESC)`;
}
async function bodyOf(req:IncomingMessage) {
  if (!req.headers['content-type']?.startsWith('application/json')) fail('Send a JSON request.',415);
  const chunks:Buffer[]=[];let size=0;
  for await(const chunk of req){const part=Buffer.from(chunk);size+=part.length;if(size>32768)fail('This request is too large.',413);chunks.push(part);}
  try { const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!data||Array.isArray(data)||typeof data!=='object')fail('Invalid request.');return data; }catch{fail('Invalid request.');}
}
export default async function handler(req:IncomingMessage,res:ServerResponse) {
  const send=(status:number,data:unknown)=>{res.statusCode=status;res.setHeader('content-type','application/json; charset=utf-8');res.setHeader('cache-control','no-store, private');res.setHeader('x-content-type-options','nosniff');res.setHeader('x-robots-tag','noindex, nofollow');res.end(JSON.stringify(data));};
  try {
    const url=new URL(req.url||'/',origin),path=url.searchParams.get('route')||url.pathname.replace(/^\/api\/admin\/?/,'');
    if(!['GET','POST'].includes(req.method||''))return send(405,{error:'Method not allowed.'});
    if(!requireSameOrigin(req.method!,req.headers.origin,req.headers['sec-fetch-site'] as string|undefined,origin))return send(403,{error:'Open administration on AVI Wavey to continue.'});
    // Publishing the entrance must not initialize a database or enroll an owner.
    // Enable only after the owner has deliberately configured administrator access.
    if(process.env.ADMINISTRATION_ENABLED!=='true'){
      if(path==='session'&&req.method==='GET')return send(200,{authenticated:false,account:null,ready:false});
      return send(503,{error:'Administrator sign-in setup is pending. No access has been granted.'});
    }
    if(!process.env.DATABASE_URL)return send(503,{error:'Administration is not connected yet.'});
    const sql=neon(process.env.DATABASE_URL);
    if(!initialized)initialized=initialize(sql).catch(error=>{initialized=undefined;throw error;});await initialized;
    const log=async(actor:string|null,event:string,target:string|null=null)=>{await sql`INSERT INTO avw_admin_audit(id,actor,event,target) VALUES(${randomUUID()},${actor},${event},${target})`;};
    const limit=async(bucket:string,max:number,seconds:number)=>{
      const id=digest(bucket),until=new Date(Date.now()+seconds*1000).toISOString();
      const rows=await sql`INSERT INTO avw_admin_limits(id,count,expires_at) VALUES(${id},1,${until}) ON CONFLICT(id) DO UPDATE SET count=CASE WHEN avw_admin_limits.expires_at<now() THEN 1 ELSE avw_admin_limits.count+1 END,expires_at=CASE WHEN avw_admin_limits.expires_at<now() THEN ${until}::timestamptz ELSE avw_admin_limits.expires_at END RETURNING count`;
      if(Number(rows[0]?.count)>max){res.setHeader('retry-after',String(seconds));fail('Too many attempts. Please wait before trying again.',429);}
    };
    const ip=String(req.headers['x-vercel-forwarded-for']||req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();
    const existingOwner=async()=>{const rows=await sql`SELECT id FROM avw_admin_accounts WHERE role='owner' LIMIT 1`;return rows[0];};
    const authenticate=async(touch=true)=>{
      const raw=readCookie(req.headers.cookie,adminCookie);if(!raw)return null;
      const rows=await sql`SELECT a.*,s.id AS session_id,s.created_at AS signed_in_at,s.expires_at,s.last_seen,s.revoked_at FROM avw_admin_sessions s JOIN avw_admin_accounts a ON a.id=s.owner_id WHERE s.token_hash=${digest(raw)} LIMIT 1`;
      const row=rows[0];if(!validSession(row))return null;
      if(touch)await sql`UPDATE avw_admin_sessions SET last_seen=now() WHERE id=${row.session_id} AND revoked_at IS NULL`;
      return row;
    };
    const current=async()=>{const a=await authenticate();if(!a)fail('Sign in to administration to continue.',401);return a!;};
    const fresh=async()=>{const a=await current();if(Date.parse(String(a.signed_in_at))<Date.now()-300000)fail('Sign out and verify your passkey again before changing access.',403);return a;};
    const challenge=async(kind:string,payload:unknown)=>{
      const raw=token();await sql`INSERT INTO avw_admin_challenges(id,kind,payload,expires_at) VALUES(${digest(raw)},${kind},${JSON.stringify(payload)}::jsonb,now()+interval '5 minutes')`;
      res.setHeader('set-cookie',cookie(challengeCookie,raw,300));
    };
    const consume=async(kind:string)=>{
      const raw=readCookie(req.headers.cookie,challengeCookie);if(!raw)fail('This sign-in expired. Please start again.',401);
      const rows=await sql`DELETE FROM avw_admin_challenges WHERE id=${digest(raw!)} AND kind=${kind} AND expires_at>now() RETURNING payload`;
      res.setHeader('set-cookie',cookie(challengeCookie,'',0));if(!rows.length)fail('This sign-in expired. Please start again.',401);return rows[0].payload;
    };
    const session=async(owner:string)=>{
      const raw=token();await sql`INSERT INTO avw_admin_sessions(id,owner_id,token_hash,expires_at) VALUES(${randomUUID()},${owner},${digest(raw)},now()+interval '8 hours')`;
      res.setHeader('set-cookie',[cookie(adminCookie,raw,28800),cookie(challengeCookie,'',0)]);
      await log(owner,'sign_in');
    };
    const key=async()=>{
      const secret=process.env.ADMIN_SERVICE_SECRET;if(!secret||secret.length<32)fail('The private moderation connection needs configuration.',503);
      const bytes=Buffer.from(secret!);let rows=await sql`SELECT kid,sealed FROM avw_admin_service_keys WHERE service='social-link'`;
      if(!rows.length){const candidate=createAdminKey(bytes);await sql`INSERT INTO avw_admin_service_keys(service,kid,sealed) VALUES('social-link',${candidate.kid},${candidate.sealed}) ON CONFLICT DO NOTHING`;rows=await sql`SELECT kid,sealed FROM avw_admin_service_keys WHERE service='social-link'`;}
      return {record:{kid:String(rows[0].kid),sealed:String(rows[0].sealed)},secret:bytes};
    };
    if(path==='keys'&&req.method==='GET'){const k=await key();return send(200,{keys:[adminPublicKey(k.record,k.secret)]});}
    if(path==='session'&&req.method==='GET'){
      const a=await authenticate(false);return send(200,{authenticated:!!a,account:a?publicAccount(a):null,ready:true});
    }
    if(path==='auth/options'&&req.method==='POST'){
      await limit('signin:'+ip,30,900);await bodyOf(req);
      await sql`DELETE FROM avw_admin_challenges WHERE id IN (SELECT id FROM avw_admin_challenges WHERE expires_at<now() LIMIT 100)`;
      await sql`DELETE FROM avw_admin_limits WHERE id IN (SELECT id FROM avw_admin_limits WHERE expires_at<now() LIMIT 100)`;
      const options=await generateAuthenticationOptions({rpID,userVerification:'required',timeout:60000});await challenge('login',{challenge:options.challenge});return send(200,options);
    }
    if(path==='auth/verify'&&req.method==='POST'){
      await limit('verify:'+ip,12,900);const body=await bodyOf(req),c=await consume('login');
      const rows=await sql`SELECT k.*,a.status FROM avw_admin_credentials k JOIN avw_admin_accounts a ON a.id=k.owner_id WHERE k.id=${String(body.id||'')} LIMIT 1`;
      const k=rows[0];if(!k||k.status!=='active')fail('This passkey cannot sign in to administration.',401);
      let verified;
      try{verified=await verifyAuthenticationResponse({response:body,expectedChallenge:c.challenge,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true,credential:{id:String(k.id),publicKey:new Uint8Array(Buffer.from(String(k.public_key),'base64url')),counter:Number(k.counter),transports:k.transports}});}catch{fail('This passkey could not be verified.',401);}
      if(!verified!.verified)fail('This passkey could not be verified.',401);
      const changed=await sql`UPDATE avw_admin_credentials SET counter=${verified!.authenticationInfo.newCounter} WHERE id=${k.id} AND counter=${k.counter} RETURNING id`;
      if(!changed.length)fail('Please verify your passkey again.',409);await session(String(k.owner_id));return send(200,{authenticated:true});
    }
    if(path==='enroll/options'&&req.method==='POST'){
      await limit('enroll:'+ip,6,900);const body=await bodyOf(req);
      if(await existingOwner()||!matchesEnrollment(body.invitation,process.env.ADMIN_OWNER_ENROLLMENT_SHA256,process.env.ADMIN_OWNER_ENROLLMENT_EXPIRES_AT))fail('This invitation is unavailable or expired.',403);
      const email=process.env.ADMIN_OWNER_EMAIL?.trim().toLowerCase();if(!email||!/^\S+@\S+\.\S+$/.test(email))fail('The owner invitation needs configuration.',503);
      const id=randomUUID(),options=await generateRegistrationOptions({rpID,rpName:'AVI Wavey Administration',userID:new TextEncoder().encode(id),userName:email!,userDisplayName:'Owner',attestationType:'none',authenticatorSelection:{residentKey:'required',userVerification:'required'},supportedAlgorithmIDs:[-7,-257],timeout:60000});
      await challenge('enroll',{challenge:options.challenge,id,email,invitationHash:digest(body.invitation)});return send(200,options);
    }
    if(path==='enroll/verify'&&req.method==='POST'){
      await limit('enrollverify:'+ip,6,900);const body=await bodyOf(req),c=await consume('enroll');
      if(await existingOwner()||c.invitationHash!==process.env.ADMIN_OWNER_ENROLLMENT_SHA256||!(Date.parse(process.env.ADMIN_OWNER_ENROLLMENT_EXPIRES_AT||'')>Date.now())||c.email!==process.env.ADMIN_OWNER_EMAIL?.trim().toLowerCase())fail('This invitation is unavailable or expired.',403);
      let result;try{result=await verifyRegistrationResponse({response:body,expectedChallenge:c.challenge,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]});}catch{fail('The passkey could not be registered. Please try again.',400);}
      if(!result!.verified||!result!.registrationInfo)fail('The passkey could not be registered.');const k=result!.registrationInfo!.credential;
      const rows=await sql`WITH owner AS (INSERT INTO avw_admin_accounts(id,email,role,products) VALUES(${c.id},${c.email},'owner','["avi","aura","mike"]'::jsonb) ON CONFLICT DO NOTHING RETURNING id) INSERT INTO avw_admin_credentials(id,owner_id,public_key,counter,transports,label) SELECT ${k.id},id,${Buffer.from(k.publicKey).toString('base64url')},${k.counter},${JSON.stringify(k.transports||[])}::jsonb,'Owner passkey' FROM owner RETURNING id`;
      if(!rows.length)fail('Owner setup has already been completed.',409);await log(c.id,'owner_enrolled');await session(c.id);return send(200,{authenticated:true});
    }
    const a=await current();await limit('account:'+a.id,120,60);
    if(path==='logout'&&req.method==='POST'){
      await bodyOf(req);await sql`UPDATE avw_admin_sessions SET revoked_at=now() WHERE id=${a.session_id}`;await log(String(a.id),'sign_out');res.setHeader('set-cookie',cookie(adminCookie,'',0));return send(200,{signedOut:true});
    }
    if(path==='overview'&&req.method==='GET'){
      const product=url.searchParams.get('product')||'avi';if(!permitted(a as any,product,'overview.read'))fail('This website is outside your permissions.',403);
      const activity=await sql`SELECT event,target,created_at FROM avw_admin_audit WHERE actor=${a.id} ORDER BY created_at DESC LIMIT 8`;
      return send(200,{account:publicAccount(a),product,capabilities:{safety:product==='avi'&&!!process.env.ADMIN_SERVICE_SECRET&&permitted(a as any,product,'safety.review'),identity:permitted(a as any,product,'identity.read'),security:true},activity});
    }
    if(path==='security'&&req.method==='GET'){
      const keys=await sql`SELECT id,label,created_at FROM avw_admin_credentials WHERE owner_id=${a.id} ORDER BY created_at ASC LIMIT 20`;
      const sessions=await sql`SELECT id,created_at,last_seen FROM avw_admin_sessions WHERE owner_id=${a.id} AND revoked_at IS NULL AND expires_at>now() AND last_seen>now()-interval '30 minutes' ORDER BY created_at DESC LIMIT 20`;
      return send(200,{keys,sessions:sessions.map(s=>({...s,current:s.id===a.session_id}))});
    }
    if(path==='security/revoke'&&req.method==='POST'){
      const body=await bodyOf(req);await fresh();if(body.id===a.session_id)fail('Use Sign out to end this session.');
      await sql`UPDATE avw_admin_sessions SET revoked_at=now() WHERE id=${String(body.id||'')} AND owner_id=${a.id}`;await log(String(a.id),'session_revoked');return send(200,{revoked:true});
    }
    if(path==='security/key/options'&&req.method==='POST'){
      await bodyOf(req);await fresh();const keys=await sql`SELECT id FROM avw_admin_credentials WHERE owner_id=${a.id}`;if(keys.length>=10)fail('You already have ten administrator passkeys.');
      const options=await generateRegistrationOptions({rpID,rpName:'AVI Wavey Administration',userID:new TextEncoder().encode(String(a.id)),userName:String(a.email),userDisplayName:'Administrator',attestationType:'none',excludeCredentials:keys.map(k=>({id:String(k.id)})),authenticatorSelection:{residentKey:'required',userVerification:'required'},supportedAlgorithmIDs:[-7,-257]});
      await challenge('addkey',{challenge:options.challenge,owner:a.id,session:a.session_id});return send(200,options);
    }
    if(path==='security/key/verify'&&req.method==='POST'){
      await fresh();const body=await bodyOf(req),c=await consume('addkey');if(c.owner!==a.id||c.session!==a.session_id)fail('Verify your access again.',403);
      let result;try{result=await verifyRegistrationResponse({response:body.credential,expectedChallenge:c.challenge,expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]});}catch{fail('The passkey could not be registered.');}
      if(!result!.verified||!result!.registrationInfo)fail('The passkey could not be registered.');const k=result!.registrationInfo!.credential;
      const label=typeof body.label==='string'?body.label.trim().slice(0,60):'Backup passkey';
      await sql`INSERT INTO avw_admin_credentials(id,owner_id,public_key,counter,transports,label) VALUES(${k.id},${a.id},${Buffer.from(k.publicKey).toString('base64url')},${k.counter},${JSON.stringify(k.transports||[])}::jsonb,${label||'Backup passkey'})`;
      await log(String(a.id),'passkey_added');return send(200,{added:true});
    }
    if(path==='identity'&&req.method==='GET'){
      if(a.role!=='owner')fail('Owner access is required.',403);
      const accounts=await sql`SELECT id,email,role,products,status,created_at FROM avw_admin_accounts ORDER BY created_at ASC LIMIT 100`;return send(200,{accounts});
    }
    if(path==='safety'&&req.method==='POST'){
      if(!permitted(a as any,'avi','safety.review'))fail('Safety access is required.',403);
      const body=await bodyOf(req);if(body.product!=='avi')fail('This website has not connected its report service.',409);
      const action=body.action==='queue'?'query':body.action==='review'?'mutation':null;if(!action)fail('Unknown safety action.');
      const k=await key();await log(String(a.id),body.action==='review'?'report_review_requested':'report_queue_opened',body.action==='review'?String(body.args?.id||'').slice(0,100):null);
      const response=await fetch(service+'/api/'+action,{method:'POST',redirect:'error',headers:{'content-type':'application/json',authorization:'Bearer '+adminToken(k.record,k.secret,String(a.id))},body:JSON.stringify({path:'moderation:'+body.action,args:body.args||{},format:'json'}),signal:AbortSignal.timeout(20000)});
      const result=await response.json();if(!response.ok||result.status!=='success')fail(typeof result.errorData==='string'?result.errorData:'The report service could not complete this request.',502);
      if(body.action==='review')await log(String(a.id),'report_review_completed',String(body.args?.id||'').slice(0,100));return send(200,result.value);
    }
    return send(404,{error:'This administration action is not available.'});
  }catch(error){const e=error as Error&{status?:number};send(e.status||503,{error:e.status?e.message:'Administration could not connect. Please retry.'});}
}
