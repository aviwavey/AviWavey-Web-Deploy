import {moduleAccess} from '../src/ModuleReleasePolicy.mjs';
import { neon } from "@neondatabase/serverless";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { SignJWT, jwtVerify } from "jose";
import { AccountService } from "../src/account-service.js";
import { loadConfig } from "../src/config.js";
import { ContactVerificationService } from "../src/contact-verification.js";
import { parseProduct, publicAuthError, validatedReturnPath } from "../src/http-contract.js";
import { NeonIdentityRepository } from "../src/neon-repository.js";
import { appleAuthorizationUrl, exchangeAppleCode, exchangeGoogleCode, googleAuthorizationUrl } from "../src/oauth.js";
import { ScryptPasswordHasher } from "../src/passwords.js";
import { cookieValue, cookieValues, DatabaseSessionIssuer } from "../src/sessions.js";
import { profileComplete } from "../src/domain.js";
import { AccountSettingsService } from "../src/account-settings.js";

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const tempCookie = (name: string, value: string, maxAge = 600) => `${name}=${value}; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const clearCookie = (name: string, path = "/api/auth") => `${name}=; Path=${path}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
const clearDomainCookie = (name: string, hostname: string, path = "/") => `${name}=; Path=${path}; Domain=.${hostname}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
const sessionCookies = (cookieName: string, sessionCookie: string, hostname: string) => [
  // Older deployments scoped the session cookie to /api/auth. Browsers prefer
  // that more-specific stale cookie over the current site-wide cookie on API
  // requests, so remove it whenever a fresh session is established.
  clearCookie(cookieName, "/api/auth"),
  clearDomainCookie(cookieName, hostname, "/api/auth"),
  clearDomainCookie(cookieName, hostname, "/"),
  sessionCookie,
];
const string = (value: unknown) => typeof value === "string" ? value.trim() : "";
type UploadedFile = { size: number; type: string; arrayBuffer(): Promise<ArrayBuffer> };
const uploadedFile = (value: unknown): value is UploadedFile => Boolean(
  value && typeof value === "object" &&
  typeof (value as UploadedFile).size === "number" &&
  typeof (value as UploadedFile).type === "string" &&
  typeof (value as UploadedFile).arrayBuffer === "function",
);

const json = (response: ServerResponse, status: number, body: unknown, headers?: Record<string, string | string[]>) => {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  for (const [name, value] of Object.entries(headers ?? {})) response.setHeader(name, value);
  response.end(JSON.stringify(body));
};

async function jsonBody(request: IncomingMessage, limit = 16384) {
  const chunks: Buffer[] = [];
  let size=0;for await (const chunk of request){const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);size+=b.length;if(size>limit)throw new Error("REQUEST_TOO_LARGE");chunks.push(b);}
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown> : {};
}

async function formBody(request: IncomingMessage, absoluteUrl: string) {
  const init = { method: request.method, headers: request.headers as HeadersInit, body: Readable.toWeb(request) as ReadableStream, duplex: "half" } as RequestInit & { duplex: string };
  return new Request(absoluteUrl, init).formData();
}

export default async function handler(request: IncomingMessage, response: ServerResponse) {
  try {
    const config = loadConfig();
    const requestUrl = new URL(request.url ?? "/api/auth", config.baseUrl);
    const routedPath = requestUrl.searchParams.get("path");
    if (routedPath) requestUrl.pathname = `/api/auth/${routedPath.replace(/^\/+/, "")}`;
    const identities = new NeonIdentityRepository(config.databaseUrl);
    const sessions = new DatabaseSessionIssuer(config.databaseUrl, config.sessionCookieName, config.production);
    const accounts = new AccountService(identities, new ScryptPasswordHasher(), sessions, () => crypto.randomUUID());
    const contacts = new ContactVerificationService(config);
    const settings = new AccountSettingsService(config.databaseUrl);
    let authenticatedToken='';
    const current = async () => {
      // Legacy host-only, domain-wide and path-scoped cookies can arrive in any
      // order. Select the first token that is still a valid database session.
      for (const token of cookieValues(request.headers.cookie, config.sessionCookieName)) {
        const authenticated = await sessions.authenticate(token);
        if (authenticated){authenticatedToken=token;return authenticated;}
      }
      return undefined;
    };

    // Presentation metadata is signed and bound to the exact active session.
    // It never grants access or guesses a provider from an email address.
    const signInCookieName=config.sessionCookieName+'_method';
    const signedInCookies=async(session:{cookie:string;expiresAt?:Date},signInMethod:'google'|'apple'|'email')=>{
      const token=cookieValue(session.cookie,config.sessionCookieName);
      if(!token)throw new Error('AUTHENTICATION_FAILED');
      const marker=await new SignJWT({signInMethod})
        .setProtectedHeader({alg:'HS256'}).setIssuer('TrueMarkGate').setAudience('session-method')
        .setSubject(createHash('sha256').update(token).digest('base64url')).setIssuedAt()
        .setExpirationTime(session.expiresAt?Math.floor(session.expiresAt.getTime()/1000):'30d').sign(config.sessionSigningKey);
      return [...sessionCookies(config.sessionCookieName,session.cookie,config.baseUrl.hostname),tempCookie(signInCookieName,marker,30*24*60*60)];
    };
    const readSignInMethod=async()=>{
      const marker=cookieValue(request.headers.cookie,signInCookieName);if(!marker||!authenticatedToken)return undefined;
      try{
        const {payload}=await jwtVerify(marker,config.sessionSigningKey,{algorithms:['HS256'],issuer:'TrueMarkGate',audience:'session-method'});
        if(payload.sub!==createHash('sha256').update(authenticatedToken).digest('base64url'))return undefined;
        return ['google','apple','email'].includes(String(payload.signInMethod))?payload.signInMethod as 'google'|'apple'|'email':undefined;
      }catch{return undefined;}
    };

    const sql=neon(config.databaseUrl);
    const verifyAttempt=async(state:string)=>{
      if(!state)throw new Error('OAUTH_STATE_INVALID');
      const verified=await jwtVerify(state,config.sessionSigningKey,{algorithms:['HS256']});
      const id=verified.payload.jti||'';
      if(verified.payload.transaction===2){
        if(!/^[A-Za-z0-9_-]{22}$/.test(id))throw new Error('OAUTH_STATE_INVALID');
        const verifier=cookieValue(request.headers.cookie,'avi_oauth_'+id);
        if(!verifier)throw new Error('OAUTH_STATE_INVALID');
        return {verified,verifier,clear:[clearCookie('avi_oauth_'+id)]};
      }
      if(state!==cookieValue(request.headers.cookie,'avi_oauth_state'))throw new Error('OAUTH_STATE_INVALID');
      return {verified,verifier:cookieValue(request.headers.cookie,'avi_oauth_verifier')||'',clear:[clearCookie('avi_oauth_state'),clearCookie('avi_oauth_verifier')]};
    };

    const settingsPath=(product:string)=>product==='aura'?'/AuraAI/settings/':'/dashboard/settings';
    const redirect=(path:string,cookies:string[]=[])=>{response.statusCode=303;response.setHeader('Cache-Control','no-store');response.setHeader('Location',new URL(path,config.baseUrl).toString());if(cookies.length)response.setHeader('Set-Cookie',cookies);response.end();};
    const proof=async(kind:string,payload:Record<string,unknown>)=>new SignJWT({...payload,kind}).setProtectedHeader({alg:'HS256'}).setIssuer('TrueMarkGate').setAudience('account-change').setIssuedAt().setExpirationTime('5m').setJti(b64(randomBytes(24))).sign(config.sessionSigningKey);
    const readProof=async(name:string,kind:string)=>{try{const t=cookieValue(request.headers.cookie,name);if(!t)return null;const v=await jwtVerify(t,config.sessionSigningKey,{algorithms:['HS256'],issuer:'TrueMarkGate',audience:'account-change'});return v.payload.kind===kind?v.payload:null;}catch{return null;}};
    const consume=async(jti:string)=>{await sql`CREATE TABLE IF NOT EXISTS truemark_consumed_proofs(jti text PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now())`;const rows=await sql`INSERT INTO truemark_consumed_proofs(jti) VALUES(${jti}) ON CONFLICT DO NOTHING RETURNING jti`;if(!rows.length)throw new Error('OAUTH_STATE_INVALID');};
    if(request.method==='POST'&&!requestUrl.pathname.endsWith('/callback')){
      const origin=request.headers.origin;if(origin!==config.baseUrl.origin||request.headers['sec-fetch-site']==='cross-site')return json(response,403,{message:'Open this action from the signed-in website.'});
    }
    if(request.method==='GET'&&requestUrl.pathname.endsWith('/methods')){
      const a=await current();if(!a)return json(response,401,{message:'Sign in to continue.'});
      const p=await readProof('avi_password_proof','password');const credentials=await identities.credentialsForUser(a.userId);
      return json(response,200,{passwordReady:Boolean(p&&p.userId===a.userId&&p.sessionId===a.sessionId),hasPassword:credentials.some(c=>c.kind==='password'&&!c.revokedAt)});
    }
    if(request.method==='POST'&&requestUrl.pathname.endsWith('/password/add')){
      const a=await current(),p=await readProof('avi_password_proof','password');if(!a||!p||p.userId!==a.userId||p.sessionId!==a.sessionId)return json(response,403,{message:'Verify a linked account again before setting a password.'});
      if((await identities.findUserById(a.userId))?.status!=='active')throw new Error('AUTHENTICATION_FAILED');
      const body=await jsonBody(request),password=typeof body.password==='string'?body.password:'';
      if(password.length<12||password.length>256)return json(response,400,{message:'Use a password between 12 and 256 characters.'});
      if(await identities.passwordCredentialForUser(a.userId))return json(response,409,{message:'A password already exists. Use password recovery to change it.'});
      const secret=await new ScryptPasswordHasher().hash(password);await consume(String(p.jti));
      // A stable subject makes concurrent attempts idempotent under the existing unique constraint.
      await identities.saveCredential({id:randomUUID(),userId:a.userId,kind:'password',providerSubject:'local:'+a.userId,secretHash:secret});
      return json(response,200,{saved:true},{'Set-Cookie':clearCookie('avi_password_proof')});
    }
    if(request.method==='POST'&&requestUrl.pathname.endsWith('/callback')){
      const form=await formBody(request,requestUrl.toString()),state=string(form.get('state'));
      await verifyAttempt(state);
      // Apple form_post arrives cross-site; continue on a same-site GET so the account session is available.
      return redirect('/api/auth/callback?'+new URLSearchParams({state,code:string(form.get('code'))}));
    }
    if(requestUrl.pathname.endsWith('/link')){
      const p=await readProof('avi_link_proof','link');if(!p)return json(response,410,{message:'This link request expired. Start again from Settings.'});
      const identity=p.identity as {provider:'google'|'apple';subject:string;verifiedEmail:string};
      if(request.method==='POST'){
        const form=await formBody(request,requestUrl.toString());if(string(form.get('consent'))!=='yes')return json(response,400,{message:'Confirm that you want to link the account.'});
        let a=await current();let cookie='';
        if(!a||a.userId!==p.target){
          await sql`CREATE TABLE IF NOT EXISTS truemark_link_attempts(owner_id text PRIMARY KEY,attempts integer NOT NULL,window_start timestamptz NOT NULL DEFAULT now())`;
          const attempts=await sql`INSERT INTO truemark_link_attempts(owner_id,attempts) VALUES(${String(p.target)},1) ON CONFLICT(owner_id) DO UPDATE SET attempts=CASE WHEN truemark_link_attempts.window_start < now()-interval '15 minutes' THEN 1 ELSE truemark_link_attempts.attempts+1 END,window_start=CASE WHEN truemark_link_attempts.window_start < now()-interval '15 minutes' THEN now() ELSE truemark_link_attempts.window_start END RETURNING attempts`;
          if(Number(attempts[0].attempts)>5)return json(response,429,{message:'Too many attempts. Please wait 15 minutes before trying again.'});
          const result=await accounts.login({email:string(form.get('email')),password:typeof form.get('password')==='string'?String(form.get('password')):'',product:parseProduct(p.product),remember:false});if(result.userId!==p.target)throw new Error('AUTHENTICATION_FAILED');a={userId:result.userId,sessionId:''};cookie=result.session.cookie;}
        const target=await identities.findUserById(a.userId);if(target?.status!=='active')throw new Error('AUTHENTICATION_FAILED');
        await consume(String(p.jti));await accounts.linkProvider(a.userId,identity);
        return redirect(settingsPath(String(p.product)),[clearCookie('avi_link_proof'),...(cookie?await signedInCookies({cookie},'email'):[])]);
      }
      const a=await current();const signedIn=a?.userId===p.target;
      response.setHeader('Content-Type','text/html; charset=utf-8');response.setHeader('Cache-Control','no-store');response.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
      return response.end(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Link your account</title><style>body{font:16px system-ui;background:#f4f7f6;color:#23483f;margin:0;padding:24px}main{max-width:440px;margin:8vh auto;background:white;padding:28px;border:1px solid #d4e1dd;border-radius:12px}label{display:block;margin:16px 0}input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #adc9bf;border-radius:6px}input[type=checkbox]{width:auto}button,a{display:inline-block;padding:12px;color:#176f61}button{background:#f7e7ee;border:1px solid #ddbbc9;border-radius:6px}</style><main><h1>Link your account</h1><p>An existing account needs your approval before this sign-in method can be linked.</p><form method="post">${signedIn?'': '<label>Existing account email<input name="email" type="email" autocomplete="username" required></label><label>Existing account password<input name="password" type="password" autocomplete="current-password" required></label>'}<label><input type="checkbox" name="consent" value="yes" required> Link this Google or Apple sign-in to my account</label><button type="submit">Confirm link</button></form><p>If your original account uses Google or Apple, sign in using that account first, then link the other account in Settings.</p><a href="${p.product==='aura'?'/AuraAI/sign-in/':'/home?authError=retry'}">Return to sign in</a></main>`);
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/health")) {
      const database = new NeonIdentityRepository(config.databaseUrl);
      await database.findUserById("health-check");
      return json(response, 200, { service: "TrueMarkGate", ready: true, database: "connected", products: ["avi", "aura"], providers: ["email", "google", ...(config.apple ? ["apple"] : []), "passkey"] });
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/config")) {
      return json(response, 200, { providers: { email: true, google: true, apple: Boolean(config.apple), passkey: true }, profileCompletionRequired: true, recoveryAvailable: true });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/register")) {
      const body = await jsonBody(request);
      const result = await accounts.register({ firstName: string(body.firstName), lastName: string(body.lastName), email: string(body.email), password: typeof body.password==="string"?body.password:"", product: parseProduct(body.product), termsAccepted: body.termsAccepted === true });
      return json(response, 201, { authenticated: true, profileComplete: result.profileComplete }, { "Set-Cookie": await signedInCookies(result.session,'email') });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/login")) {
      const body = await jsonBody(request);
      const result = await accounts.login({ email: string(body.email), password: typeof body.password==="string"?body.password:"", product: parseProduct(body.product), remember: body.remember === true });
      return json(response, 200, { authenticated: true, profileComplete: result.profileComplete }, { "Set-Cookie": await signedInCookies(result.session,'email') });
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/start")) {
      const product = parseProduct(requestUrl.searchParams.get("product"));
      const provider = requestUrl.searchParams.get("provider") ?? "google";
      if (provider !== "google" && provider !== "apple") return json(response, 400, { code: "INVALID_PROVIDER", message: "Choose Google or Apple." });
      if (provider === "apple" && !config.apple) return json(response, 503, { code: "PROVIDER_NOT_CONFIGURED", message: "Apple sign-in is not available yet." });
      const intent=requestUrl.searchParams.get('intent')||'signin';
      if(!['signin','link','password'].includes(intent))throw new Error('OAUTH_STATE_INVALID');
      const actor=await current();
      if(intent==='signin' && actor && requestUrl.searchParams.get('switch')!=='1'){
        const user=await identities.findUserById(actor.userId);
        if(user?.status==='active' && user.memberships.includes(product))return redirect(profileComplete(user)?validatedReturnPath(product,requestUrl.searchParams.get('returnTo')||undefined):product==='avi'?'/complete-profile':'/AuraAI/complete-profile/');
      }
      if(intent!=='signin'&&!actor)return json(response,401,{message:'Sign in before changing account access.'});
      const returnTo = validatedReturnPath(product, requestUrl.searchParams.get("returnTo") ?? undefined);
      const verifier = b64(randomBytes(32));
      const challenge = b64(createHash("sha256").update(verifier).digest());
      const nonce = b64(randomBytes(24));
      const attempt=b64(randomBytes(16));
      const state = await new SignJWT({ transaction:2, product, provider, returnTo, nonce, intent, userId:actor?.userId, sessionId:actor?.sessionId }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("10m").setJti(attempt).sign(config.sessionSigningKey);
      response.setHeader("Set-Cookie", [tempCookie("avi_oauth_"+attempt, verifier).replace("SameSite=Lax",provider==="apple"?"SameSite=None":"SameSite=Lax")]);
      response.statusCode = 302;
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Location", provider === "google" ? googleAuthorizationUrl(config, { product, state, codeChallenge: challenge, nonce }).toString() : appleAuthorizationUrl(config, state, nonce).toString());
      return response.end();
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/callback")) {
      const state = requestUrl.searchParams.get("state") ?? "";
      const attempt = await verifyAttempt(state);
      const verifiedState = attempt.verified;
      const product = parseProduct(verifiedState.payload.product);
      const provider=verifiedState.payload.provider;
      if(provider!=='google'&&provider!=='apple')throw new Error('OAUTH_PROVIDER_INVALID');
      const identity=provider==='apple'?await exchangeAppleCode(config,requestUrl.searchParams.get('code')||'',String(verifiedState.payload.nonce||'')):await exchangeGoogleCode(config,product,requestUrl.searchParams.get('code')||'',attempt.verifier,String(verifiedState.payload.nonce||''));
      const clear=attempt.clear;
      if(['link','password'].includes(String(verifiedState.payload.intent))){
        const a=await current();if(!a||a.userId!==verifiedState.payload.userId||a.sessionId!==verifiedState.payload.sessionId)throw new Error('OAUTH_STATE_INVALID');
        const user=await identities.findUserById(a.userId);if(user?.status!=='active')throw new Error('AUTHENTICATION_FAILED');
        await consume(String(verifiedState.payload.jti));
        if(verifiedState.payload.intent==='link')await accounts.linkProvider(a.userId,identity);
        else {const owner=await identities.findUserByProvider(identity.provider,identity.subject);if(owner?.id!==a.userId)throw new Error('AUTHENTICATION_FAILED');clear.push(tempCookie('avi_password_proof',await proof('password',{userId:a.userId,sessionId:a.sessionId}),300));}
        return redirect(settingsPath(product),clear);
      }
      const linked=await identities.findUserByProvider(identity.provider,identity.subject);
      if(!linked){const existing=await identities.findUserByEmail(identity.verifiedEmail.toLowerCase());if(existing){
        if(existing.status!=='active')throw new Error('AUTHENTICATION_FAILED');
        const token=await proof('link',{identity,target:existing.id,product});
        return redirect('/api/auth/link',[...clear,tempCookie('avi_link_proof',token,300)]);
      }}
      const result = await accounts.finishProviderSignIn(identity, product);
      const returnTo = validatedReturnPath(product, String(verifiedState.payload.returnTo ?? ""));
      response.statusCode = 302;
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Set-Cookie", [...await signedInCookies(result.session,provider), ...clear]);
      response.setHeader("Location", new URL(result.profileComplete ? returnTo : product === "avi" ? "/complete-profile" : "/AuraAI/complete-profile/", config.baseUrl).toString());
      return response.end();
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/session")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 200, { authenticated: false });
      const user = await identities.findUserById(authenticated.userId);
      if (!user || user.status !== "active") return json(response, 200, { authenticated: false });
      const completed = profileComplete(user);
      const publicSettings = await settings.read(authenticated.userId).catch(() => undefined);
      return json(response, 200, { authenticated: true, signInMethod: await readSignInMethod(), profileComplete: completed, name: [user.firstName, user.lastName].filter(Boolean).join(" "), email: user.primaryEmail, picture: publicSettings?.public.profilePicture || user.profilePictureKey, memberships: user.memberships, assurance: user.assurance, moduleAccess: moduleAccess(user,process.env) });
    }

    if(requestUrl.pathname.endsWith('/creative-profile')&&['GET','POST'].includes(request.method||'')){
      const a=await current();
      if(!a)return json(response,401,{message:'Sign in to continue.'});
      const user=await identities.findUserById(a.userId);
      if(!user||user.status!=='active'||!profileComplete(user))return json(response,403,{message:'Complete your account profile first.'});
      if(request.method==='GET')return json(response,200,await settings.readCreative(a.userId));
      const body=await jsonBody(request);
      return json(response,200,await settings.saveCreative(a.userId,body.disciplines));
    }
    if (request.method === "GET" && requestUrl.pathname.endsWith("/settings")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      return json(response, 200, await settings.read(authenticated.userId));
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/settings/public")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const form = await formBody(request, requestUrl.toString());
      const photo = form.get("profilePicture");
      let picture: string | undefined;
      if (uploadedFile(photo) && photo.size > 0) {
        if (photo.size > 2_000_000 || !photo.type.startsWith("image/")) return json(response, 400, { code: "INVALID_PROFILE_PICTURE", message: "Choose an image smaller than 2 MB." });
        picture = `data:${photo.type};base64,${Buffer.from(await photo.arrayBuffer()).toString("base64")}`;
      }
      const updated = await settings.updatePublic(authenticated.userId, {
        pronouns:string(form.get("publicPronouns")).slice(0,80), gender:string(form.get("publicGender")).slice(0,80), displayName: string(form.get("displayName")), bio: string(form.get("bio")).slice(0, 500), profilePicture: picture,
        contactEmail: string(form.get("contactEmail")), contactTelephone: string(form.get("contactTelephone")),
        usePrivateTelephone: form.get("usePrivateTelephone") === "true",
      });
      return json(response, 200, updated);
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/settings/private/contact")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const body = await jsonBody(request);
      return json(response, 200, await settings.updatePrivateTelephone(authenticated.userId, string(body.telephone)));
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/contact/telephone/start")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const body = await jsonBody(request);
      await contacts.startTelephone(authenticated.userId, string(body.telephone));
      return json(response, 202, { sent: true });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/contact/telephone/verify")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const body = await jsonBody(request);
      await contacts.verifyTelephone(authenticated.userId, string(body.telephone), string(body.code));
      return json(response, 200, { verified: true });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/profile/complete")) {
      const authenticated = await current();
      if (!authenticated) return json(response, 401, { code: "AUTHENTICATION_REQUIRED", message: "Sign in again to continue." });
      const contentType = String(request.headers["content-type"] ?? "");
      let username = ""; let telephone = ""; let picture = "";
      if (contentType.includes("application/json")) {
        const body = await jsonBody(request, 2_800_000);
        username = string(body.username); telephone = string(body.telephone); picture = string(body.profilePicture);
        const match = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(picture);
        if (!match || Buffer.from(match[2], "base64").byteLength > 2_000_000) return json(response, 400, { code: "PROFILE_PICTURE_REQUIRED", message: "Choose a JPEG, PNG or WebP image smaller than 2 MB." });
      } else {
        const form = await formBody(request, requestUrl.toString());
        const photo = form.get("profilePicture");
        if (!uploadedFile(photo) || photo.size === 0 || photo.size > 2_000_000 || !photo.type.startsWith("image/")) return json(response, 400, { code: "PROFILE_PICTURE_REQUIRED", message: "Choose an image smaller than 2 MB." });
        username = string(form.get("username")); telephone = string(form.get("telephone"));
        picture = `data:${photo.type};base64,${Buffer.from(await photo.arrayBuffer()).toString("base64")}`;
      }
      const user = await identities.completeProfile(authenticated.userId, { username, telephone, profilePictureKey: picture });
      return json(response, 200, { completed: profileComplete(user), telephoneVerified: user.telephoneVerified });
    }
    if (request.method === "POST" && requestUrl.pathname.endsWith("/logout")) {
      const authenticated = await current();
      if (authenticated) await sessions.revoke(authenticated.sessionId);
      return json(response, 200, { authenticated: false }, { "Set-Cookie": [clearCookie(signInCookieName), clearCookie(config.sessionCookieName, "/api/auth"), clearDomainCookie(config.sessionCookieName, config.baseUrl.hostname, "/api/auth"), clearDomainCookie(config.sessionCookieName, config.baseUrl.hostname, "/"), clearCookie(config.sessionCookieName, "/")] });
    }
    return json(response, 404, { code: "AUTH_ROUTE_NOT_FOUND", message: "This authentication route is not available." });
  } catch (error) {
    const callbackUrl=new URL(request.url||'/','https://aviwavey.com');
    if(callbackUrl.pathname.endsWith('/callback')||callbackUrl.searchParams.get('path')==='callback'){
      response.statusCode=303;response.setHeader('Cache-Control','no-store');
      response.setHeader('Location','/home?authError=retry');return response.end();
    }
    const configurationError = error instanceof Error && error.message.startsWith("Missing required configuration:");
    if (!configurationError) {
      const publicError = publicAuthError(error);
      if (publicError.body.code !== "AUTHENTICATION_FAILED" || publicError.status !== 401) return json(response, publicError.status, publicError.body);
    }
    return json(response, configurationError || (request.method==="GET" && (request.url||"").includes("session")) ? 503 : 401, { code: configurationError ? "SERVICE_NOT_CONFIGURED" : "AUTHENTICATION_FAILED", message: configurationError ? "TrueMarkGate is awaiting secure deployment configuration." : "We could not complete that sign-in request." });
  }
}
