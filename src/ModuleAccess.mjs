import {loadConfig} from './config.js';
import {cookieValues,DatabaseSessionIssuer} from './sessions.js';
import {NeonIdentityRepository} from './neon-repository.js';
import {authorizeModules} from './ModuleReleasePolicy.mjs';
export async function guardModules(req,res,keys){
 res.setHeader('Cache-Control','no-store, private');
 try{
  const config=loadConfig(),sessions=new DatabaseSessionIssuer(config.databaseUrl,config.sessionCookieName,config.production),identities=new NeonIdentityRepository(config.databaseUrl);
  const result=await authorizeModules({tokens:cookieValues(req.headers.cookie,config.sessionCookieName),authenticate:t=>sessions.authenticate(t),findUser:id=>identities.findUserById(id),keys,env:process.env});
  if(result.allowed)return true;
  res.statusCode=result.status;res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('X-Content-Type-Options','nosniff');
  res.end(JSON.stringify({code:result.status===401?'SIGN_IN_REQUIRED':'MODULE_COMING_SOON',message:result.status===401?'Sign in with your AVI account.':'This module is taking shape. Visit its dashboard page to see what is planned.'}));
 }catch{
  res.statusCode=503;res.setHeader('Content-Type','application/json; charset=utf-8');
  res.end(JSON.stringify({code:'ACCESS_UNAVAILABLE',message:'We could not check access. Please try again.'}));
 }
 return false;
}
