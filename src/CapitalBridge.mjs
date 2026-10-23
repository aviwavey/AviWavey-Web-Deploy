import {createHmac,randomUUID,createHash} from 'node:crypto';
const routes=[
 ['GET',/^\/api\/v1\/auth\/me$/],['GET',/^\/api\/v1\/dashboard\/(metrics|platform-status)$/],
 ['GET',/^\/api\/v1\/payments(?:\/[A-Za-z0-9_-]+)?$/],['POST',/^\/api\/v1\/payments\/initiate$/],['POST',/^\/api\/v1\/payments\/[A-Za-z0-9_-]+\/(verify|refund|receipt\/send)$/],
 ['GET',/^\/api\/v1\/escrow(?:\/[A-Za-z0-9_-]+)?$/],['POST',/^\/api\/v1\/escrow$/],['POST',/^\/api\/v1\/escrow\/[A-Za-z0-9_-]+\/(fund|release|dispute|refund|mark-in-transit|mark-in-inspection|request-release|mediate\/(accept|reject|propose))$/],
 ['GET',/^\/api\/v1\/payouts(?:\/[A-Za-z0-9_-]+)?$/],['POST',/^\/api\/v1\/payouts(?:\/[A-Za-z0-9_-]+\/(cancel|hold|release-hold))?$/],
 ['GET',/^\/api\/v1\/users\/(my-customers|lookup|[A-Za-z0-9_-]+\/public)$/],
 ['GET',/^\/api\/v1\/commissions(?:\/[A-Za-z0-9_-]+)?$/],
 ['GET',/^\/api\/v1\/bank-accounts(?:\/banks)?$/],['POST',/^\/api\/v1\/bank-accounts(?:\/resolve)?$/],['PATCH',/^\/api\/v1\/bank-accounts$/],['DELETE',/^\/api\/v1\/bank-accounts$/],
 ['GET',/^\/api\/v1\/virtual-accounts\/invoices(?:\/[A-Za-z0-9_-]+)?$/],['POST',/^\/api\/v1\/virtual-accounts\/invoices(?:\/[A-Za-z0-9_-]+\/(send|cancel|mark-paid))?$/],['PATCH',/^\/api\/v1\/virtual-accounts\/invoices\/[A-Za-z0-9_-]+$/],['POST',/^\/api\/v1\/exports\/send$/]
];
export const allowedRoute=(method,path)=>!/(?:admin|process-pending|disputed|failed)$/.test(path)&&routes.some(([m,r])=>m===method&&r.test(path));
const json=(status,data)=>Response.json(data,{status,headers:{'cache-control':'no-store, private','x-content-type-options':'nosniff'}});
export async function capitalBridge(request,{authenticate,serviceUrl,secret,fetcher=fetch}){
 const user=await authenticate();if(!user?.id)return json(401,{detail:'Sign in to open Payment Portal.'});
 const url=new URL(request.url),path=url.pathname.replace(/^\/api\/capital/,'');
 let service;try{service=new URL(serviceUrl);if(service.protocol!=='https:'||service.username||service.password||service.search||service.hash)throw Error();}catch{service=null;}
 const configured=Boolean(service&&secret&&secret.length>=32);
 if(path==='/status'&&request.method==='GET')return json(200,{ready:configured,message:configured?'Payment service configured.':'Payment service connection is pending. Your dashboard is ready; live accounts and transactions are not connected yet.'});
 if(!allowedRoute(request.method,path))return json(404,{detail:'This payment operation is not available in the dashboard.'});
 if(!configured)return json(503,{detail:'Payment service connection is pending.'});
 if(request.method!=='GET'&&(request.headers.get('origin')!==url.origin||request.headers.get('sec-fetch-site')==='cross-site'))return json(403,{detail:'Open this action from your signed-in dashboard.'});
 const body=['GET','HEAD'].includes(request.method)?null:Buffer.from(await request.arrayBuffer());
 if(body&&body.length>4*1024*1024)return json(413,{detail:'This request is too large.'});
 const timestamp=String(Math.floor(Date.now()/1000)),nonce=randomUUID();
 const exchange=JSON.stringify({subject:user.id,product:'avi-capital',timestamp:Number(timestamp),nonce});
 const signature=createHmac('sha256',secret).update(exchange).digest('hex');
 try{
 const session=await fetcher(new URL('/integration/session',service),{method:'POST',headers:{'content-type':'application/json','x-capital-signature':signature},body:exchange,redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!session.ok)return json(session.status===403||session.status===409?409:503,{detail:session.status===403||session.status===409?'Your Capital account is not linked to the payment service yet.':'The payment connection is temporarily unavailable.'});
 const token=await session.json();if(typeof token.access_token!=='string')throw Error();
 const headers=new Headers({'authorization':'Bearer '+token.access_token,'x-payseq-csrf':'1'});
 if(request.headers.has('content-type'))headers.set('content-type',request.headers.get('content-type'));
 if(request.headers.has('idempotency-key'))headers.set('idempotency-key',request.headers.get('idempotency-key'));
 const target=new URL(path,service);target.search=url.search;
 const upstream=await fetcher(target,{method:request.method,headers,body,redirect:'error',signal:AbortSignal.timeout(30000)});
 const data=await upstream.arrayBuffer();
 return new Response(data.byteLength?data:null,{status:upstream.status,headers:{'content-type':upstream.headers.get('content-type')||'application/json','cache-control':'no-store, private','x-content-type-options':'nosniff'}});
 }catch{return json(503,{detail:'The payment service could not be reached. No automatic retry was made; check the transaction status before trying a payment again.'});}
}
