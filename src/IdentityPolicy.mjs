// Only server-retrieved, live, policy-approved inquiries can award a badge.
export function personaOutcome(payload, expected) {
 const d=payload?.data, a=d?.attributes;
 if (!d || d.id!==expected.inquiryId || a?.['reference-id']!==expected.owner ||
     d.relationships?.['inquiry-template']?.data?.id!==expected.templateId) throw new Error('PERSONA_BINDING_MISMATCH');
 const status=String(a.status||'unknown');
 const checks=(payload.included||[]).filter(v=>v.type?.startsWith('verification/'));
 const linked=new Set((d.relationships?.verifications?.data||[]).map(v=>v.id));
 const passed=type=>checks.some(v=>linked.has(v.id)&&v.type===type&&v.attributes?.status==='passed');
 const document=passed('verification/government-id'),selfie=passed('verification/selfie'),address=passed('verification/document');
 const fields=a.fields||{};const first=fields['name-first']?.value,last=fields['name-last']?.value,birthdate=fields.birthdate?.value;
 const normalized=v=>String(v||'').normalize('NFKC').trim().replace(/\s+/g,' ').toLocaleLowerCase('en');
 const nameMatches=Boolean(first&&last&&normalized(first)===normalized(expected.firstName)&&normalized(last)===normalized(expected.lastName));
 const birthdatePresent=typeof birthdate==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(birthdate);
 return {status,document,selfie,address,nameMatches,birthdatePresent,verified:expected.mode==='production'&&status==='approved'&&document&&selfie&&address&&nameMatches&&birthdatePresent};
}
export function allowedMutation(origin,site,expected) {
 return origin===expected && site!=='cross-site';
}
export function safePortrait(value) {
 return typeof value==='string'&&/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(value)&&value.length<2800000 ? value : null;
}

// A public/uploaded portrait must never become an identity-card portrait.
export function verifiedSelfieUrl(payload, expected) {
 const state=personaOutcome(payload,expected);
 if(!state.verified)return null;
 const linked=new Set((payload.data.relationships?.verifications?.data||[]).map(v=>v.id));
 const selfie=(payload.included||[]).find(v=>linked.has(v.id)&&v.type==='verification/selfie'&&v.attributes?.status==='passed');
 const value=selfie?.attributes?.['center-photo-url'];
 try{const url=new URL(value);return url.protocol==='https:'&&url.hostname==='files.withpersona.com'&&!url.username&&!url.password&&(!url.port||url.port==='443')?url.href:null;}catch{return null;}
}
