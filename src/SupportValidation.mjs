export const categories=['general','account','payments','technical','feedback'];
export function validateTicket(input){
 if(!input||typeof input!=='object')throw Error('Enter your support request.');
 const subject=String(input.subject||'').trim(),description=String(input.description||'').trim(),category=String(input.category||'general');
 if(subject.length<3||subject.length>160)throw Error('Use a subject between 3 and 160 characters.');
 if(description.length<10||description.length>10000)throw Error('Describe the issue in 10 to 10,000 characters.');
 if(!categories.includes(category))throw Error('Choose a support category.');
 const reference=String(input.reference||'').trim();if(reference.length>150)throw Error('The reference is too long.');
 const attachment=input.attachment?validateAttachment(input.attachment):null;
 return {subject,description,category,reference,attachment};
}
export function validateAttachment(file){
 if(!file||typeof file.name!=='string'||file.name.length>160||typeof file.data!=='string')throw Error('Invalid attachment.');
 const match=/^data:(image\/png|image\/jpeg|application\/pdf);base64,([A-Za-z0-9+/=]+)$/.exec(file.data);if(!match)throw Error('Use a PNG, JPEG or PDF attachment.');
 const bytes=Buffer.from(match[2],'base64');if(!bytes.length||bytes.length>2*1024*1024)throw Error('Keep the attachment below 2 MB.');
 const valid=match[1]==='application/pdf'?bytes.subarray(0,5).toString()==='%PDF-':match[1]==='image/png'?bytes.subarray(0,8).toString('hex')==='89504e470d0a1a0a':bytes[0]===255&&bytes[1]===216&&bytes[2]===255;
 if(!valid)throw Error('The attachment does not match its file type.');
 return {name:file.name.replace(/[\r\n\/\\]/g,'_'),type:match[1],data:match[2]};
}
export function validateReply(input){const content=String(input?.content||'').trim();if(content.length<1||content.length>10000)throw Error('Write a reply of up to 10,000 characters.');return content;}
