export function validateNote(input) {
 if(!input||!['text','voice','written','folder'].includes(input.kind))throw Error('Choose a valid note type.');
 const title=typeof input.title==='string'?input.title.trim():'';
 if(!title||title.length>150)throw Error('Enter a title of up to 150 characters.');
 const parent=input.parent||null;
 if(parent!==null&&(typeof parent!=='string'||!/^[\w-]{1,80}$/.test(parent)))throw Error('Invalid folder.');
 const src=input.content||{},content={};
 const text=(key)=>{if(src[key]!==undefined){if(typeof src[key]!=='string'||src[key].length>50000)throw Error('Notes support up to 50,000 characters.');content[key]=src[key];}};
 if(input.kind==='text'){if(typeof src.text!=='string')throw Error('Enter note text.');text('text');if(src.textPages!==undefined){if(!Array.isArray(src.textPages)||src.textPages.length<1||src.textPages.length>20||src.textPages.some(p=>typeof p!=='string')||src.textPages.join('\n\n').length>50000)throw Error('Use up to 20 pages and 50,000 characters.');content.textPages=src.textPages;content.text=src.textPages.join('\n\n');}}
 if(input.kind==='voice'){
  const audio=src.audio;
  if(typeof audio!=='string'||audio.length>3100000||!/^data:audio\/(webm|ogg|mp4)(;codecs=[a-zA-Z0-9.,-]+)?;base64,[A-Za-z0-9+/=]+$/.test(audio))throw Error('Record a voice note within the 2.3 MB limit.');
  content.audio=audio;text('transcript');
  if(src.duration!==undefined){if(!Number.isFinite(src.duration)||src.duration<0||src.duration>605)throw Error('Recording duration is invalid.');content.duration=src.duration;}
  for(const [key,max,length] of [['peaks',1,500],['bookmarks',605,100]])if(src[key]!==undefined){if(!Array.isArray(src[key])||src[key].length>length||src[key].some(v=>!Number.isFinite(v)||v<0||v>max))throw Error('Invalid recording markers.');content[key]=src[key];}
 }
 if(input.kind==='written'){
  const pages=src.pages!==undefined?src.pages:[src.strokes];
  if(!Array.isArray(pages)||pages.length<1||pages.length>20)throw Error('Use up to 20 notebook pages.');
  let points=0,count=0;
  const clean=pages.map(strokes=>{
   if(!Array.isArray(strokes))throw Error('Invalid notebook page.');count+=strokes.length;
   return strokes.map(s=>{
    if(!s||!/^#[0-9a-f]{6}$/i.test(s.color)||!Number.isFinite(s.width)||s.width<1||s.width>20||!Array.isArray(s.points)||!s.points.length)throw Error('Invalid drawing.');
    points+=s.points.length;
    for(const p of s.points)if(!Array.isArray(p)||p.length!==3||p.some(v=>!Number.isFinite(v))||p[0]<0||p[0]>1000||p[1]<0||p[1]>600||p[2]<0||p[2]>1)throw Error('Invalid drawing point.');
    if(s.tool!==undefined&&!['pen','highlighter'].includes(s.tool))throw Error('Invalid pen tool.');
    return {color:s.color,width:s.width,points:s.points,...(s.tool?{tool:s.tool}:{})};
   });
  });
  if(points>50000||count>2000)throw Error('This notebook is full. Start another note.');
  if(src.pages!==undefined)content.pages=clean;else content.strokes=clean[0];
  if(src.thumbnail!==undefined){if(typeof src.thumbnail!=='string'||src.thumbnail.length>12000||!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(src.thumbnail))throw Error('Invalid page thumbnail.');content.thumbnail=src.thumbnail;}
 }
 if(input.kind==='text'&&src.checklist!==undefined){if(!Array.isArray(src.checklist)||src.checklist.length>100)throw Error('Use up to 100 checklist items.');const ids=new Set();content.checklist=src.checklist.map(i=>{if(!i||typeof i.id!=='string'||! /^[\w-]{1,80}$/.test(i.id)||ids.has(i.id)||typeof i.text!=='string'||i.text.length>300||typeof i.done!=='boolean')throw Error('Invalid checklist item.');ids.add(i.id);return {id:i.id,text:i.text,done:i.done};});}
 if(input.kind!=='folder'&&src.links!==undefined){if(!Array.isArray(src.links)||src.links.length>50)throw Error('Use up to 50 connections.');content.links=src.links.map(l=>{if(!l||!['day','task','event','meeting'].includes(l.kind)||typeof l.id!=='string'||! /^[\w-]{1,80}$/.test(l.id)||typeof l.title!=='string'||l.title.length>150||(l.date!==undefined&&!/^\d{4}-\d{2}-\d{2}$/.test(l.date)))throw Error('Invalid note connection.');return {kind:l.kind,id:l.id,title:l.title,...(l.date?{date:l.date}:{})};});}
 if(input.kind!=='folder'){
  for(const [key,values] of [['paper',['plain','lined','grid','dots']],['colour',['cream','sage','rose','sky']]])if(src[key]!==undefined){if(!values.includes(src[key]))throw Error('Invalid notebook appearance.');content[key]=src[key];}
  for(const key of ['pinned','handwriting'])if(src[key]!==undefined){if(typeof src[key]!=='boolean')throw Error('Invalid note option.');content[key]=src[key];}
 }
 return {title,kind:input.kind,parent,content};
}
