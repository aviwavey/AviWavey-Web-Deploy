export function validateNote(input) {
 const kinds=['text','voice','written','folder'];
 if(!input||!kinds.includes(input.kind))throw Error('Choose a valid note type.');
 const title=typeof input.title==='string'?input.title.trim():'';
 if(!title||title.length>150)throw Error('Enter a title of up to 150 characters.');
 const parent=input.parent||null;
 if(parent!==null&&(typeof parent!=='string'||!/^[\w-]{1,80}$/.test(parent)))throw Error('Invalid folder.');
 let content={};
 if(input.kind==='text'){if(typeof input.content?.text!=='string'||input.content.text.length>50000)throw Error('Text notes support up to 50,000 characters.');content={text:input.content.text};}
 if(input.kind==='voice'){const audio=input.content?.audio;if(typeof audio!=='string'||audio.length>1400000||!/^data:audio\/(webm|ogg|mp4)(;codecs=[a-zA-Z0-9.,-]+)?;base64,[A-Za-z0-9+/=]+$/.test(audio))throw Error('Record a voice note of up to 60 seconds.');content={audio};}
 if(input.kind==='written'){const strokes=input.content?.strokes;if(!Array.isArray(strokes)||strokes.length>2000)throw Error('This drawing is too large.');let points=0;for(const s of strokes){if(!/^#[0-9a-f]{6}$/i.test(s.color)||!Number.isFinite(s.width)||s.width<1||s.width>20||!Array.isArray(s.points))throw Error('Invalid drawing.');points+=s.points.length;for(const p of s.points){if(!Array.isArray(p)||p.length!==3||p.some(v=>!Number.isFinite(v))||p[0]<0||p[0]>1000||p[1]<0||p[1]>600||p[2]<0||p[2]>1)throw Error('Invalid drawing point.');}}if(points>50000)throw Error('This drawing is full. Start another note.');content={strokes};}
 return {title,kind:input.kind,parent,content};
}
