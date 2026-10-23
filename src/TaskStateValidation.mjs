export function validateTaskState(data){
 if(!data||!Number.isInteger(data.version)||data.version<0||!Array.isArray(data.items)||data.items.length>500||!Array.isArray(data.logs)||data.logs.length>200)throw Error('Invalid task collection.');
 const ids=new Set();const items=data.items.map(t=>{
 if(!t||!Number.isSafeInteger(t.id)||ids.has(t.id)||typeof t.title!=='string'||!t.title.trim()||t.title.length>150||!['To do','In progress','Done'].includes(t.status)||!['Task','Appointment','Meeting','Poll hold'].includes(t.kind)||!['Personal','Creative','Business'].includes(t.category)||!['Low','Normal','High'].includes(t.priority)||typeof t.notes!=='string'||t.notes.length>2000||typeof t.date!=='string'||!(t.date===''||/^\d{4}-\d{2}-\d{2}$/.test(t.date))||typeof t.time!=='string'||!(t.time===''||/^([01]\d|2[0-3]):[0-5]\d$/.test(t.time)))throw Error('Invalid task fields.');
 if(t.sourceNoteId!==undefined&&(typeof t.sourceNoteId!=='string'||! /^[\w-]{1,80}$/.test(t.sourceNoteId)))throw Error('Invalid linked note.');
 ids.add(t.id);return {id:t.id,title:t.title.trim(),date:t.date,time:t.time,category:t.category,priority:t.priority,status:t.status,kind:t.kind,notes:t.notes,...(t.sourceNoteId?{sourceNoteId:t.sourceNoteId}:{})};
 });
 const logs=data.logs.map(l=>{if(!l||typeof l.text!=='string'||l.text.length>300||typeof l.date!=='string'||l.date.length>100)throw Error('Invalid activity log.');return {text:l.text,date:l.date};});
 return {items,logs,version:data.version};
}
