export function personaOutcome(payload:unknown,expected:{owner:string;inquiryId:string;templateId:string;mode:string;firstName:string;lastName:string}):{status:string;document:boolean;selfie:boolean;address:boolean;nameMatches:boolean;birthdatePresent:boolean;verified:boolean};
export function allowedMutation(origin:unknown,site:string,expected:string):boolean;
export function safePortrait(value:unknown):string|null;

export function verifiedSelfieUrl(payload:unknown,expected:Parameters<typeof personaOutcome>[1]):string|null;
