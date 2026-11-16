import type {IncomingMessage,ServerResponse} from 'node:http';
export function guardModules(req:IncomingMessage,res:ServerResponse,keys:string[]):Promise<boolean>;
