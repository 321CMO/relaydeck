import type {Server,Node,User} from './types';
export const protocols:Record<string,string>;
export function online(server:Server,now?:number):boolean;
export function serverStatus(server:Server,now?:number):{text:string;tone:string};
export function nodeStatus(node:Node,servers:Server[]):{text:string;tone:string};
export function userStatus(user:User,now?:number):{text:string;tone:string};
export function timeText(value?:string):string;
