import type {State,Node} from './types';
export const realityCandidates:{name:string;host:string}[];
export function transports(n:Partial<Node>):string[];
export function suggestedPort(state:State,serverId:string,protocol:string,id?:string,network?:string):number;
export function protocolDefaults(protocol:string,state:State,serverId:string):Partial<Node>;
export function nodeWarnings(d:Node,state:State):string[];
