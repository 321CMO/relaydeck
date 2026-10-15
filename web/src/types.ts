export type Server={id:string;name:string;address:string;privateIp:string;region:string;enrolled:boolean;lastSeen:string;desired:number;applied:number;coreVersion:string;error?:string};
export type Node={id:string;name:string;serverId:string;protocol:string;address:string;port:number;enabled:boolean;sni:string;target:string;publicKey:string;shortId:string;tlsMode:string;certificate?:string;key?:string;hopStart:number;hopEnd:number;hopInterval:number;exitId:string;requiredRevision:number};
export type User={id:string;name:string;enabled:boolean;limit:number;used:number;upload?:number;download?:number;usageSince?:string;usageUpdated?:string;expires:string;nodeIds:string[]};
export type Rule={id:string;scope:string;kind:string;value:string;action:string;nodeId:string};
export type Task={id:string;serverId:string;revision:number;status:string;summary:string;error?:string;created:string};
export type Settings={https:{adminPort?:number;domain:string;subscriptionDomain:string;publishedDomain?:string;mode:string;email:string;cloudflareToken?:string;certificate?:string;key?:string;status:string;expires:string};telegram:{enabled:boolean;token?:string;chatId:string;daily:boolean;hour:number;status:string};routingPreset:string;timezone:string};
export type State={servers:Server[];nodes:Node[];users:User[];routes:Rule[];tasks:Task[];settings:Settings;notifications:{id:string;kind:string;text:string;status:string}[]};
export type Session={authenticated:boolean;setupRequired:boolean;csrf:string;username:string;version:string};
