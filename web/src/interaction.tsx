import {useEffect,useRef} from 'react';

const guards=new Map<symbol,()=>boolean>();
let navigationApproved=false;
export function proceedNavigation(){navigationApproved=true}
export function confirmLeave(except?:symbol){return ![...guards.entries()].some(([id,fn])=>id!==except&&fn())||window.confirm('存在未保存的修改。确定放弃更改？')}
export function useUnsaved(dirty:boolean){
 const flag=useRef(dirty);flag.current=dirty;const id=useRef(Symbol());
 useEffect(()=>{guards.set(id.current,()=>flag.current);const unload=(e:BeforeUnloadEvent)=>{if(flag.current&&!navigationApproved){e.preventDefault();e.returnValue=''}};window.addEventListener('beforeunload',unload);return()=>{guards.delete(id.current);window.removeEventListener('beforeunload',unload)}},[]);
 return {confirmOthers:()=>confirmLeave(id.current)};
}

// Keep only operation hashes and random keys in session storage, never form contents.
export async function creationKey(path:string,data:unknown){
 if(!/^(servers|nodes|users|outbounds|routes)$/.test(path))return undefined;
 const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(path+'\0'+JSON.stringify(data)));
 const name='relaydeck-operation-'+Array.from(new Uint8Array(bytes)).map(x=>x.toString(16).padStart(2,'0')).join('');
 let value;try{value=JSON.parse(sessionStorage.getItem(name)||'null')}catch{}
 if(!value||Date.now()-value.time>86400000){value={key:crypto.randomUUID(),time:Date.now()};sessionStorage.setItem(name,JSON.stringify(value))}
 return {key:value.key as string,clear:()=>sessionStorage.removeItem(name)};
}
