import React,{useEffect,useRef,useState} from 'react';
import type {State,User} from './types';
import {protocols} from './logic.mjs';
import {useUnsaved} from './interaction';
type API=(path:string,method?:string,data?:unknown)=>Promise<any>;
export default function UserSecurity({user,state,api,refresh,notice,onDelivery,onBusyChange}:{user:User;state:State;api:API;refresh:()=>Promise<unknown>;notice:(text:string)=>void;onDelivery:()=>void;onBusyChange:(busy:boolean)=>void}){
 const [rotateToken,setToken]=useState(false),[nodeIds,setNodes]=useState<string[]>([]),[preview,setPreview]=useState<any>(null),[confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[completed,setCompleted]=useState<any>(null);
 const mounted=useRef(true);useEffect(()=>()=>{mounted.current=false},[]);
 useEffect(()=>{onBusyChange(busy);return()=>onBusyChange(false)},[busy,onBusyChange]);
 useUnsaved(!completed&&(rotateToken||nodeIds.length>0));
 const nodes=state.nodes.filter(n=>user.nodeIds.includes(n.id));
 function reset(){setPreview(null);setConfirmed(false);setError('')}
 async function prepare(){setBusy(true);setError('');try{const p=await api('users/'+user.id+'/security/preview','POST',{rotateToken,nodeIds});if(mounted.current){setPreview(p);setConfirmed(false)}}catch(e){if(mounted.current)setError((e as Error).message)}finally{if(mounted.current)setBusy(false)}}
 async function rotate(){if(!preview||!confirmed)return;setBusy(true);setError('');let written=false;try{
  const r=await api('users/'+user.id+'/security/rotate','POST',{rotateToken:preview.rotateToken,nodeIds:preview.nodes.map((n:any)=>n.id),version:preview.version,confirm:true});written=true;
  if(!mounted.current)return;setCompleted(r);setPreview(null);setConfirmed(false);
  const ok=await refresh();if(ok===false)setError('轮换已完成，但列表刷新失败。请重试读取状态，不要再次轮换。');
  notice(r.rotatedToken?'订阅地址已重置，请重新交付。':'节点认证已轮换，等待 Agent 应用后刷新客户端订阅。');
 }catch(e){if(mounted.current){setError((written?'轮换已完成，读取结果失败：':'')+(e as Error).message);if((e as any).status===409){setPreview(null);setConfirmed(false)}}}finally{if(mounted.current)setBusy(false)}}
 return <div className="user-security">
 <p>为「{user.name}」处理订阅地址或节点认证泄露。两种操作可以分别执行，也可以一起处理。</p>
 {completed?<><div className="alert success" role="status"><strong>轮换已提交</strong><p>{completed.rotatedToken?'旧订阅与用量地址已立即失效，请重新交付当前地址。':'订阅地址保持不变。'}</p>{completed.rotatedNodeIds?.length>0&&<p>已更新 {completed.rotatedNodeIds.length} 个节点认证。新连接使用旧认证的撤销，需等待对应服务器应用完成；应用过程中客户端可能短暂重连。</p>}</div><button type="button" className="primary" disabled={busy} onClick={onDelivery}>查看当前交付地址</button><button type="button" className="text-button" disabled={busy} onClick={()=>refresh()}>重新读取应用状态</button></>:<>
 <section className="security-choice"><label className="checkbox"><input type="checkbox" disabled={busy} checked={rotateToken} onChange={e=>{setToken(e.target.checked);reset()}}/>重置订阅与用量地址</label><p className="hint">旧地址立即失效，使用者必须重新导入新地址。此操作不会撤销已经导入客户端的节点认证。</p></section>
 <section className="security-choice"><h3>轮换节点认证</h3><p className="hint">勾选需要更新 UUID、HY2 密码或 SS2022 客户端密钥的节点。共享的 Reality 私钥、Short ID 与 SS2022 主密钥保持不变，其他订阅认证不变。</p><div className="node-choices">{nodes.map(n=><label className="node-choice" key={n.id}><input type="checkbox" disabled={busy} checked={nodeIds.includes(n.id)} onChange={e=>{setNodes(e.target.checked?[...nodeIds,n.id]:nodeIds.filter(id=>id!==n.id));reset()}}/><div><strong>{n.name}</strong><small>{protocols[n.protocol]} · {state.servers.find(s=>s.id===n.serverId)?.name}</small></div></label>)}</div>{!nodes.length&&<p className="hint">此订阅尚未授权节点。</p>}</section>
 <button type="button" className="secondary" disabled={busy||!rotateToken&&!nodeIds.length} onClick={prepare}>{busy&&!preview?'正在核对…':'预览轮换影响'}</button>
 {preview&&<section className="rotation-preview"><h3>本次影响范围</h3><p>订阅地址：{preview.rotateToken?'立即使旧地址失效，需要重新交付':'保持不变'}</p><p>节点认证：{preview.nodes.length} 个节点，{preview.serverIds.length} 台服务器需要应用。</p><ul>{preview.nodes.map((n:any)=><li key={n.id}>{n.name} · {protocols[n.protocol]}</li>)}</ul><p className="hint">服务端会再次核对当前授权和参数；如果其他页面已修改，将要求重新预览。使用者的累计流量、到期与授权节点保持不变。对应核心重载时，同机其他连接也可能短暂重连。</p><label className="checkbox"><input type="checkbox" disabled={busy} checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/>我已核对影响范围，并会重新交付或通知使用者刷新订阅</label><button type="button" className="destructive" disabled={busy||!confirmed} onClick={rotate}>{busy?'正在执行轮换…':'确认并执行轮换'}</button></section>}
 </>}
 {error&&<div className="alert danger" role="alert">{error}</div>}
 </div>
}
