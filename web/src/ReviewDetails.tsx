import type {State,Server,Node,User} from './types';
import {timeText} from './logic.mjs';

export function TaskDetails({state,serverId,busy,retry}:{state:State;serverId?:string;busy:boolean;retry:(id:string)=>void}){
 const tasks=state.tasks.filter(t=>!serverId||t.serverId===serverId).slice().reverse();
 return <><p className="hint">版本表示 Agent 配置回执，实际 TCP/UDP 连通需另行检测。应用失败时请结合生效版本核对上一份配置。</p>{state.servers.filter(s=>!serverId||s.id===serverId).map(s=><section className="diagnostic-row" key={s.id}><h3>{s.name}</h3><p>生效 / 目标：{s.applied} / {s.desired} · {s.coreVersion||'尚无核心版本'}</p>{s.error&&<div className="alert danger"><strong>Agent 最近错误</strong><pre>{s.error}</pre></div>}</section>)}{tasks.length?tasks.map(t=><section className="diagnostic-row" key={t.id}><h3>{t.summary}</h3><p>{state.servers.find(s=>s.id===t.serverId)?.name} · 版本 {t.revision} · {timeText(t.created)} · {({applied:'已应用',pending:'等待应用',failed:'应用失败',superseded:'已被更新替代'} as Record<string,string>)[t.status]||t.status}</p>{t.error&&<div className="alert danger"><pre>{t.error}</pre></div>}{t.status==='failed'&&<button type="button" className="secondary" disabled={busy} onClick={()=>retry(t.id)}>重试此服务器配置</button>}</section>):<p>暂无配置任务。</p>}</>
}

export function DeletionImpact({state,resource,id,onEdit,onRouting}:{state:State;resource:string;id:string;onEdit:(resource:string,obj:Server|Node|User)=>void;onRouting:()=>void}){
 const nodes=state.nodes.filter(n=>resource==='nodes'?n.id===id:resource==='servers'?(n.serverId===id||n.exitId===id):resource==='outbounds'?n.outboundId===id:false);
 const users=state.users.filter(u=>resource==='users'?u.id===id:u.nodeIds.some(n=>nodes.some(v=>v.id===n)));
 const routes=state.routes.filter(r=>resource==='nodes'?(r.nodeId===id||r.nodeIds?.includes(id)):resource==='users'?r.userIds?.includes(id):resource==='outbounds'?r.outboundId===id:resource==='servers'?r.serverId===id:false);
 const outbounds=state.outbounds.filter(o=>resource==='servers'?o.serverId===id:resource==='outbounds'?o.detourId===id:false);
 const policies=state.routingPolicies.filter(p=>resource==='outbounds'&&p.defaultOutboundId===id);
 return <><h3>影响预览</h3><p>删除的是面板记录，服务器上的卸载操作需另外执行。删除节点会撤销该节点在所有订阅中的授权；操作执行后需要 Agent 应用。</p><p>相关节点 {nodes.length} · 订阅 {users.length} · 路由 {routes.length} · 出站/默认出口 {outbounds.length+policies.length}</p>{nodes.map(n=><p key={n.id}>节点：<button type="button" className="text-button" onClick={()=>onEdit('nodes',n)}>{n.name}</button></p>)}{users.map(u=><p key={u.id}>订阅：<button type="button" className="text-button" onClick={()=>onEdit('users',u)}>{u.name}</button>{resource==='nodes'&&'（将失去此节点授权）'}</p>)}{(routes.length+outbounds.length+policies.length>0)&&<><p>存在路由或出站引用，请先在分流页调整依赖。服务端会再次检查当前引用。</p><button type="button" className="secondary" onClick={onRouting}>前往分流调整依赖</button>{routes.map(r=><p key={r.id}>路由：{r.name||r.value}</p>)}{outbounds.map(o=><p key={o.id}>出站：{o.name}</p>)}</>}</>
}
