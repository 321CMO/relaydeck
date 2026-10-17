import React,{useEffect,useRef,useState} from 'react';
import type {State} from './types';
import {protocols} from './logic.mjs';
import {nodeWarnings,protocolDefaults,realityCandidates,suggestedPort,transports} from './node-config.mjs';
import {ConfigField as Field,ProtocolFields} from './ProtocolFields';

type Props={onBusyChange:(busy:boolean)=>void;data:any;state:State;patch:(value:any)=>void;api:(p:string,m?:string,d?:unknown)=>Promise<any>};
export default function NodeFields({data:d,state,patch,api,onBusyChange}:Props){
 const [tab,setTab]=useState('basic'),[working,setWorking]=useState(false),[error,setError]=useState('');
 const [revealed,setRevealed]=useState<Record<string,string>|null>(null),[check,setCheck]=useState<any>(null);
 const context=JSON.stringify([d.id,d.serverId,d.protocol,d.method,d.target,d.sni]);
 const current=useRef(context),mounted=useRef(true),generation=useRef(0),checkSequence=useRef(0);current.current=context;
 useEffect(()=>{onBusyChange(working);return()=>onBusyChange(false)},[working,onBusyChange]);
 useEffect(()=>()=>{mounted.current=false;generation.current++},[]);
 useEffect(()=>{checkSequence.current++;setCheck(null);setRevealed(null)},[context]);
 useEffect(()=>{if(!revealed)return;const t=setTimeout(()=>setRevealed(null),30000);return()=>clearTimeout(t)},[revealed]);
 const change=(key:string,value:any)=>{
  if(key==='method')patch({method:value,serverKey:'',rotateCredentials:false});
  else if(key==='obfs')patch({obfs:value,obfsPassword:'',hasObfsPassword:false});
  else patch({[key]:value});
 };
 async function keys(reveal=false,type=d.protocol){
  const snapshot=context,sequence=++generation.current;setWorking(true);setError('');
  try{
   const v=await api(reveal?'nodes/'+d.id+'/secrets':'nodes/generate-keys',reveal?'GET':'POST',reveal?undefined:{type,method:d.method||'2022-blake3-aes-128-gcm'});
   if(!mounted.current||sequence!==generation.current||snapshot!==current.current)return;
   if(reveal)setRevealed(v);
   else if(type==='short-id'){
    const ids=(d.shortIds?.length?d.shortIds:[d.shortId]).filter(Boolean);
    if(ids.length>=32)throw new Error('Short ID 最多 32 个，请先移除不再使用的值');
    const next=[...ids,v.shortId];patch({shortIds:next,shortId:next[0]});
   }else patch({...v,...(d.id&&type!=='hy2'?{rotateCredentials:false}:{})});
  }catch(e){if(mounted.current&&snapshot===current.current)setError((e as Error).message)}
  finally{if(mounted.current&&sequence===generation.current)setWorking(false)}
 }
 async function checkTarget(){
  const snapshot=context,sequence=++checkSequence.current;setError('');setCheck({status:'pending'});
  try{
   const job=await api('nodes/checks','POST',{serverId:d.serverId,target:d.target,sni:d.sni});
   for(let i=0;i<96;i++){
    if(!mounted.current||snapshot!==current.current||sequence!==checkSequence.current)return;
    const result=await api('nodes/checks/'+job.id);
    if(!mounted.current||snapshot!==current.current||sequence!==checkSequence.current)return;
    setCheck(result);if(result.status!=='pending')return;
    await new Promise(resolve=>setTimeout(resolve,1000));
   }
   if(mounted.current&&snapshot===current.current&&sequence===checkSequence.current)setCheck({status:'timeout'});
  }catch(e){if(mounted.current&&snapshot===current.current&&sequence===checkSequence.current){setCheck(null);setError((e as Error).message)}}
 }
 const exitValue=d.exitId?'via:'+d.exitId:d.outboundId||'';
 const server=state.servers.find(s=>s.id===d.serverId),exit=state.servers.find(s=>s.id===d.exitId);
 const warnings=nodeWarnings(d,state),affected=state.users.filter(u=>u.nodeIds.includes(d.id));
 const preset=realityCandidates.find(c=>d.sni===c.host&&d.target===c.host+':443')?.host||'';
 const keyBytes=(d.method||'2022-blake3-aes-128-gcm').includes('128')?16:32;
 const checkResult=check&&<div className={'alert '+(check.status==='passed'?'success':check.status==='pending'?'':'warning')} role="status">
  {check.status==='pending'?'等待入口 Agent 检测，通常需 15–45 秒。':check.status==='timeout'?'检测超时：检查服务器管理连接和 Agent 版本后重试。':check.result?.message}
  {check.result?.latencyMs!=null&&<small> TCP / TLS 耗时 {check.result.latencyMs} ms · ALPN {check.result.alpn||'未协商'} · {new Date(check.result.checked).toLocaleTimeString()}</small>}
 </div>;
 return <div className="node-config" onInvalidCapture={e=>{
  e.preventDefault();const input=e.target as HTMLInputElement;const area=input.closest<HTMLElement>('[data-node-tab]');
  if(area?.dataset.nodeTab)setTab(area.dataset.nodeTab);setError('请检查'+(input.labels?.[0]?.textContent||'必填配置'));requestAnimationFrame(()=>input.focus());
 }}>
 <div className="routing-tabs" role="tablist" aria-label="入站配置">{[['basic','基本'],['security','协议与安全'],['connection','连接与出口'],['review','检查与确认']].map(([id,name])=><button key={id} type="button" role="tab" aria-selected={tab===id} onClick={()=>{setTab(id);setError('')}}>{name}</button>)}</div>
 <div data-node-tab="basic" hidden={tab!=='basic'}>
  <Field label="节点名称"><input autoFocus required maxLength={100} value={d.name} onChange={e=>change('name',e.target.value)} placeholder="例如：香港 · Reality"/></Field>
  <Field label="入站 Tag" help="留空使用稳定节点 ID。路由通过节点 ID 关联，修改 Tag 后自动更新原生引用。"><input value={d.tag||''} maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]*" placeholder={d.id||'自动分配'} onChange={e=>change('tag',e.target.value)}/></Field>
  <div className="field-grid">
   <Field label="服务器"><select disabled={!!d.id||working} value={d.serverId} onChange={e=>{const s=state.servers.find(s=>s.id===e.target.value);patch({serverId:s?.id||'',address:s?.address||'',port:suggestedPort(state,s?.id||'',d.protocol),exitId:'',outboundId:''})}}>{state.servers.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></Field>
   <Field label="协议"><select disabled={!!d.id||working} value={d.protocol} onChange={e=>patch(protocolDefaults(e.target.value,state,d.serverId))}>{Object.entries(protocols).map(([id,name])=><option key={id} value={id}>{name}</option>)}</select></Field>
  </div>
  <div className="field-grid">
   <Field label="监听地址" help="留空监听 ::；指定回环地址后公网客户端将无法直接连接。"><input value={d.listen||''} onChange={e=>change('listen',e.target.value)} placeholder="::"/></Field>
   <Field label="端口" help="VPS 上核心实际监听的端口。推荐值避开面板内已知冲突，系统中的其他程序需另行检查。"><input type="number" required min={1} max={65535} value={d.port} onChange={e=>change('port',Number(e.target.value))}/></Field>
  </div>
  <button type="button" className="text-button port-suggest" onClick={()=>change('port',suggestedPort(state,d.serverId,d.protocol,d.id,d.network))}>使用推荐端口 · {suggestedPort(state,d.serverId,d.protocol,d.id,d.network)}</button>
  <div className="field-grid">
   <Field label="连接地址" help="写入订阅的对外域名或 IP。"><input required value={d.address} onChange={e=>change('address',e.target.value)}/></Field>
   <Field label="对外端口" help="0 跟随监听端口；HY2 端口跳跃时不支持额外端口映射。"><input type="number" min={0} max={65535} value={d.publicPort||0} onChange={e=>change('publicPort',Number(e.target.value))}/></Field>
  </div>
 </div>
 <div data-node-tab="security" hidden={tab!=='security'}>
  <ProtocolFields data={d} type={d.protocol} change={change} working={working} generateSecret={()=>keys(false,'hy2')}/>
  {d.protocol==='reality'&&<>
   <Field label="Reality 候选站点" help="仅提供候选，不保证在你的 VPS 可用。应用后会同时填入 SNI 与握手目标；也可手动输入。"><select value={preset} onChange={e=>{patch({sni:e.target.value,target:e.target.value?e.target.value+':443':''})}}><option value="">自定义目标</option>{realityCandidates.map(c=><option key={c.host} value={c.host}>{c.name} · {c.host}</option>)}</select></Field>
   <Field label="Reality SNI" help="必须在目标站点证书覆盖范围内，无需解析到你的 VPS。"><input required value={d.sni} onChange={e=>change('sni',e.target.value.trim())}/></Field>
   <Field label="目标站点与端口" help="入口 VPS 必须能访问该目标。推荐 TLS 1.3、X25519 与 HTTP/2；检测不检查网页重定向。"><input required value={d.target} onChange={e=>change('target',e.target.value.trim())}/></Field>
   <button type="button" className="secondary" disabled={check?.status==='pending'||!d.target||!d.sni} onClick={checkTarget}>从入口 VPS 检测目标</button>
   {checkResult}<p className="hint">从「{server?.name||'未选择服务器'}」检测；更改服务器、目标或 SNI 后需重新检测。预设不会自动轮换。</p>
   <div className="button-row"><button type="button" className="secondary" disabled={working} onClick={()=>keys()}>生成 X25519 密钥与 Short ID</button>{d.id&&<button type="button" className="text-button" disabled={working} onClick={()=>keys(true)}>读取已保存密钥</button>}</div>
   <Field label="Reality 私钥" help={d.hasPrivateKey?'已保存，留空沿用。更改后客户端必须刷新订阅。':'留空自动生成。X25519 私钥为 32 字节、43 位 Base64URL 字符，无需自己编写。'}><input type="password" disabled={working} autoComplete="new-password" value={d.privateKey||''} onChange={e=>change('privateKey',e.target.value)}/></Field>
   <Field label="Reality 公钥" help="由私钥计算，订阅自动携带；不要填写成私钥。"><input readOnly value={d.publicKey||''} placeholder="保存或生成后自动计算"/></Field>
   <Field label="Short ID 列表" help="每行一个 2–16 位偶数长度十六进制值，推荐随机 16 位，最多 32 个且不能重复。第一个用于新订阅；保留旧值可兼容已有客户端。留空沿用，首次自动生成。"><textarea disabled={working} value={(d.shortIds?.length?d.shortIds:[d.shortId||'']).join('\n')} onChange={e=>patch({shortIds:e.target.value.split('\n').map(v=>v.trim()),shortId:e.target.value.split('\n')[0].trim()})}/></Field>
   <button type="button" className="text-button" disabled={working} onClick={()=>keys(false,'short-id')}>追加随机 Short ID（保留旧值）</button>
   <Field label="最大时间差" help="留空不检查。启用前请保证服务器与客户端时间同步；30s 表示允许 30 秒偏差。"><input value={d.maxTimeDifference||''} onChange={e=>change('maxTimeDifference',e.target.value)} placeholder="留空不检查，例如 30s"/></Field>
   {d.id&&d.privateKey&&<label className="checkbox"><input type="checkbox" required checked={!!d.rotateCredentials} onChange={e=>change('rotateCredentials',e.target.checked)}/>确认更改 Reality 私钥，通知 {affected.length} 个订阅刷新客户端</label>}
  </>}
  {d.protocol==='hy2'&&<>
   <Field label="证书域名" help="需为你持有的域名；客户端会校验证书，不建议跳过验证。"><input required value={d.sni} onChange={e=>change('sni',e.target.value)} placeholder="hy.example.com"/></Field>
   <Field label="证书方式"><select value={d.tlsMode} onChange={e=>change('tlsMode',e.target.value)}><option value="auto">核心自动申请与续期</option><option value="import">导入证书与私钥</option></select></Field>
   <p className="hint">自动申请需要域名指向本机且 TCP 80 可用。中心 Caddy 共机时请导入有效证书；导入证书需自行续期。</p>
   {d.tlsMode==='import'&&<><Field label="PEM 证书链"><textarea required={!d.id} value={d.certificate||''} placeholder={d.id?'留空沿用已保存证书':''} onChange={e=>change('certificate',e.target.value)}/></Field><Field label="PEM 私钥"><textarea required={!d.id} value={d.key||''} onChange={e=>change('key',e.target.value)}/></Field></>}
   <Field label="HTTP/3 伪装目标" help="HTTP/HTTPS URL；留空返回核心默认 404，Salamander 与普通 HTTP/3 伪装不是同一配置。"><input value={d.masquerade||''} onChange={e=>change('masquerade',e.target.value)} placeholder="https://example.com"/></Field>
  </>}
  {d.protocol==='ss2022'&&<>
   <div className="button-row"><button type="button" className="secondary" disabled={working} onClick={()=>keys()}>生成服务端主密钥</button>{d.id&&<button type="button" className="text-button" disabled={working} onClick={()=>keys(true)}>读取已保存密钥</button>}</div>
   <Field label="服务端主密钥" help={(d.hasServerKey?'已保存，留空沿用。':'留空自动生成。')+`当前算法需要 ${keyBytes} 字节随机密钥（Base64 编码后 ${keyBytes===16?24:44} 位），不是普通密码。更换算法时重新生成。`}><input type="password" disabled={working} autoComplete="new-password" value={d.serverKey||''} onChange={e=>change('serverKey',e.target.value)}/></Field>
   {d.id&&<label className="checkbox"><input type="checkbox" checked={!!d.rotateCredentials} onChange={e=>change('rotateCredentials',e.target.checked)}/>确认更改算法/主密钥时轮换此节点的所有客户端密钥</label>}
   {d.id&&<p className="hint">轮换影响 {affected.length} 个订阅：{affected.map(u=>u.name).join('、')||'暂无授权'}。生效后客户端必须刷新订阅。</p>}
  </>}
  {revealed&&<div className="saved-secrets"><p>已保存参数 · 仅本次查看，30 秒后自动隐藏，不会填入编辑草稿。</p>{Object.entries(revealed).filter(([k,v])=>v&&(d.protocol==='reality'?k==='privateKey':d.protocol==='ss2022'?k==='serverKey':k==='obfsPassword')).map(([k,v])=><Field key={k} label="已保存密钥（只读）"><input readOnly value={v}/></Field>)}<button type="button" className="text-button" onClick={()=>setRevealed(null)}>立即隐藏</button></div>}
 </div>
 <div data-node-tab="connection" hidden={tab!=='connection'}>
  {d.protocol==='hy2'&&<><h3>UDP 端口跳跃</h3><label className="checkbox"><input type="checkbox" checked={d.hopStart>0} onChange={e=>patch({hopStart:e.target.checked?20000:0,hopEnd:e.target.checked?20010:0})}/>启用连续端口跳跃</label>{d.hopStart>0&&<><div className="field-grid"><Field label="起始端口"><input type="number" min={1} max={65535} value={d.hopStart} onChange={e=>change('hopStart',Number(e.target.value))}/></Field><Field label="结束端口"><input type="number" min={d.hopStart} max={Math.min(65535,d.hopStart+4095)} value={d.hopEnd} onChange={e=>change('hopEnd',Number(e.target.value))}/></Field></div><Field label="跳跃间隔（秒）"><input type="number" min={5} max={3600} value={d.hopInterval} onChange={e=>change('hopInterval',Number(e.target.value))}/></Field><p className="hint">云安全组需放行整个 UDP 范围，本机转发由 Agent 管理。面板最多支持 4096 个连续端口。Clash 交付跳跃参数；Shadowrocket 当前使用单端口。</p></>}</>}
  <Field label="流量出口" help="设置未命中自定义路由时的出口。内网落地不可达时不回退直连。"><select value={exitValue} onChange={e=>{const v=e.target.value;patch({exitId:v.startsWith('via:')?v.slice(4):'',outboundId:v.startsWith('via:')?'':v})}}><option value="">继承服务器默认出口</option><option value="direct">明确直连 · direct</option><optgroup label="自定义出站">{(state.outbounds||[]).filter(o=>o.serverId===d.serverId).map(o=><option key={o.id} value={o.id} disabled={!o.enabled}>{o.name} · {o.tag}{o.enabled?'':'（已停用）'}</option>)}</optgroup><optgroup label="受管内网落地">{state.servers.filter(s=>s.id!==d.serverId).map(s=><option key={s.id} value={'via:'+s.id}>{s.name} · {s.privateIp||'尚未设置内网 IP'}</option>)}</optgroup></select></Field>
 </div>
 <div data-node-tab="review" hidden={tab!=='review'}>
  <h3>保存前核对</h3><dl className="node-summary"><dt>入口 / 协议</dt><dd>{server?.name||'未选择'} · {protocols[d.protocol]}</dd><dt>服务端监听</dt><dd>{d.listen||'::'} : {d.port} / {transports(d).join(' + ').toUpperCase()}</dd><dt>客户端连接</dt><dd>{d.address||'未填写'} : {d.publicPort||d.port}</dd><dt>默认出口</dt><dd>{exit?`原生内网 → ${exit.name}`:d.outboundId==='direct'?'明确直连':state.outbounds.find(o=>o.id===d.outboundId)?.name||'继承服务器默认出口'}</dd><dt>订阅认证</dt><dd>每个订阅独立生成，节点保存后在“订阅”中授权。</dd></dl>
  {d.protocol==='reality'&&checkResult}
  <ul className="node-checklist">{warnings.map(w=><li key={w}>{w}</li>)}</ul>
  <p className="hint">保存会提交配置任务。Agent 完成配置检查并应用后才会交付节点；“配置已应用”不代表公网连接、证书续期或端到端线路已验证。</p>
 </div>
 {error&&<div className="alert danger" role="alert">{error}</div>}
 <label className="checkbox"><input type="checkbox" checked={d.enabled} onChange={e=>change('enabled',e.target.checked)}/>启用这个节点</label>
 </div>
}
