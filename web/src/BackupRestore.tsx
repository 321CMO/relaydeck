import {useEffect,useRef,useState} from 'react';
import {ConfigField as Field} from './ProtocolFields';
import {proceedNavigation,useUnsaved} from './interaction';
export default function BackupRestore({api,disabled=false}:{api:(path:string,method?:string,data?:unknown)=>Promise<any>;disabled?:boolean}){
 const [file,setFile]=useState<File|null>(null),[password,setPassword]=useState(''),[currentPassword,setCurrent]=useState(''),[preview,setPreview]=useState<any>(null),[confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[uncertain,setUncertain]=useState(false);
 const mounted=useRef(true);useEffect(()=>()=>{mounted.current=false},[]);useUnsaved(!!file&&!uncertain);
 function reset(){setPreview(null);setConfirmed(false);setCurrent('');setError('');setUncertain(false)}
 async function prepare(){if(!file)return;setBusy(true);setError('');try{
  if(file.size>32*1024*1024)throw new Error('备份文件不能超过 32 MiB');
  const session=await api('session');const body=new FormData();body.set('file',file);body.set('password',password);
  const r=await fetch(new URL('api/backup/preview',location.href),{method:'POST',headers:{'X-CSRF-Token':session.csrf},body,signal:AbortSignal.timeout(60000)});
  const data=await r.json();if(!r.ok)throw new Error(data.error||'备份预览失败');if(mounted.current){setPreview(data);setPassword('');setConfirmed(false)}
 }catch(e){if(mounted.current)setError((e as Error).message)}finally{if(mounted.current)setBusy(false)}}
 function reload(){proceedNavigation();location.reload()}
 async function restore(){if(!preview||!confirmed)return;setBusy(true);setError('');try{
  await api('backup/restore','POST',{planId:preview.planId,currentPassword,confirm:true});setCurrent('');reload();
 }catch(e){if(mounted.current){setError((e as Error).message);if(!(e as any).status){setUncertain(true);setCurrent('');setError('未收到导入结果。请重新登录，核对配置与操作审计后再决定是否重试，避免重复恢复。')}else if((e as any).status===409){setPreview(null);setConfirmed(false)}}}finally{if(mounted.current)setBusy(false)}}
 return <section className="backup-restore"><h3>导入备份</h3><p className="hint">先解密并预览，不会立即覆盖配置。网页导入保留当前管理员、密码、域名、管理端口及安全路径；账号或域名迁移请使用终端完整恢复。</p>
 {disabled&&<p className="alert warning">请先保存或放弃其他设置分区的修改，再导入备份。</p>}
 <Field label="加密备份文件"><input type="file" accept=".bin,.rdbak" disabled={busy||disabled||uncertain} onChange={e=>{setFile(e.target.files?.[0]||null);reset()}}/></Field>
 {!preview&&<Field label="导入备份口令"><input type="password" autoComplete="new-password" minLength={12} maxLength={128} disabled={busy||disabled||uncertain} value={password} onChange={e=>setPassword(e.target.value)}/></Field>}
 {!preview&&<button type="button" className="secondary" disabled={busy||disabled||uncertain||!file||password.length<12} onClick={prepare}>{busy?'正在解密检查…':'解密并预览备份'}</button>}
 {preview&&<div className="restore-preview"><h4>恢复前核对</h4><table><thead><tr><th>业务数据</th><th>当前</th><th>备份</th></tr></thead><tbody>{[['servers','服务器'],['nodes','节点'],['users','订阅'],['routes','路由'],['outbounds','出站']].map(([key,label])=><tr key={key}><td>{label}</td><td>{preview.current[key]}</td><td>{preview.backup[key]}</td></tr>)}</tbody></table><p className="hint">将用备份替换业务数据和 TG 设置；原记录中不在备份内的对象会被移除。订阅地址和节点认证恢复到备份时的值，之前轮换掉的认证可能重新有效。必要时导入后再次轮换。</p><p className="hint">Agent 必须确认新恢复代次才能重新交付。异机备份的 Agent 身份可能不匹配，需要恢复对应身份或重新部署。导入前自动保留最近 3 份同机加密恢复点，用于误导入后在终端回退。连接可能短暂中断。预览 10 分钟有效；配置变化后需重新预览。</p><Field label="导入确认：当前管理员密码"><input type="password" autoComplete="current-password" disabled={busy||uncertain} value={currentPassword} onChange={e=>setCurrent(e.target.value)} maxLength={128}/></Field><label className="checkbox"><input type="checkbox" disabled={busy||uncertain} checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/>我确认替换业务配置，并在导入后重新登录</label><button type="button" className="destructive" disabled={busy||disabled||uncertain||!confirmed||!currentPassword} onClick={restore}>{busy?'正在导入…':'确认导入并重新登录'}</button></div>}
 {uncertain&&<button type="button" className="secondary" onClick={reload}>重新登录并核对结果</button>}
 {error&&<div className="alert danger" role="alert">{error}</div>}
 </section>
}
