import {useState} from 'react';
import {useUnsaved,proceedNavigation} from './interaction';

type Props={busy:boolean;api:(path:string,method?:string,data?:unknown)=>Promise<any>;action:(fn:()=>Promise<void>)=>Promise<void>;beforeChange?:()=>boolean};

export function PasswordSettings({busy,api,action,beforeChange}:Props){
 const [current,setCurrent]=useState(''),[next,setNext]=useState(''),[confirm,setConfirm]=useState('');
 const guard=useUnsaved(!!(current||next||confirm));
 const bytes=new TextEncoder().encode(next).length;
 const valid=!!current&&[...next].length>=8&&bytes<=128&&next===confirm&&next!==current;
 return <section className="card settings-card"><h2>账号与安全</h2><p className="hint">修改成功后，所有设备都会退出登录。用户名和订阅凭据不变。</p><form onSubmit={e=>{e.preventDefault();if(valid&&guard.confirmOthers())void action(async()=>{await api('account/password','POST',{currentPassword:current,newPassword:next,confirmPassword:confirm});sessionStorage.setItem('relaydeck-security-notice','密码已修改，请使用新密码登录。');proceedNavigation();location.reload()})}}>
 <label className="field"><span>当前密码</span><input type="password" required maxLength={128} autoComplete="current-password" value={current} onChange={e=>setCurrent(e.target.value)}/></label>
 <label className="field"><span>新密码</span><input aria-label="新密码" type="password" required maxLength={128} autoComplete="new-password" value={next} onChange={e=>setNext(e.target.value)}/><small>至少 8 个字符，最多 128 字节；建议使用独立的长密码。</small></label>
 <label className="field"><span>确认新密码</span><input aria-label="确认新密码" type="password" required maxLength={128} autoComplete="new-password" value={confirm} onChange={e=>setConfirm(e.target.value)}/>{confirm&&confirm!==next&&<small role="status">两次输入的新密码不一致</small>}</label>
 <button className="secondary full" disabled={busy||!valid}>修改密码并退出登录</button></form></section>
}

export function AccessSettings({port,busy,api,action,beforeChange}:{port:number}&Props){
 const [nextPort,setPort]=useState(port),[path,setPath]=useState(location.pathname.replace(/^\/+|\/+$/g,'')),[rotate,setRotate]=useState(false);
 const guard=useUnsaved(nextPort!==port||path!==location.pathname.replace(/^\/+|\/+$/g,'')||rotate);
 const segment=path.replace(/^\/+|\/+$/g,'');
 const valid=Number.isInteger(nextPort)&&nextPort>=1024&&nextPort<=65535&&(rotate||/^[A-Za-z0-9_-]{6,96}$/.test(segment));
 const preview=new URL(location.href);if(nextPort>=1024&&nextPort<=65535)preview.port=String(nextPort);preview.pathname='/'+segment+'/';preview.hash='';preview.search='';
 return <details><summary>更改管理端口与安全地址</summary>
 <label className="field"><span>管理 HTTPS 端口</span><input type="number" min={1024} max={65535} value={nextPort} onChange={e=>setPort(Number(e.target.value))}/></label>
 <label className="field"><span>安全地址路径</span><input aria-label="安全地址路径" disabled={rotate} value={path} maxLength={98} autoComplete="off" spellCheck={false} placeholder="例如 my-relay-panel" onChange={e=>setPath(e.target.value)}/><small>6–96 个字母、数字、下划线或连字符，可带首尾斜杠。</small></label>
 <label className="checkbox"><input type="checkbox" checked={rotate} onChange={e=>setRotate(e.target.checked)}/>重新生成随机安全路径</label>
 {!rotate&&valid&&<label className="field"><span>新管理入口预览</span><input readOnly value={preview.toString()}/></label>}
 <p className="hint">先在云安全组放行新的 TCP 端口。切换成功后，旧管理地址失效，所有设备需要重新登录。请保存新入口，订阅和 Agent 地址保持不变。</p>
 <button type="button" className="secondary" disabled={busy||!valid} onClick={()=>{if(!guard.confirmOthers())return;void action(async()=>{const v=await api('https/access','POST',{port:nextPort,rotate,...(!rotate?{path:segment}:{})});proceedNavigation();location.assign(v.adminUrl)})}}>应用并跳转新管理入口</button></details>
}
