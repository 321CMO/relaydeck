// Candidates are suggestions, never a promise of availability from a VPS.
export const realityCandidates=[
 {name:'Microsoft',host:'www.microsoft.com'},
 {name:'Apple',host:'www.apple.com'},
 {name:'Amazon AWS',host:'aws.amazon.com'},
];
const reserved=[2019,8787,10085,18999];
export function transports(n){return n.protocol==='reality'?['tcp']:n.protocol==='hy2'?['udp']:n.network?[n.network]:['tcp','udp'];}
export function suggestedPort(state,serverId,protocol,id='',network=''){
 const ts=transports({protocol,network});const start=protocol==='reality'?18443:protocol==='hy2'?443:20838;
 for(let p=start;p<=65535;p++){
  if(reserved.includes(p)||ts.includes('tcp')&&p===state.settings.https.adminPort)continue;
  if(!state.nodes.some(n=>n.id!==id&&n.serverId===serverId&&n.enabled&&transports(n).some(t=>ts.includes(t))&&(n.port===p||n.protocol==='hy2'&&n.hopStart>0&&p>=n.hopStart&&p<=n.hopEnd)))return p;
 }
 return 0;
}
export function protocolDefaults(protocol,state,serverId){return {protocol,port:suggestedPort(state,serverId,protocol),publicPort:0,sni:protocol==='reality'?realityCandidates[0].host:'',target:protocol==='reality'?realityCandidates[0].host+':443':'',flow:undefined,fingerprint:'',alpn:[],privateKey:'',publicKey:'',shortId:'',shortIds:[],hasPrivateKey:false,serverKey:'',hasServerKey:false,rotateCredentials:false,obfs:'',obfsPassword:'',hasObfsPassword:false,upMbps:0,downMbps:0,method:'',network:'',masquerade:'',hopStart:0,hopEnd:0,hopInterval:30,certificate:'',key:'',tlsMode:'auto',maxTimeDifference:''};}
export function nodeWarnings(d,state){
 const w=[];const srv=state.servers.find(s=>s.id===d.serverId);
 if(!srv?.enrolled||!srv.lastSeen||Date.now()-Date.parse(srv.lastSeen)>90000)w.push('服务器未在线：可以保存配置，但尚不能确认应用与交付。');
 if(d.listen&&d.listen!=='::'&&d.listen!=='0.0.0.0')w.push('已指定监听地址，请确认它属于入口 VPS 且客户端能访问；回环地址无法供公网直连。');
 if(reserved.includes(d.port))w.push('监听端口属于系统保留端口，无法保存。');
 if(state.nodes.some(n=>n.id!==d.id&&n.serverId===d.serverId&&n.enabled&&d.enabled&&transports(n).some(t=>transports(d).includes(t))&&(n.port===d.port||n.protocol==='hy2'&&n.hopStart>0&&d.port>=n.hopStart&&d.port<=n.hopEnd||d.protocol==='hy2'&&d.hopStart>0&&(n.port>=d.hopStart&&n.port<=d.hopEnd||n.hopStart>0&&n.hopStart<=d.hopEnd&&d.hopStart<=n.hopEnd))))w.push('监听端口或跳跃范围与同机节点冲突，请使用推荐端口或调整范围。');
 if(d.protocol==='reality'){
  w.push('Reality 候选站点需要从入口 VPS 检测；检测通过后仍需客户端验证整条代理线路。');
  if(d.flow==='')w.push('已关闭 Vision，请确认客户端使用相同 Flow 配置。');
  if(d.id&&d.privateKey)w.push('保存新的 Reality 私钥会中断旧客户端认证，使用者必须刷新订阅。');
 }
 if(d.protocol==='hy2'){
  if(d.tlsMode==='auto')w.push('自动证书要求证书域名解析到入口 VPS，TCP 80 可达且未被其他程序占用；与面板 Caddy 共机时应导入证书。');
  if(d.tlsMode==='import')w.push('导入证书需自行续期，证书链、私钥与域名必须匹配。');
  if(d.hopStart>0){w.push('请在云安全组放行全部跳跃 UDP 端口；Clash 使用跳跃参数，Shadowrocket 当前导出单端口。');if(d.hopEnd-d.hopStart+1>4096)w.push('跳跃范围超过面板支持的 4096 个连续端口。');if(d.publicPort&&d.publicPort!==d.port)w.push('端口映射与端口跳跃不能同时启用。');}
 }
 if(d.protocol==='ss2022'&&d.id&&d.rotateCredentials)w.push('轮换 SS2022 算法或主密钥会更新此节点的客户端密钥，使用者必须刷新订阅。');
 if(d.exitId){const exit=state.servers.find(s=>s.id===d.exitId);if(!srv?.privateIp||!exit?.privateIp)w.push('内网落地要求入口和落地服务器都填写原生内网 IP。');w.push('内网落地不可达时此线路停止转发，不自动回退直连。');}
 if(!d.id)w.push('保存节点后还需在“订阅”中授权节点；每位使用者的 UUID / 密码 / SS2022 客户端密钥会独立生成。');
 return w;
}
