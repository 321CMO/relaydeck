import test from 'node:test';
import assert from 'node:assert/strict';
import {suggestedPort,protocolDefaults,nodeWarnings} from '../src/node-config.mjs';
const state=()=>({settings:{https:{adminPort:42214}},servers:[{id:'a',name:'A',enrolled:true,lastSeen:new Date().toISOString(),privateIp:'10.0.0.1'}],nodes:[],users:[],outbounds:[]});
test('推荐端口避开已用 TCP、双栈 SS 和 UDP 跳跃范围，允许独立协议端口',()=>{
 const s=state();s.nodes=[{id:'1',serverId:'a',protocol:'reality',port:18443,enabled:true},{id:'2',serverId:'a',protocol:'ss2022',port:18444,enabled:true},{id:'3',serverId:'a',protocol:'hy2',port:24443,hopStart:443,hopEnd:445,enabled:true}];
 assert.equal(suggestedPort(s,'a','reality'),18445);assert.equal(suggestedPort(s,'a','hy2'),446);
 s.nodes[0].protocol='ss2022';s.nodes[0].network='udp';assert.equal(suggestedPort(s,'a','reality'),18443);
 assert.equal(suggestedPort(s,'b','reality'),18443);
});
test('切换协议清除旧密钥、证书、目标及跳跃配置；保留名称等公共字段由调用端控制',()=>{
 const d=protocolDefaults('ss2022',state(),'a');assert.equal(d.privateKey,'');assert.equal(d.target,'');assert.deepEqual(d.shortIds,[]);assert.equal(d.certificate,'');assert.equal(d.hopStart,0);assert.equal(d.port,20838);
});
test('配置核对明确指出证书自动申请前提、客户端跳跃边界及映射冲突',()=>{
 const warnings=nodeWarnings({protocol:'hy2',serverId:'a',port:443,publicPort:8443,tlsMode:'auto',hopStart:20000,hopEnd:20010},state()).join('\n');assert.match(warnings,/TCP 80/);assert.match(warnings,/Shadowrocket/);assert.match(warnings,/端口映射与端口跳跃不能同时/);assert.match(warnings,/每位使用者/);
});
