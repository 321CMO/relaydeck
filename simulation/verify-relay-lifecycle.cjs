const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const M = require('./relay-lifecycle-model.cjs');
const tests = [];
const check = (name, fn) => tests.push({ name, fn });
function ready() {
  const s = M.createState();
  for (const host of ['A', 'B', 'C']) M.install(s, host, 'agent');
  M.install(s, 'A', 'center');
  return s;
}
function plan(s, id = 'line-1', exit = 'B', nodeIDs = s.nodes.filter(n => n.host === 'A' && n.purpose === 'public').map(n => n.id)) {
  return M.planLine(s, { id, entry: 'A', exit, nodeIDs, privateIP: s.hosts[exit].privateIP });
}
function finish(s, id = 'line-1') {
  const exit = s.tasks[id].exit;
  const evidence = { privateRoute: true, auth: true, tcp: true, udp: true, dns: true, egressIP: s.hosts[exit].publicIP };
  while (s.tasks[id].status === 'running') M.stepLine(s, id, evidence);
  return s.tasks[id].status;
}

check('首次安装下载失败不生成身份或组件', () => {
  const s = M.createState();
  assert.equal(M.install(s, 'A', 'agent', { download: false }), 'download-rejected');
  assert.equal(s.hosts.A.identity, null);
  assert.deepEqual(s.hosts.A.roles, {});
});
check('不支持的架构不会写入服务', () => {
  const s = M.createState();
  assert.equal(M.install(s, 'A', 'agent', { archSupported: false }), 'unsupported');
  assert.deepEqual(s.hosts.A.roles, {});
});
check('校验失败不能覆盖正在运行的组件', () => {
  const s = ready(); const before = structuredClone(s.hosts.A);
  assert.equal(M.upgrade(s, 'A', 'center', { integrity: false }), 'download-rejected');
  assert.deepEqual(s.hosts.A, before);
});
check('失败安装重试保留身份，重复安装不产生第二份服务', () => {
  const s = M.createState();
  assert.equal(M.install(s, 'A', 'agent', { health: false }), 'retry-needed');
  const identity = s.hosts.A.identity;
  assert.equal(M.install(s, 'A', 'agent'), 'installed');
  assert.equal(M.install(s, 'A', 'agent'), 'unchanged');
  assert.equal(s.hosts.A.identity, identity);
  assert.equal(Object.keys(s.hosts.A.roles).length, 1);
});
check('不兼容更新不改变现网数据', () => {
  const s = ready(); const before = structuredClone(s.hosts.A.roles.center);
  assert.equal(M.upgrade(s, 'A', 'center', { compatible: false }), 'incompatible');
  assert.deepEqual(s.hosts.A.roles.center, before);
});
for (const fault of ['migration', 'health']) check(`${fault}失败同时恢复旧程序、数据库和订阅身份`, () => {
  const s = ready();
  assert.equal(M.upgrade(s, 'A', 'center', { [fault]: false }), 'rolled-back');
  const c = s.hosts.A.roles.center;
  assert.equal(c.version, 'demo-v1'); assert.equal(c.schema, 1);
  assert.equal(c.data.token, 'demo-stable-token'); assert.equal(s.pendingWrite, false);
});
check('恢复检查失败不能虚报回退成功，写操作保持冻结', () => {
  const s = ready();
  assert.equal(M.upgrade(s, 'A', 'center', { health: false, restoreHealth: false }), 'needs-recovery');
  assert.equal(s.pendingWrite, true); assert.equal(s.hosts.A.roles.center.running, false);
});
check('正常更新保留匹配旧快照和稳定身份', () => {
  const s = ready(); assert.equal(M.upgrade(s, 'A', 'center'), 'upgraded');
  const c = s.hosts.A.roles.center;
  assert.equal(c.version, 'demo-v2'); assert.equal(c.schema, 2);
  assert.equal(c.backup.schema, 1); assert.equal(c.data.token, c.backup.data.token);
});
check('中心卸载不停止同机和远端节点，默认保留数据', () => {
  const s = ready(); assert.equal(M.uninstall(s, 'A', 'center'), 'uninstalled');
  assert.equal(s.hosts.A.roles.agent.running, true); assert.equal(s.hosts.B.roles.agent.running, true);
  assert.equal(s.hosts.A.roles.center.data.token, 'demo-stable-token');
  assert.deepEqual(s.hosts.A.unrelatedRules, ['keep-ssh']);
});
check('清除数据需要明确确认', () => {
  const s = ready(); assert.equal(M.uninstall(s, 'A', 'center', { clear: true }), 'confirmation-required');
  assert.equal(s.hosts.A.roles.center.running, true);
  assert.equal(M.uninstall(s, 'A', 'center', { clear: true, confirmed: true }), 'uninstalled');
  assert.equal(s.hosts.A.roles.center, undefined);
});
check('三个对外协议可以共享一条落地线路', () => {
  const s = ready(); assert.equal(plan(s).status, 'planned'); assert.equal(finish(s), 'committed');
  for (const n of ['A-reality', 'A-hy2', 'A-ss2022']) assert.equal(M.routeRequest(s, n), 'B');
});
check('新候选线路就绪前不改变当前有效出口', () => {
  const s = ready(); plan(s); M.stepLine(s, 'line-1');
  assert.equal(M.routeRequest(s, 'A-reality'), 'A');
  assert.deepEqual(s.paths, {});
});
for (const fault of ['privateRoute', 'auth', 'tcp', 'udp']) check(`${fault}检查失败不能启用内网线路`, () => {
  const s = ready(); plan(s); M.stepLine(s, 'line-1');
  M.stepLine(s, 'line-1', { privateRoute: true, auth: true, tcp: true, udp: true, [fault]: false });
  assert.equal(s.tasks['line-1'].status, 'failed'); assert.deepEqual(s.paths, {});
  assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 0);
});
check('不允许自动改用 B 公网地址', () => {
  const s = ready();
  assert.equal(M.planLine(s, { id: 'x', entry: 'A', exit: 'B', nodeIDs: ['A-reality'], privateIP: s.hosts.B.publicIP }).status, 'not-confirmed-private');
});
check('A 与 B 相同被拒绝', () => {
  const s = ready(); assert.equal(plan(s, 'x', 'A').status, 'self-loop');
});
check('选中的对外节点必须属于入口 A', () => {
  const s = ready(); assert.equal(plan(s, 'x', 'B', ['missing']).status, 'invalid-nodes');
});
check('托管线路成环被拒绝', () => {
  const s = ready(); plan(s); finish(s);
  s.nodes.push({ id: 'B-reality', host: 'B', protocol: 'reality', purpose: 'public', grants: ['friend'], revision: 1 });
  assert.equal(M.planLine(s, { id: 'reverse', entry: 'B', exit: 'A', nodeIDs: ['B-reality'], privateIP: s.hosts.A.privateIP }).status, 'cycle');
});
check('同一任务重发不增加内部入口或重复应用', () => {
  const s = ready(); plan(s); M.stepLine(s, 'line-1');
  assert.equal(plan(s).status, 'replay'); assert.equal(s.tasks['line-1'].phase, 1);
  finish(s); assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 1);
});
check('相同任务 ID 不能携带不同落地请求', () => {
  const s = ready(); plan(s);
  assert.equal(plan(s, 'line-1', 'C').status, 'task-id-conflict');
  assert.equal(s.tasks['line-1'].exit, 'B');
});
check('未完成任务阻止同入口并发切换', () => {
  const s = ready(); plan(s); assert.equal(plan(s, 'new', 'C').status, 'conflicting-task');
});
check('回执未知不虚报有效出口，冻结任务直到核对', () => {
  const s = ready(); plan(s);
  assert.equal(M.stepLine(s, 'line-1', { ack: 'unknown' }), 'uncertain');
  assert.equal(M.routeRequest(s, 'A-reality'), 'unknown-needs-reconcile');
  assert.equal(plan(s, 'new', 'C').status, 'conflicting-task');
  assert.equal(M.reconcileLine(s, 'line-1', { phase: 0 }), 'running');
  assert.equal(finish(s), 'committed');
});
check('B 已执行但回执丢失，核对后重建资源记录并继续而非重复安装', () => {
  const s = ready(); plan(s); M.stepLine(s, 'line-1', { ack: 'unknown' });
  assert.equal(M.reconcileLine(s, 'line-1', { phase: 1 }), 'running');
  assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 1);
  assert.equal(finish(s), 'committed');
  assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 1);
  assert.equal(M.routeRequest(s, 'internal-line-1'), 'B');
});
check('不接受倒退的核对阶段，保持任务待核对', () => {
  const s = ready(); plan(s); M.stepLine(s, 'line-1'); M.stepLine(s, 'line-1', { ack: 'unknown' });
  assert.equal(M.reconcileLine(s, 'line-1', { phase: 0 }), 'invalid-evidence');
  assert.equal(s.tasks['line-1'].status, 'uncertain');
});
check('出口是 A 或 DNS 未就绪，拒绝提交候选线路', () => {
  for (const e of [{ egressIP: '192.0.2.1', dns: true }, { egressIP: '192.0.2.2', dns: false }]) {
    const s = ready(); plan(s);
    for (let i = 0; i < 3; i++) M.stepLine(s, 'line-1', { privateRoute: true, auth: true, tcp: true, udp: true });
    M.stepLine(s, 'line-1', { tcp: true, udp: true, ...e });
    assert.equal(s.tasks['line-1'].status, 'failed'); assert.deepEqual(s.paths, {});
  }
});
check('切换 C 在任一阶段失败，原 B 线路继续有效', () => {
  for (let failPhase = 0; failPhase < 5; failPhase++) {
    const s = ready(); plan(s); finish(s); const before = structuredClone(s.paths);
    plan(s, 'switch-C', 'C');
    for (let i = 0; i < failPhase; i++) M.stepLine(s, 'switch-C', { privateRoute: true, auth: true, tcp: true, udp: true, dns: true, egressIP: s.hosts.C.publicIP });
    assert.equal(M.stepLine(s, 'switch-C', { ok: false }), 'failed');
    assert.deepEqual(s.paths, before); assert.equal(M.routeRequest(s, 'A-reality'), 'B');
    assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 1);
  }
});
check('B 下线请求被阻断，无 A 直出或公网回退', () => {
  const s = ready(); plan(s); finish(s); s.hosts.B.online = false;
  assert.equal(M.routeRequest(s, 'A-reality'), 'blocked');
  assert.equal(M.routeRequest(s, 'A-hy2'), 'blocked');
  assert.equal(s.paths['A-reality'].privateIP, s.hosts.B.privateIP);
});
check('仅指定节点走 B，其他节点保留本机出口', () => {
  const s = ready(); plan(s, 'line-1', 'B', ['A-hy2']); finish(s);
  assert.equal(M.routeRequest(s, 'A-hy2'), 'B'); assert.equal(M.routeRequest(s, 'A-reality'), 'A');
});
check('B 内部入口固定 B 出网，订阅过滤不依赖普通授权是否误设', () => {
  const s = ready(); const before = M.subscription(s, 'friend'); plan(s); finish(s);
  assert.deepEqual(M.subscription(s, 'friend'), before);
  assert.equal(M.routeRequest(s, 'internal-line-1'), 'B');
  assert.equal(M.subscription(s, 'someone-else').length, 0);
});
check('切换落地不改变朋友的节点连接信息', () => {
  const s = ready(); plan(s); finish(s); const before = M.subscription(s, 'friend');
  plan(s, 'switch-C', 'C'); finish(s, 'switch-C');
  assert.equal(M.routeRequest(s, 'A-reality'), 'C'); assert.deepEqual(M.subscription(s, 'friend'), before);
  assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 1);
});
check('部分节点切换落地时保留仍被其他节点引用的 B 入口', () => {
  const s = ready(); plan(s); finish(s);
  plan(s, 'only-hy2', 'C', ['A-hy2']); finish(s, 'only-hy2');
  assert.equal(M.routeRequest(s, 'A-hy2'), 'C'); assert.equal(M.routeRequest(s, 'A-reality'), 'B');
  assert.equal(s.nodes.filter(n => n.purpose === 'internal').length, 2);
});
check('使用中的落地机和正在部署的候选落地不能普通卸载', () => {
  const s = ready(); plan(s); assert.equal(M.uninstall(s, 'B', 'agent'), 'dependent-lines');
  finish(s); assert.equal(M.uninstall(s, 'B', 'agent'), 'dependent-lines');
});
check('A 用户计一次，B 内部字节排除，重复上报排除', () => {
  const s = ready(); plan(s); finish(s);
  const batch = { node: 'A-ss2022', user: 'friend', epoch: 'demo-boot-1', sequence: 1, bytes: 1024 };
  assert.equal(M.ingest(s, batch), 'counted'); assert.equal(M.ingest(s, batch), 'duplicate');
  assert.equal(M.ingest(s, { ...batch, node: 'internal-line-1' }), 'internal-excluded');
  assert.equal(s.usage.friend, 1024);
});
check('计量序号按节点及运行周期区分', () => {
  const s = ready(); const batch = { node: 'A-ss2022', user: 'friend', epoch: 'demo-boot-1', sequence: 1, bytes: 1024 };
  M.ingest(s, batch); M.ingest(s, { ...batch, node: 'A-hy2' }); M.ingest(s, { ...batch, epoch: 'demo-boot-2' });
  assert.equal(s.usage.friend, 3072);
});
check('SS2022 验证真实字节长度，拒绝文本密码、短密钥和错误算法', () => {
  assert.equal(M.validKey('2022-blake3-aes-128-gcm', Buffer.alloc(16).toString('base64')), true);
  assert.equal(M.validKey('2022-blake3-aes-256-gcm', Buffer.alloc(32).toString('base64')), true);
  assert.equal(M.validKey('2022-blake3-aes-128-gcm', 'password'), false);
  assert.equal(M.validKey('2022-blake3-aes-128-gcm', Buffer.alloc(8).toString('base64')), false);
  assert.equal(M.validKey('unknown', Buffer.alloc(16).toString('base64')), false);
});

const results = tests.map(({ name, fn }) => {
  try { fn(); return { name, status: 'pass' }; }
  catch (error) { return { name, status: 'fail', error: error.message }; }
});
const report = {
  kind: 'offline-design-state-model', scope: 'v6 install/upgrade/uninstall and private A-to-B relay constraints',
  realDeploymentTested: false, passed: results.filter(r => r.status === 'pass').length,
  total: results.length, results,
};
fs.writeFileSync(path.join(__dirname, 'relay-lifecycle-test-results.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ passed: report.passed, total: report.total, failures: results.filter(r => r.status === 'fail') }));
if (report.passed !== report.total) process.exitCode = 1;
