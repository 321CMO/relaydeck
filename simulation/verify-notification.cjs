const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const M = require('./notification-model.cjs');
const tests = [];
const check = (name, fn) => tests.push({ name, fn });
const privateActor = user => ({ user, chat: user, private: true });
const event = (id = 'demo-event') => ({ id, type: 'quota', subject: 'alice', level: 80 });
function down(s) { for (let n = 0; n < 3; n++) M.observe(s, 'A-to-B', false, n * 30, { affected: 3 }); }
check('一位朋友无法查询其他人的用量', () => {
  const s = M.createState(); assert.equal(M.canRead(s, privateActor('2001'), 'alice'), true);
  assert.equal(M.canRead(s, privateActor('2001'), 'bob'), false);
  assert.equal(M.canRead(s, privateActor('9999'), 'alice'), false);
});
check('管理员群内点击不披露私人用量，聊天 ID 不能冒充操作者', () => {
  const s = M.createState(); assert.equal(M.canRead(s, { user: '1001', chat: '-10001', private: false }, 'alice'), false);
  assert.equal(M.canRead(s, { user: '1001', chat: '9999', private: true }, 'alice'), false);
});
check('管理员私聊可读管理数据，解绑后朋友立即不可读', () => {
  const s = M.createState(); assert.equal(M.canRead(s, privateActor('1001'), 'alice'), true);
  s.recipients.friend.active = false; assert.equal(M.canRead(s, privateActor('2001'), 'alice'), false);
});
check('点击绑定链接不能直接获得用户或管理员权限', () => {
  const s = M.createState(); const code = M.bindingTicket(s, 'bob', 0);
  assert.equal(M.claim(s, code, privateActor('3001'), 1), 'pending-web-confirmation');
  assert.equal(M.canRead(s, privateActor('3001'), 'bob'), false);
  assert.equal(M.confirm(s, code, '3001', 2), 'forbidden');
  assert.equal(M.confirm(s, code, '1001', 2), 'bound');
  assert.equal(M.canRead(s, privateActor('3001'), 'bob'), true);
  assert.equal(M.canRead(s, privateActor('3001'), 'alice'), false);
});
check('绑定码在精确到期时失效', () => {
  const s = M.createState(); const code = M.bindingTicket(s, 'bob', 0);
  assert.equal(M.claim(s, code, privateActor('3001'), 600), 'expired');
});
check('绑定只接受私聊，重复与并发领取有明确状态', () => {
  const s = M.createState(); const code = M.bindingTicket(s, 'bob', 0);
  assert.equal(M.claim(s, code, { user: '3001', chat: '-10001', private: false }, 1), 'private-chat-required');
  M.claim(s, code, privateActor('3001'), 1);
  assert.equal(M.claim(s, code, privateActor('4001'), 2), 'claimed');
  assert.equal(M.claim(s, code, privateActor('3001'), 2), 'pending-web-confirmation');
  M.confirm(s, code, '1001', 3); assert.equal(M.claim(s, code, privateActor('3001'), 4), 'used');
});
check('确认时也检查过期与重复绑定', () => {
  const s = M.createState(); const expired = M.bindingTicket(s, 'bob', 0);
  M.claim(s, expired, privateActor('3001'), 1);
  assert.equal(M.confirm(s, expired, '1001', 600), 'expired');
  const duplicate = M.bindingTicket(s, 'bob', 700); M.claim(s, duplicate, privateActor('2001'), 701);
  assert.equal(M.confirm(s, duplicate, '1001', 702), 'already-bound');
});
check('生成新绑定码撤销旧码和旧的待确认申请', () => {
  const s = M.createState(); const first = M.bindingTicket(s, 'bob', 0); M.claim(s, first, privateActor('3001'), 1);
  const second = M.bindingTicket(s, 'bob', 2);
  assert.equal(M.claim(s, first, privateActor('3001'), 3), 'revoked');
  assert.equal(M.confirm(s, first, '1001', 3), 'not-pending');
  assert.equal(M.claim(s, second, privateActor('3002'), 3), 'pending-web-confirmation');
});
check('群消息排除个人额度、登录信息和备份附件', () => {
  const s = M.createState(); M.enqueue(s, event(), 0);
  M.enqueue(s, { id: 'login', type: 'login' }, 0); M.enqueue(s, { id: 'backup', type: 'backup-attachment' }, 0);
  assert.equal(s.jobs.filter(j => j.target === 'group').length, 0);
});
check('固定模板不传播原始 token、密码、订阅 URL 或错误字段', () => {
  const s = M.createState(); M.enqueue(s, { ...event(), password: 'demo-secret', token: 'demo-token', url: 'https://example.com/s/demo-secret', rawError: 'demo-private-error' }, 0);
  for (const j of s.jobs) assert.doesNotMatch(j.text, /demo-secret|demo-token|demo-private-error|example\.com/);
  assert.doesNotMatch(JSON.stringify(s.jobs), /demo-secret|demo-token|demo-private-error|example\.com/);
});
check('同一事件重复采集和进程恢复不重复排队', () => {
  let s = M.createState(); M.enqueue(s, event(), 0); assert.equal(s.jobs.length, 2);
  s = JSON.parse(JSON.stringify(s)); assert.equal(M.enqueue(s, event(), 10), 0); assert.equal(s.jobs.length, 2);
});
check('朋友与管理员按目标独立投递', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); const admin = M.nextJob(s, 0);
  assert.equal(admin.target, 'admin'); M.result(s, admin.id, 403, 0);
  assert.equal(M.nextJob(s, 0).target, 'friend');
});
check('移除接收人后待投递消息取消', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); s.recipients.friend.active = false;
  const j = M.nextJob(s, 0); M.result(s, j.id, 200, 0); assert.equal(M.nextJob(s, 0), null);
  assert.equal(s.jobs.find(j => j.target === 'friend').status, 'cancelled');
});
check('换绑后的旧队列不发给新 Telegram 身份', () => {
  const s = M.createState(); M.enqueue(s, event(), 0);
  const code = M.bindingTicket(s, 'alice', 1); M.claim(s, code, privateActor('2002'), 2); M.confirm(s, code, '1001', 3);
  const j = M.nextJob(s, 4); M.result(s, j.id, 200, 4); assert.equal(M.nextJob(s, 4), null);
  assert.equal(s.jobs.find(j => j.target === 'friend').status, 'cancelled');
});
check('更换 Bot 配置后旧消息不被新通道补发', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); s.generation++;
  assert.equal(M.nextJob(s, 1), null); assert.ok(s.jobs.every(j => j.status === 'cancelled'));
});
check('额度按周期和阈值去重，新周期可再次提醒', () => {
  const s = M.createState(); assert.equal(M.quota(s, 'alice', '2026-10', 85, 100, 0), 80);
  assert.equal(M.quota(s, 'alice', '2026-10', 86, 100, 1), 'unchanged');
  assert.equal(M.quota(s, 'alice', '2026-10', 95, 100, 2), 90);
  assert.equal(M.quota(s, 'alice', '2026-10', 100, 100, 3), 100);
  assert.equal(M.quota(s, 'alice', '2026-11', 85, 100, 4), 80);
  assert.equal(s.jobs.length, 8);
});
check('首次采集就超额只报告最高阈值，不补刷低阈值', () => {
  const s = M.createState(); assert.equal(M.quota(s, 'alice', 'cycle', 101, 100, 0), 100);
  assert.equal(M.quota(s, 'alice', 'cycle', 85, 100, 1), 'unchanged'); assert.equal(s.jobs.length, 2);
});
check('无限额和无效数据不产生额度提醒', () => {
  const s = M.createState(); assert.equal(M.quota(s, 'alice', 'cycle', 100, null, 0), 'unlimited');
  for (const bad of [NaN, -1, Infinity]) assert.equal(M.quota(s, 'alice', 'cycle', bad, 100, 0), 'invalid');
  assert.equal(s.jobs.length, 0);
});
check('一次探测失败不告警，连续三次才开启故障周期', () => {
  const s = M.createState(); M.observe(s, 'A-to-B', false, 0); M.observe(s, 'A-to-B', true, 30);
  assert.equal(s.jobs.length, 0); down(s); assert.equal(s.jobs.length, 2);
});
check('同一 B 故障只产生一组管理员/群通知，标明三入口影响', () => {
  const s = M.createState(); down(s); M.observe(s, 'A-to-B', false, 90, { affected: 3 });
  assert.equal(s.jobs.length, 2); assert.ok(s.jobs.every(j => j.event.affected === 3));
  assert.equal(s.jobs.filter(j => j.target === 'friend').length, 0);
});
check('故障后两次成功才恢复，再次故障有新事件周期', () => {
  const s = M.createState(); down(s); assert.equal(M.observe(s, 'A-to-B', true, 90), 'unchanged');
  assert.equal(M.observe(s, 'A-to-B', true, 120), 'recovered'); const old = s.incidents['A-to-B'].id;
  down(s); assert.notEqual(s.incidents['A-to-B'].id, old);
});
check('维护中不刷停机告警，维护结束仍失败才提醒', () => {
  const s = M.createState(); for (let n = 0; n < 5; n++) M.observe(s, 'A-to-B', false, n * 30, { maintenance: true });
  assert.equal(s.jobs.length, 0); assert.equal(M.observe(s, 'A-to-B', false, 150), 'down');
});
check('离线期间故障已恢复，补发恢复摘要并取消孤立恢复消息', () => {
  const s = M.createState(); down(s); M.observe(s, 'A-to-B', true, 90); M.observe(s, 'A-to-B', true, 120);
  const j = M.nextJob(s, 130); assert.match(j.text, /recovered-summary/);
  assert.equal(s.jobs.find(k => k.target === j.target && k.event.type === 'line.up').status, 'cancelled');
});
check('再次故障不会抹掉上一周期记录或补发上一周期的陈旧故障', () => {
  let s = M.createState(); down(s); const previous = s.incidents['A-to-B'].id;
  M.observe(s, 'A-to-B', true, 90); M.observe(s, 'A-to-B', true, 120);
  for (let n = 0; n < 3; n++) M.observe(s, 'A-to-B', false, 150 + n * 30);
  s = JSON.parse(JSON.stringify(s));
  assert.equal(s.history[previous].active, false); assert.equal(s.incidents['A-to-B'].active, true);
  assert.match(M.nextJob(s, 220).text, /recovered-summary/);
});
check('静默时段延后普通消息，关键故障即时排队', () => {
  const s = M.createState(); M.enqueue(s, event(), 0, { quietUntil: 100 });
  assert.equal(M.nextJob(s, 99), null);
  M.enqueue(s, { id: 'critical', type: 'line.down', critical: true }, 1, { quietUntil: 100 });
  assert.equal(M.nextJob(s, 1).event.id, 'critical');
});
check('429 严格遵守 retry_after，重试不新增消息', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); const j = M.nextJob(s, 0);
  assert.equal(M.result(s, j.id, 429, 0, { retryAfter: 30 }), 'retry');
  // Isolate this target to inspect its retry time.
  s.recipients.friend.active = false;
  assert.equal(M.nextJob(s, 29), null); assert.equal(M.nextJob(s, 30).id, j.id);
  assert.equal(s.jobs.length, 2);
});
check('429 缺少重试参数时仍有退避，不快速循环或直接放弃', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); const j = M.nextJob(s, 0);
  assert.equal(M.result(s, j.id, 429, 0), 'retry'); assert.equal(j.due, 30);
});
check('401 停止失效通道并标明 Token 问题', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); const j = M.nextJob(s, 0);
  assert.equal(M.result(s, j.id, 401, 0), 'token-invalid'); assert.equal(s.enabled, false); assert.equal(M.nextJob(s, 1), null);
});
check('永久格式错误不无限重试', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); const j = M.nextJob(s, 0);
  assert.equal(M.result(s, j.id, 400, 0), 'failed'); assert.equal(j.attempts, 1);
});
check('超时标记投递不确定，暂时错误最多尝试三次', () => {
  const s = M.createState(); M.enqueue(s, event(), 0); s.recipients.friend.active = false;
  let j = M.nextJob(s, 0); M.result(s, j.id, 'timeout', 0); assert.equal(j.uncertain, true);
  j = M.nextJob(s, 2); M.result(s, j.id, 503, 2);
  j = M.nextJob(s, 6); assert.equal(M.result(s, j.id, 503, 6), 'failed'); assert.equal(j.attempts, 3);
});
check('陈旧消息超过保留窗口不造成补发风暴', () => {
  const s = M.createState(); M.enqueue(s, event(), 0);
  assert.equal(M.nextJob(s, 86401), null); assert.ok(s.jobs.every(j => j.status === 'expired'));
});

const results = tests.map(({ name, fn }) => {
  try { fn(); return { name, status: 'pass' }; }
  catch (error) { return { name, status: 'fail', error: error.message }; }
});
const report = { kind: 'offline-notification-design-model', realTelegramTested: false, passed: results.filter(r => r.status === 'pass').length, total: results.length, results };
fs.writeFileSync(path.join(__dirname, 'notification-test-results.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ passed: report.passed, total: report.total, failures: results.filter(r => r.status === 'fail') }));
if (report.passed !== report.total) process.exitCode = 1;
