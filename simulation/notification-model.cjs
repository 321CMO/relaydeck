// Offline design model. No real Bot Token, Telegram requests, or service operations.
const MAX_AGE = 86400;
const USER_EVENTS = new Set(['quota', 'expiry', 'authorization']);
function createState() {
  return {
    enabled: true, generation: 1, next: 1,
    recipients: {
      admin: { id: 'admin', role: 'admin', actor: '1001', chat: '1001', active: true, epoch: 1 },
      friend: { id: 'friend', role: 'friend', actor: '2001', chat: '2001', user: 'alice', active: true, epoch: 1 },
      group: { id: 'group', role: 'group', chat: '-10001', active: true, epoch: 1 },
    },
    admins: ['1001'], tickets: {}, jobs: [], seen: [], incidents: {}, history: {}, quota: {},
  };
}
function actorValid(a) { return a?.private === true && /^\d+$/.test(a.user) && a.chat === a.user; }
function canRead(s, actor, subject) {
  if (!actorValid(actor)) return false;
  if (s.admins.includes(actor.user)) return true;
  return Object.values(s.recipients).some(r => r.active && r.role === 'friend' && r.actor === actor.user && r.user === subject);
}
function bindingTicket(s, subject, now) {
  for (const t of Object.values(s.tickets)) if (t.subject === subject && ['available', 'pending'].includes(t.status)) t.status = 'revoked';
  const id = `demo-bind-${s.next++}`;
  s.tickets[id] = { id, subject, expires: now + 600, status: 'available', actor: null };
  return id;
}
function claim(s, id, actor, now) {
  const t = s.tickets[id];
  if (!t || t.expires <= now) return 'expired';
  if (!actorValid(actor)) return 'private-chat-required';
  if (t.status === 'revoked') return 'revoked';
  if (t.status === 'confirmed') return 'used';
  if (t.actor && t.actor !== actor.user) return 'claimed';
  t.status = 'pending'; t.actor = actor.user;
  return 'pending-web-confirmation';
}
function confirm(s, id, admin, now) {
  const t = s.tickets[id];
  if (!s.admins.includes(admin)) return 'forbidden';
  if (!t || t.expires <= now) return 'expired';
  if (t.status !== 'pending') return 'not-pending';
  if (Object.values(s.recipients).some(r => r.active && r.role === 'friend' && r.actor === t.actor && r.user !== t.subject)) return 'already-bound';
  const prior = Object.values(s.recipients).find(r => r.role === 'friend' && r.user === t.subject);
  const key = prior?.id ?? `friend-${t.subject}`;
  s.recipients[key] = { id: key, role: 'friend', actor: t.actor, chat: t.actor, user: t.subject, active: true, epoch: (prior?.epoch ?? 0) + 1 };
  t.status = 'confirmed';
  return 'bound';
}
function audience(r, event) {
  if (!r.active) return false;
  if (r.role === 'admin') return true;
  if (r.role === 'group') return !event.subject && !['login', 'backup-attachment'].includes(event.type);
  return USER_EVENTS.has(event.type) && r.user === event.subject;
}
function render(event, recipient) {
  // Whitelisted fields only. Arbitrary credential/raw-error fields never become messages.
  if (recipient.role === 'group') return `${event.type}: ${event.source ?? 'system'}; affected=${event.affected ?? 0}; event=${event.id}`;
  const subject = event.subject ? `; user=${event.subject}` : '';
  const data = event.level === undefined ? '' : `; threshold=${event.level}%`;
  return `${event.type}: ${event.source ?? 'system'}${subject}${data}; event=${event.id}`;
}
function enqueue(s, event, now, { quietUntil = 0 } = {}) {
  if (!s.enabled) return 0;
  const fields = new Set(['id', 'type', 'source', 'subject', 'level', 'incident', 'critical', 'affected']);
  event = Object.fromEntries(Object.entries(event).filter(([key]) => fields.has(key)));
  let count = 0;
  for (const r of Object.values(s.recipients).filter(r => audience(r, event))) {
    const key = JSON.stringify([event.id, r.id, s.generation, r.epoch]);
    if (s.seen.includes(key)) continue;
    s.seen.push(key);
    s.jobs.push({
      id: `demo-job-${s.next++}`, event: structuredClone(event), target: r.id,
      generation: s.generation, epoch: r.epoch, created: now,
      due: event.critical ? now : Math.max(now, quietUntil), attempts: 0,
      status: 'queued', text: render(event, r), uncertain: false,
    });
    count++;
  }
  return count;
}
function quota(s, user, cycle, used, limit, now) {
  if (limit == null) return 'unlimited';
  if (!Number.isSafeInteger(limit) || limit <= 0 || !Number.isSafeInteger(used) || used < 0) return 'invalid';
  const percent = used / limit * 100;
  const level = percent >= 100 ? 100 : percent >= 90 ? 90 : percent >= 80 ? 80 : 0;
  const key = JSON.stringify([user, cycle]);
  if (level <= (s.quota[key] ?? 0)) return 'unchanged';
  s.quota[key] = level;
  enqueue(s, { id: `quota-${user}-${cycle}-${level}`, type: 'quota', subject: user, level }, now);
  return level;
}
function observe(s, source, healthy, now, { maintenance = false, affected = 1 } = {}) {
  const i = s.incidents[source] ??= { source, bad: 0, good: 0, active: false, revision: 0 };
  if (healthy) { i.good++; i.bad = 0; } else { i.bad++; i.good = 0; }
  if (maintenance) return 'maintenance';
  if (!i.active && i.bad >= 3) {
    i.active = true; i.revision++; i.start = now; delete i.end;
    i.id = `incident-${source}-${i.revision}`;
    s.history[i.id] = { id: i.id, source, start: now, active: true };
    enqueue(s, { id: `${i.id}-down`, incident: i.id, type: 'line.down', source, affected, critical: true }, now);
    return 'down';
  }
  if (i.active && i.good >= 2) {
    i.active = false; i.end = now;
    Object.assign(s.history[i.id], { active: false, end: now });
    enqueue(s, { id: `${i.id}-up`, incident: i.id, type: 'line.up', source, affected }, now);
    return 'recovered';
  }
  return 'unchanged';
}
function nextJob(s, now) {
  for (const j of s.jobs.filter(j => ['queued', 'retry'].includes(j.status))) {
    const r = s.recipients[j.target];
    if (!s.enabled || j.generation !== s.generation || !r?.active || j.epoch !== r.epoch || !audience(r, j.event)) { j.status = 'cancelled'; continue; }
    if (now - j.created > MAX_AGE) { j.status = 'expired'; continue; }
    if (j.due > now) continue;
    const i = j.event.incident && s.history[j.event.incident];
    if (j.event.type === 'line.down' && i && !i.active) {
      j.text = `line.recovered-summary: ${i.source}; start=${i.start}; end=${i.end}; event=${i.id}`;
      for (const up of s.jobs.filter(k => k.target === j.target && k.event.incident === i.id && k.event.type === 'line.up' && ['queued', 'retry'].includes(k.status))) up.status = 'cancelled';
    }
    j.status = 'sending';
    return j;
  }
  return null;
}
function result(s, id, code, now, { retryAfter = 0 } = {}) {
  const j = s.jobs.find(j => j.id === id);
  if (!j || j.status !== 'sending') return 'invalid-job';
  j.attempts++;
  if (code === 200) { j.status = 'sent'; return j.status; }
  if (code === 401) { s.enabled = false; j.status = 'token-invalid'; return j.status; }
  if (code === 403) { s.recipients[j.target].active = false; j.status = 'recipient-unavailable'; return j.status; }
  if (code === 429) {
    j.status = 'retry'; j.due = now + (Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : 30);
  } else if (code === 'timeout' || code >= 500) {
    j.uncertain ||= code === 'timeout';
    j.status = j.attempts < 3 ? 'retry' : 'failed';
    j.due = now + 2 ** j.attempts;
  } else j.status = 'failed';
  return j.status;
}
module.exports = { createState, canRead, bindingTicket, claim, confirm, enqueue, quota, observe, nextJob, result };
