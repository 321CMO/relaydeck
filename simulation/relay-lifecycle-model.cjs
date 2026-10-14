// Offline design model only: no package download, shell, network or proxy core.
const clone = value => structuredClone(value);
const PROTOCOLS = ['reality', 'hy2', 'ss2022'];
const CIPHERS = {
  '2022-blake3-aes-128-gcm': 16,
  '2022-blake3-aes-256-gcm': 32,
  '2022-blake3-chacha20-poly1305': 32,
};

function createState() {
  return {
    hosts: Object.fromEntries(['A', 'B', 'C'].map(id => [id, {
      id, privateIP: `10.10.0.${{ A: 1, B: 2, C: 3 }[id]}`,
      publicIP: `192.0.2.${{ A: 1, B: 2, C: 3 }[id]}`, online: true,
      identity: null, roles: {}, unrelatedRules: ['keep-ssh'],
    }])),
    nodes: PROTOCOLS.map(protocol => ({
      id: `A-${protocol}`, host: 'A', protocol, purpose: 'public',
      address: 'entry.example.com', revision: 1, grants: ['friend'],
    })),
    paths: {}, tasks: {}, usage: {}, batches: [], pendingWrite: false,
  };
}

function install(s, host, role, evidence = {}) {
  if (!s.hosts[host] || !['center', 'agent'].includes(role)) return 'invalid';
  if (evidence.archSupported === false) return 'unsupported';
  if (evidence.download === false || evidence.integrity === false) return 'download-rejected';
  const h = s.hosts[host];
  h.identity ??= `demo-identity-${host}`;
  if (h.roles[role]?.running) return 'unchanged';
  h.roles[role] = {
    version: 'demo-v1', schema: 1, data: { token: 'demo-stable-token' },
    running: evidence.health !== false, backup: null,
  };
  return h.roles[role].running ? 'installed' : 'retry-needed';
}

function upgrade(s, host, role, evidence = {}) {
  const component = s.hosts[host]?.roles[role];
  if (!component?.running) return 'not-running';
  if (evidence.compatible === false) return 'incompatible';
  if (evidence.download === false || evidence.integrity === false) return 'download-rejected';
  const old = clone(component);
  delete old.backup;
  component.backup = old;
  s.pendingWrite = true;
  component.version = 'demo-v2';
  component.schema = 2;
  if (evidence.migration === false || evidence.health === false) {
    s.hosts[host].roles[role] = { ...clone(old), backup: old };
    if (evidence.restoreHealth === false) {
      s.hosts[host].roles[role].running = false;
      return 'needs-recovery';
    }
    s.pendingWrite = false;
    return 'rolled-back';
  }
  s.pendingWrite = false;
  return 'upgraded';
}

function uninstall(s, host, role, { clear = false, confirmed = false } = {}) {
  if (clear && !confirmed) return 'confirmation-required';
  const h = s.hosts[host];
  if (!h?.roles[role]) return 'absent';
  const dependency = Object.values(s.paths).some(p => p.exit === host)
    || Object.values(s.tasks).some(t => t.exit === host && ['running', 'uncertain'].includes(t.status));
  if (role === 'agent' && dependency) return 'dependent-lines';
  if (clear) delete h.roles[role];
  else h.roles[role].running = false;
  return 'uninstalled';
}

function validKey(cipher, key) {
  if (!CIPHERS[cipher] || typeof key !== 'string') return false;
  const bytes = Buffer.from(key, 'base64');
  return bytes.length === CIPHERS[cipher] && bytes.toString('base64') === key;
}

function planLine(s, { id, entry, exit, nodeIDs, privateIP }) {
  const fingerprint = JSON.stringify([entry, exit, [...(nodeIDs ?? [])].sort(), privateIP]);
  if (s.tasks[id]) return s.tasks[id].fingerprint === fingerprint
    ? { status: 'replay', task: s.tasks[id] } : { status: 'task-id-conflict' };
  if (!s.hosts[entry]?.roles.agent?.running || !s.hosts[exit]?.roles.agent?.running) return { status: 'unregistered' };
  if (entry === exit) return { status: 'self-loop' };
  if (privateIP !== s.hosts[exit].privateIP) return { status: 'not-confirmed-private' };
  if (!nodeIDs?.length || new Set(nodeIDs).size !== nodeIDs.length
      || nodeIDs.some(id => !s.nodes.some(n => n.id === id && n.host === entry && n.purpose === 'public'))) return { status: 'invalid-nodes' };
  if (Object.values(s.tasks).some(t => ['running', 'uncertain'].includes(t.status)
      && t.nodeIDs.some(n => nodeIDs.includes(n)))) return { status: 'conflicting-task' };
  const edges = [...Object.values(s.paths), ...Object.values(s.tasks).filter(t => ['running', 'uncertain'].includes(t.status))];
  const reaches = (current, target, seen = new Set()) => {
    if (current === target) return true;
    if (seen.has(current)) return false;
    seen.add(current);
    return edges.filter(p => p.entry === current).some(p => reaches(p.exit, target, seen));
  };
  if (reaches(exit, entry)) return { status: 'cycle' };
  const task = {
    id, fingerprint, entry, exit, nodeIDs: [...nodeIDs], privateIP, phase: 0, status: 'running',
    previous: Object.fromEntries(nodeIDs.map(n => [n, clone(s.paths[n] ?? null)])),
  };
  s.tasks[id] = task;
  return { status: 'planned', task };
}

function failLine(s, task) {
  for (const node of task.nodeIDs) {
    if (task.previous[node]) s.paths[node] = clone(task.previous[node]);
    else delete s.paths[node];
  }
  s.nodes = s.nodes.filter(n => n.id !== `internal-${task.id}`);
  task.status = 'failed';
  return task.status;
}

function ensureInternal(s, task) {
  if (!s.nodes.some(n => n.id === `internal-${task.id}`)) s.nodes.push({
    id: `internal-${task.id}`, host: task.exit, protocol: 'ss2022',
    purpose: 'internal', revision: 1, grants: ['friend'],
  });
}

// Evidence represents results that real Agents/core probes must obtain later.
function stepLine(s, id, evidence = {}) {
  const task = s.tasks[id];
  if (!task) return 'unknown-task';
  if (task.status !== 'running') return task.status;
  if (evidence.ack === 'unknown') { task.status = 'uncertain'; return task.status; }
  if (evidence.ok === false) return failLine(s, task);
  if (task.phase === 0) {
    ensureInternal(s, task);
  } else if (task.phase === 1) {
    if (!evidence.privateRoute || !evidence.auth || !evidence.tcp || !evidence.udp) return failLine(s, task);
  } else if (task.phase === 3) {
    if (evidence.egressIP !== s.hosts[task.exit].publicIP || !evidence.dns || !evidence.tcp || !evidence.udp) return failLine(s, task);
  } else if (task.phase === 4) {
    for (const node of task.nodeIDs) s.paths[node] = { lineID: task.id, entry: task.entry, exit: task.exit, privateIP: task.privateIP, failClosed: true };
    task.status = 'committed';
    const referenced = new Set(Object.values(s.paths).map(p => `internal-${p.lineID}`));
    for (const pending of Object.values(s.tasks).filter(t => ['running', 'uncertain'].includes(t.status))) referenced.add(`internal-${pending.id}`);
    s.nodes = s.nodes.filter(n => n.purpose !== 'internal' || referenced.has(n.id));
  }
  task.phase++;
  return task.status;
}

function reconcileLine(s, id, { phase, failed = false }) {
  const task = s.tasks[id];
  if (task?.status !== 'uncertain') return 'not-uncertain';
  if (failed) return failLine(s, task);
  if (!Number.isInteger(phase) || phase < task.phase || phase > 4) return 'invalid-evidence';
  if (phase > 0) ensureInternal(s, task);
  task.phase = phase;
  task.status = 'running';
  return task.status;
}

function subscription(s, user) {
  return s.nodes.filter(n => n.purpose === 'public' && n.revision > 0 && n.grants.includes(user))
    .map(n => ({ id: n.id, protocol: n.protocol, address: n.address }));
}

function routeRequest(s, node) {
  const selected = s.nodes.find(n => n.id === node);
  if (!selected) return 'rejected';
  if (!s.hosts[selected.host].roles.agent?.running) return 'blocked';
  if (selected.purpose === 'internal') return selected.host; // B internal ingress always exits locally.
  if (Object.values(s.tasks).some(t => t.status === 'uncertain' && t.nodeIDs.includes(node))) return 'unknown-needs-reconcile';
  const path = s.paths[node];
  if (!path) return selected.host;
  return s.hosts[path.exit].online && s.hosts[path.exit].roles.agent?.running ? path.exit : 'blocked';
}

function ingest(s, { node, user, epoch, sequence, bytes }) {
  const n = s.nodes.find(n => n.id === node);
  if (!n || !n.grants.includes(user) || !Number.isSafeInteger(bytes) || bytes < 0) return 'invalid';
  if (n.purpose !== 'public') return 'internal-excluded';
  if (!Number.isSafeInteger(sequence) || sequence < 0 || !epoch) return 'invalid';
  const key = JSON.stringify([node, user, epoch, sequence]);
  if (s.batches.includes(key)) return 'duplicate';
  const total = (s.usage[user] ?? 0) + bytes;
  if (!Number.isSafeInteger(total)) return 'invalid';
  s.usage[user] = total;
  s.batches.push(key);
  return 'counted';
}

module.exports = { createState, install, upgrade, uninstall, validKey, planLine, stepLine, reconcileLine, subscription, routeRequest, ingest };
