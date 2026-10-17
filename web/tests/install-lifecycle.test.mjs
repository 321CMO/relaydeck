import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, readFile, symlink, readlink, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';

const library=resolve('scripts/lib/lifecycle.sh');
const base=`source "$RELAYDECK_TEST_LIB"
ROOT="$RELAYDECK_TEST_HOME/root"
DATA="$RELAYDECK_TEST_HOME/data"
UNIT_DIR="$RELAYDECK_TEST_HOME/units"
STAGE="$RELAYDECK_TEST_HOME/package"
VERSION=v0.1.0-alpha.1
FAULT="\${FAULT:-}"
systemctl(){
 printf '%s\\n' "$*" >> "$RELAYDECK_TEST_HOME/events"
 case "$1" in
 is-active) test -f "$RELAYDECK_TEST_HOME/running/$3";;
 stop) rm -f "$RELAYDECK_TEST_HOME/running/$2";;
 start) if [[ $FAULT == start && $(bundle_target) != releases/old ]]; then return 1; fi; touch "$RELAYDECK_TEST_HOME/running/$2";;
 show) printf '0\\n';;
 *) return 1;;
 esac
}
service_ready(){
 if [[ $FAULT == health && $(bundle_target) != releases/old ]]; then
  printf 'new-state' > "$DATA/agent/identity.json"
  return 1
 fi
 systemctl is-active --quiet "$1"
}
`;
async function fixture(t,roles=['panel','agent','caddy']){const home=await mkdtemp(join(tmpdir(),'relaydeck-lifecycle-'));t.after(()=>rm(home,{recursive:true,force:true}));for(const p of ['root/releases/old','data','units','package','running'])await mkdir(join(home,p),{recursive:true});for(const name of ['relaydeck','sing-box','caddy']){await writeFile(join(home,'root/releases/old',name),'old-'+name,{mode:0o755});await writeFile(join(home,'package',name),'new-'+name,{mode:0o755})}await symlink('releases/old',join(home,'root/current'));for(const role of roles){await mkdir(join(home,'data',role),{recursive:true});await writeFile(join(home,'data',role,role==='agent'?'identity.json':'data'),'original-'+role,{mode:0o600});await writeFile(join(home,'units','relaydeck-'+role+'.service'),'# Managed by RelayDeck\n');await writeFile(join(home,'running','relaydeck-'+role),'')}return home}
function run(home,code,extra={}){const v=spawnSync('bash',['-euo','pipefail','-c',base+'\n'+code],{encoding:'utf8',env:{...process.env,RELAYDECK_TEST_HOME:home,RELAYDECK_TEST_LIB:library,...extra}});assert.equal(v.status,0,v.stderr||v.stdout);return v.stdout}

test('agent-only upgrade snapshots agent state without opening a panel database',async t=>{const home=await fixture(t,['agent']);run(home,'stage_bundle; upgrade_transaction');assert.notEqual(await readlink(join(home,'root/current')),'releases/old');const snapshot=(await readFile(join(home,'root/last-snapshot'),'utf8')).trim();assert.equal(await readFile(join(snapshot,'agent/identity.json'),'utf8'),'original-agent');await assert.rejects(stat(join(snapshot,'panel')));assert.equal((await stat(snapshot)).mode&0o777,0o700)});
test('a failed start restores the complete previous bundle and service state',async t=>{const home=await fixture(t);run(home,'stage_bundle; if upgrade_transaction; then exit 12; fi',{FAULT:'start'});assert.equal(await readlink(join(home,'root/current')),'releases/old');for(const role of ['panel','agent','caddy'])await stat(join(home,'running','relaydeck-'+role));await assert.rejects(stat(join(home,'root/pending-upgrade')))});
test('health failure restores data modified by the new process before restarting old services',async t=>{const home=await fixture(t);run(home,'stage_bundle; if upgrade_transaction; then exit 12; fi',{FAULT:'health'});assert.equal(await readFile(join(home,'data/agent/identity.json'),'utf8'),'original-agent');assert.equal(await readlink(join(home,'root/current')),'releases/old')});
test('interrupted switch is recovered from a durable private snapshot',async t=>{const home=await fixture(t);run(home,'stage_bundle; capture_running; stop_running; snapshot_data; printf "%s\\n" "$SNAPSHOT" > "$ROOT/pending-upgrade"; activate_bundle "$NEW_BUNDLE"; printf interrupted > "$DATA/agent/identity.json"');run(home,'recover_interrupted_upgrade');assert.equal(await readlink(join(home,'root/current')),'releases/old');assert.equal(await readFile(join(home,'data/agent/identity.json'),'utf8'),'original-agent');await stat(join(home,'running/relaydeck-agent'))});
test('an inactive role stays inactive while running roles upgrade',async t=>{const home=await fixture(t);await rm(join(home,'running/relaydeck-agent'));run(home,'stage_bundle; upgrade_transaction');await assert.rejects(stat(join(home,'running/relaydeck-agent')));await stat(join(home,'running/relaydeck-panel'))});
test('bundle identity depends on content rather than temporary directory names',async t=>{const home=await fixture(t);const out=run(home,'stage_bundle; first=$NEW_BUNDLE; cp -a "$STAGE" "$RELAYDECK_TEST_HOME/other-package"; STAGE="$RELAYDECK_TEST_HOME/other-package"; stage_bundle; [[ $first == "$NEW_BUNDLE" ]]');assert.equal(out,'')});
test('manual program rollback preserves user changes made after upgrading',async t=>{const home=await fixture(t);run(home,'stage_bundle; upgrade_transaction; printf later-edit > "$DATA/panel/data"; rollback_program');assert.equal(await readlink(join(home,'root/current')),'releases/old');assert.equal(await readFile(join(home,'data/panel/data'),'utf8'),'later-edit')});
test('failed manual rollback returns to the working bundle without restoring old data',async t=>{const home=await fixture(t);run(home,`stage_bundle; upgrade_transaction
new=$NEW_BUNDLE
service_ready(){ [[ $(bundle_target) != releases/old ]]; }
if rollback_program; then exit 12; fi
[[ $(bundle_target) == "$new" ]]
`);assert.notEqual(await readlink(join(home,'root/current')),'releases/old')});
test('HTTPS entry is stopped first and reopened after internal services pass health checks',async t=>{const home=await fixture(t);run(home,'stage_bundle; upgrade_transaction');const events=(await readFile(join(home,'events'),'utf8')).trim().split('\n');const stop=events.filter(v=>v.startsWith('stop '));assert.deepEqual(stop,['stop relaydeck-caddy','stop relaydeck-agent','stop relaydeck-panel']);const starts=events.filter(v=>v.startsWith('start '));assert.deepEqual(starts,['start relaydeck-panel','start relaydeck-agent','start relaydeck-caddy'])});
test('failure to persist success metadata rolls the running version back too',async t=>{const home=await fixture(t);await mkdir(join(home,'root/last-snapshot'));run(home,'stage_bundle; if upgrade_transaction; then exit 12; fi');assert.equal(await readlink(join(home,'root/current')),'releases/old');await stat(join(home,'running/relaydeck-panel'))});
test('failed snapshots keep the old program and restart existing services',async t=>{const home=await fixture(t);run(home,`stage_bundle
cp(){ if [[ $* == *"$DATA/agent"* ]]; then return 1; fi; command cp "$@"; }
if upgrade_transaction; then exit 12; fi
`);assert.equal(await readlink(join(home,'root/current')),'releases/old');await stat(join(home,'running/relaydeck-agent'));await assert.rejects(stat(join(home,'root/pending-upgrade')))});
test('upgrading a fully stopped installation leaves every service stopped',async t=>{const home=await fixture(t);for(const role of ['panel','agent','caddy'])await rm(join(home,'running','relaydeck-'+role));run(home,'stage_bundle; upgrade_transaction');for(const role of ['panel','agent','caddy'])await assert.rejects(stat(join(home,'running','relaydeck-'+role)))});
test('the generated installer is standalone and its help never requires root or systemd',async t=>{const home=await mkdtemp(join(tmpdir(),'relaydeck-standalone-'));t.after(()=>rm(home,{recursive:true,force:true}));const file=join(home,'installer.sh');const build=spawnSync('python3',['scripts/build-installer.py',file],{encoding:'utf8'});assert.equal(build.status,0,build.stderr);const syntax=spawnSync('bash',['-n',file],{encoding:'utf8'});assert.equal(syntax.status,0,syntax.stderr);const help=spawnSync('bash',[file,'help'],{encoding:'utf8'});assert.equal(help.status,0,help.stderr);assert.match(help.stdout,/RelayDeck/);assert.doesNotMatch(await readFile(file,'utf8'),/source "\$\{BASH_SOURCE\[0\]%\/\*\}\/lib/)});
