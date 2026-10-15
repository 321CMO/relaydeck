import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';

async function fixture(t){const home=await mkdtemp(join(tmpdir(),'relaydeck-package-'));t.after(()=>rm(home,{recursive:true,force:true}));const dir=join(home,'input');await mkdir(dir);for(const name of ['relaydeck','sing-box','caddy'])await writeFile(join(dir,name),'#!/bin/sh\nexit 0\n',{mode:0o755});return {home,dir,archive:join(home,'package.tar.gz')}}
function archive(f,names){const v=spawnSync('tar',['-czf',f.archive,'-C',f.dir,...names],{encoding:'utf8'});assert.equal(v.status,0,v.stderr)}
function validate(f){return spawnSync('bash',['-euo','pipefail','-c',`source "$RELAYDECK_INSTALLER"
ARTIFACT="$RELAYDECK_PACKAGE"
trap cleanup EXIT
package
`],{encoding:'utf8',env:{...process.env,RELAYDECK_INSTALLER:resolve('scripts/relaydeck.sh'),RELAYDECK_PACKAGE:f.archive}})}
test('development packages preserve controlled upstream license files',async t=>{const f=await fixture(t);await writeFile(join(f.dir,'CADDY-LICENSE.txt'),'upstream license');await writeFile(join(f.dir,'SING-BOX-LICENSE.txt'),'upstream license');archive(f,['relaydeck','sing-box','caddy','CADDY-LICENSE.txt','SING-BOX-LICENSE.txt']);const v=validate(f);assert.equal(v.status,0,v.stderr)});
test('packages missing a mandatory executable are rejected',async t=>{const f=await fixture(t);archive(f,['relaydeck','caddy']);const v=validate(f);assert.notEqual(v.status,0);assert.match(v.stderr,/缺少核心程序/)});
test('symlink executables are rejected before running any package program',async t=>{const f=await fixture(t);await rm(join(f.dir,'sing-box'));await symlink('/bin/sh',join(f.dir,'sing-box'));archive(f,['relaydeck','sing-box','caddy']);const v=validate(f);assert.notEqual(v.status,0);assert.match(v.stderr,/链接或非普通文件/)});
test('duplicate archive entries cannot override validated executables',async t=>{const f=await fixture(t);archive(f,['relaydeck','sing-box','caddy','caddy']);const v=validate(f);assert.notEqual(v.status,0);assert.match(v.stderr,/重复文件/)});
test('unexpected paths are rejected before extracting the archive',async t=>{const f=await fixture(t);await mkdir(join(f.dir,'nested'));await writeFile(join(f.dir,'nested/extra'),'unexpected');archive(f,['relaydeck','sing-box','caddy','nested/extra']);const v=validate(f);assert.notEqual(v.status,0);assert.match(v.stderr,/文件清单无效/)});
