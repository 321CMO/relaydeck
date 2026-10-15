const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const assert=require('node:assert/strict');
(async()=>{
 const path=process.env.RELAYDECK_VPS_BROWSER_SPEC;
 if(!path)throw new Error('A private VPS browser specification is required');
 const spec=JSON.parse(await fs.readFile(path,'utf8'));
 const url=new URL(spec.adminBase||spec.base);
 const adminBase=spec.adminBase||spec.base;
 if(url.protocol!=='https:')throw new Error('Real VPS browser checks require HTTPS');
 const browser=await chromium.launch({headless:true});
 let passed=0;
 try{
  // Use normal browser certificate validation. Temporary/self-signed testing is separate.
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(adminBase);
  await page.getByRole('heading',{name:'欢迎回来'}).waitFor();
  await page.getByLabel('管理员账号',{exact:true}).fill(spec.username);
  await page.getByLabel('密码',{exact:false}).fill(spec.password);
  await page.getByRole('button',{name:'登录',exact:true}).click();
  await page.getByRole('heading',{name:'四步交付第一条线路'}).waitFor();passed++;
  for(const name of ['服务器','节点','朋友与订阅','分流','设置']){
   await page.getByRole('navigation').getByRole('button',{name,exact:true}).click();
   await page.locator('h1').filter({hasText:name}).waitFor();passed++;
  }
  const state=await page.evaluate(async()=>await(await fetch(new URL('api/state',location.href))).json());
  assert.equal(state.state.servers.length,1);
  assert.equal(state.state.nodes.length,3);
  assert.equal(state.state.users.length,2);
  assert.ok(state.state.servers.every(s=>s.enrolled&&s.applied>0&&s.applied===s.desired&&!s.error));passed++;
  await page.getByRole('navigation').getByRole('button',{name:'朋友与订阅',exact:true}).click();
  await page.getByRole('button',{name:'交付订阅',exact:true}).first().click();
  const subscription=await page.getByRole('dialog').getByLabel('固定订阅地址',{exact:true}).inputValue();
  assert.equal(new URL(subscription).hostname,url.hostname);
  assert.equal(new URL(subscription).port,'');
  const result=await context.request.get(subscription+'?format=clash');
  assert.equal(result.status(),200);
  const yaml=await result.text();assert.match(yaml,/reality-opts:/);assert.match(yaml,/hysteria2/);assert.match(yaml,/2022-blake3-aes-128-gcm/);passed++;
  await page.getByRole('button',{name:'完成',exact:true}).click();
  const mobile=await context.newPage();await mobile.setViewportSize({width:390,height:844});await mobile.goto(adminBase);
  await mobile.getByRole('heading',{name:'四步交付第一条线路'}).waitFor();
  assert.equal(await mobile.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  for(const name of ['总览','服务器','节点','朋友与订阅','分流','设置']){
   const box=await mobile.getByRole('navigation').getByRole('button',{name,exact:true}).boundingBox();
   assert.ok(box&&box.x>=0&&box.x+box.width<=390);
  }
  passed++;
  await mobile.getByRole('button',{name:'退出登录',exact:true}).click();await mobile.getByRole('heading',{name:'欢迎回来'}).waitFor();passed++;
  assert.deepEqual(errors,[]);passed++;
  await fs.mkdir('test-results',{recursive:true});
  await fs.writeFile('test-results/vps-browser.json',JSON.stringify({passed,realVpsTested:true,realAgentApplied:true,normalBrowserTLSValidation:true,privateCredentialsExcluded:true},null,2));
  console.log('Real VPS browser checks passed: '+passed);
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
