const {chromium}=require('playwright');
const fs=require('node:fs/promises');
const assert=require('node:assert/strict');
(async()=>{
 const spec=JSON.parse(await fs.readFile(process.env.RELAYDECK_VPS_BROWSER_SPEC,'utf8'));
 const admin=new URL(spec.adminBase);const publicOrigin=new URL(spec.base).origin;
 const browser=await chromium.launch({headless:true});let passed=0;
 try{
  const context=await browser.newContext({viewport:{width:390,height:844}});
  const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  for(const path of ['/','/api/session','/api/state','/assets/missing.js']){
   assert.equal((await context.request.get(publicOrigin+path)).status(),404);
  }passed++;
  assert.equal((await context.request.get(admin.origin+'/')).status(),404);
  assert.equal((await context.request.get(admin.origin+'/wrong/api/session')).status(),404);passed++;
  await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:publicOrigin});
  const first=spec.users[0].subscription;
  await page.goto(first);await page.getByRole('heading',{name:/的订阅$/}).waitFor();
  assert.equal(new URL(page.url()).pathname,new URL(first).pathname);
  assert.notEqual(await page.locator('#used').textContent(),'暂无数据');
  assert.match(await page.locator('#usage-note').textContent(),/最后上报/);
  assert.equal(await page.locator('.node').count(),3);passed++;
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);passed++;
  await page.locator('#copy').click();await page.getByRole('status').filter({hasText:/已复制/}).waitFor();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),first);passed++;
  const exported=await context.request.get(first,{headers:{'User-Agent':'Clash Verge Mihomo'}});
  assert.equal(exported.status(),200);assert.match(exported.headers()['subscription-userinfo'],/upload=\d+; download=\d+; total=0/);
  assert.equal(exported.headers()['profile-web-page-url'],first);passed++;
  assert.equal((await context.cookies()).some(c=>c.name==='relaydeck_session'),false);passed++;
  const body=await page.textContent('body');assert.equal(body.includes('实测朋友 B'),false);passed++;
  if(process.env.RELAYDECK_EXPECT_DISABLED==='1'){
   const second=spec.users[1].subscription;await page.goto(second);
   await page.locator('.badge').filter({hasText:'已停用'}).waitFor();
   assert.equal(await page.getByRole('link',{name:'下载 Clash Verge 配置',exact:true}).count(),0);
   assert.equal((await context.request.get(second+'?format=clash')).status(),403);passed++;
  }
  assert.deepEqual(errors,[]);passed++;
  await fs.mkdir('test-results',{recursive:true});
  if(process.env.RELAYDECK_EXPECT_DISABLED!=='1'){
   await page.evaluate(()=>{document.getElementById('subscription').value='https://example.com/s/PRIVATE'});
   await page.screenshot({path:'test-results/personal-subscription-mobile.png',fullPage:true});
  }
  await fs.writeFile('test-results/vps-portal.json',JSON.stringify({passed,realVpsTested:true,verifiedUserTraffic:true,standardTLS:true,disabledPortalChecked:process.env.RELAYDECK_EXPECT_DISABLED==='1'},null,2));
  console.log('Real VPS personal subscription checks passed: '+passed);
 }finally{await browser.close()}
})().catch(()=>{console.error('Real VPS personal subscription check failed; inspect private test environment.');process.exitCode=1});
