const assert=require('node:assert/strict');
module.exports=async(page,check)=>{
 await page.reload();await page.getByRole('heading',{name:'欢迎回来'}).waitFor();
 await page.getByLabel('密码',{exact:true}).fill('test-password-strong-2026');await page.getByRole('button',{name:'登录',exact:true}).click();await page.getByRole('navigation').waitFor();
 await page.getByRole('navigation').getByRole('button',{name:'设置',exact:true}).click();
 await page.getByRole('heading',{name:'账号与安全',exact:true}).waitFor();
 await page.getByText('更改管理端口与安全地址',{exact:true}).click();
 await page.getByLabel('管理 HTTPS 端口',{exact:true}).fill('655350');assert.equal(await page.getByRole('button',{name:'应用并跳转新管理入口'}).isEnabled(),false);
 await page.getByLabel('管理 HTTPS 端口',{exact:true}).fill('42214');await page.getByLabel('安全地址路径',{exact:true}).fill('/my-relay-panel/');assert.equal(await page.getByLabel('新管理入口预览').inputValue(),'http://127.0.0.1:42214/my-relay-panel/');check();
 await page.getByLabel('安全地址路径',{exact:true}).fill('bad/path');assert.equal(await page.getByRole('button',{name:'应用并跳转新管理入口'}).isEnabled(),false);await page.getByLabel('重新生成随机安全路径').check();assert.equal(await page.getByLabel('安全地址路径',{exact:true}).isDisabled(),true);assert.equal(await page.getByRole('button',{name:'应用并跳转新管理入口'}).isEnabled(),true);check();
 await page.getByLabel('当前密码',{exact:true}).fill('wrong-password');await page.getByLabel('新密码',{exact:true}).fill('abcd1234');await page.getByLabel('确认新密码',{exact:true}).fill('mismatch');assert.equal(await page.getByRole('button',{name:'修改密码并退出登录'}).isEnabled(),false);check();
 await page.getByLabel('确认新密码',{exact:true}).fill('abcd1234');await page.getByRole('button',{name:'修改密码并退出登录'}).click();await page.getByRole('alert').filter({hasText:'当前密码错误'}).waitFor();assert.equal(await page.getByRole('heading',{name:'账号与安全',exact:true}).count(),1);check();
 await page.getByLabel('当前密码',{exact:true}).fill('test-password-strong-2026');await page.getByRole('button',{name:'修改密码并退出登录'}).click();await page.getByRole('heading',{name:'欢迎回来'}).waitFor();await page.getByText('密码已修改，请使用新密码登录。',{exact:true}).waitFor();check();
 await page.getByLabel('密码',{exact:true}).fill('test-password-strong-2026');await page.getByRole('button',{name:'登录',exact:true}).click();await page.getByRole('alert').filter({hasText:'账号或密码错误'}).waitFor();await page.getByLabel('密码',{exact:true}).fill('abcd1234');await page.getByRole('button',{name:'登录',exact:true}).click();await page.getByRole('navigation').waitFor();check();
};
