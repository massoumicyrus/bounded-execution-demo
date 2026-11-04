import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { start } from '../server.mjs';
test('mobile approval page presents exact action and approval unblocks it',async()=>{
  const directory=mkdtempSync(join(tmpdir(),'bounded-ui-'));const app=await start(directory);let browser;
  try{
    const task=app.store.createTask('browser-approval');const object=app.store.createObject({taskId:task.id,target:'review fixture',value:'approved test record',approval:true});
    const grant=app.store.mint(object.id);
    const invoke=()=>fetch(app.url+'/run',{method:'POST',headers:{authorization:'Bearer '+grant.token,'content-type':'application/json'},body:JSON.stringify({objectId:object.id,tool:'APPEND',value:object.value})}).then(r=>r.json());
    assert.equal((await invoke()).reason,'approval_pending');
    browser=await chromium.launch();const page=await browser.newPage({viewport:{width:390,height:844},isMobile:true,deviceScaleFactor:1});
    await page.goto(app.url+'/review');await page.locator('#credential').fill(app.secrets.human);await page.locator('#load').click();
    await page.getByRole('button',{name:'Approve',exact:true}).waitFor();
    assert.match(await page.locator('#requests').innerText(),/approved test record/);
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile horizontal overflow');
    // Remove credential from the rendered capture; it remains in process for the authorized click.
    await page.locator('#credential').evaluate(el=>el.style.visibility='hidden');
    mkdirSync('evidence',{recursive:true});await page.screenshot({path:'evidence/approval-mobile.png',fullPage:true});
    await page.getByRole('button',{name:'Approve',exact:true}).click();
    await page.getByRole('status').filter({hasText:'Approved.'}).waitFor();
    assert.equal((await invoke()).status,'verified');assert.ok(app.store.effect(object.id));
  }finally{await browser?.close();await app.close();rmSync(directory,{recursive:true,force:true});}
});
