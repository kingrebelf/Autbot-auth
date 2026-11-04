import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { AccountStore } from '../src/accounts.mjs';
test('setup, register client, backup and restore preserve identities and keys',()=>{
 const root=mkdtempSync(join(tmpdir(),'autbot-test-')); const env={...process.env,AUTBOT_CONFIG_DIR:root};
 try {
  const run=(...args)=>execFileSync(process.execPath,args,{env,stdio:'pipe'}).toString();
  run('src/admin.mjs','init','https://auth.example.test');
  assert.throws(()=>run('src/admin.mjs','init','https://auth.example.test'));
  run('src/admin.mjs','add-client','demo','https://app.example.test/callback');
  const s=new AccountStore(join(root,'autbot.sqlite')); const user=s.getOrCreate('hello@example.test'); s.close();
  run('src/admin.mjs','restrict-client','demo','hello@example.test','https://app.example.test/');
  assert.throws(()=>run('src/admin.mjs','restrict-client','demo','not-verified@example.test','https://app.example.test/'));
  assert.throws(()=>run('src/admin.mjs','restrict-client','demo','hello@example.test','http://app.example.test/'));
  run('src/backup.mjs','snapshot');
  const original=JSON.parse(readFileSync(join(root,'config.json'))); const saved=JSON.parse(readFileSync(join(root,'backups','snapshot','config.json')));
  assert.deepEqual(saved,original); assert.equal(saved.clients[0].client_id,'demo'); assert.equal(saved.restrictedApps.demo,'https://app.example.test/');
  const restored=new AccountStore(join(root,'backups','snapshot','autbot.sqlite')); assert.equal(restored.byId(user.id).email,'hello@example.test'); restored.close();
  assert.throws(()=>run('src/backup.mjs','snapshot'));
 } finally {rmSync(root,{recursive:true,force:true});}
});
