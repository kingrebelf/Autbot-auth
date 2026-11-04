import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AccountStore } from '../src/accounts.mjs';
import { AccessStore } from '../src/access-store.mjs';
test('only the active owner can invite; access is per app and revocable', () => {
 const dir=mkdtempSync(join(tmpdir(),'autbot-access-')), path=join(dir,'test.sqlite');
 const accounts=new AccountStore(path), access=new AccessStore(path);
 try {
  const owner=accounts.getOrCreate('owner@example.test'), guest=accounts.getOrCreate('guest@example.test'), outsider=accounts.getOrCreate('outsider@example.test');
  assert.equal(access.bootstrapOwner('strata',owner.id),true);
  assert.equal(access.bootstrapOwner('strata',outsider.id),false);
  assert.equal(access.hasAccess('strata',owner.id),true);
  assert.equal(access.hasAccess('strata',guest.id),false);
  assert.throws(()=>access.invite('strata',outsider.id,guest.email),/Not authorized/);
  assert.throws(()=>access.invite('strata',owner.id,'victim@example.test\r\nBcc:attacker@example.test'),/Invalid email/);
  access.invite('strata',owner.id,'guest@EXAMPLE.TEST');
  assert.equal(access.hasAccess('strata',guest.id),true);
  assert.equal(access.hasAccess('another-app',guest.id),false);
  assert.throws(()=>access.list('strata',guest.id),/Not authorized/);
  assert.throws(()=>access.revoke('strata',guest.id,guest.email),/Not authorized/);
  accounts.disable(guest.id); assert.equal(access.hasAccess('strata',guest.id),false);
  assert.equal(access.revoke('strata',owner.id,guest.email),true);
  accounts.disable(owner.id); assert.throws(()=>access.invite('strata',owner.id,outsider.email),/Not authorized/);
 } finally { access.close(); accounts.close(); rmSync(dir,{recursive:true,force:true}); }
});
