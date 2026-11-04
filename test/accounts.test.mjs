import test from 'node:test';
import assert from 'node:assert/strict';
import { AccountStore } from '../src/accounts.mjs';
test('accounts receive stable distinct identifiers and can be disabled', () => {
 const s=new AccountStore(':memory:'); const a=s.getOrCreate('a@example.test');
 assert.equal(s.getOrCreate('a@example.test').id,a.id);
 assert.notEqual(s.getOrCreate('b@example.test').id,a.id);
 assert.equal(s.disable(a.id),true); assert.equal(s.byId(a.id).disabled,1); s.close();
});
