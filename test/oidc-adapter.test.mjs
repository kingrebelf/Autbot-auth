import test from 'node:test';
import assert from 'node:assert/strict';
import { createSqliteAdapter } from '../src/oidc-adapter.mjs';
test('OIDC objects expire, consume, update indexes and revoke across models', async () => {
 let t = 100000; const store = createSqliteAdapter(':memory:', () => t);
 const session = new store.Adapter('Session'); const code = new store.Adapter('AuthorizationCode'); const token = new store.Adapter('AccessToken');
 await session.upsert('s', {uid:'old'}, 10); assert.equal((await session.findByUid('old')).uid,'old');
 await session.upsert('s', {uid:'new'}, 10); assert.equal(await session.findByUid('old'),undefined);
 await code.upsert('c',{grantId:'g',userCode:'ABCD'},10); await token.upsert('t',{grantId:'g'},10);
 assert.equal((await code.findByUserCode('ABCD')).grantId,'g');
 await code.consume('c'); assert.equal((await code.find('c')).consumed,100); await assert.rejects(() => code.consume('c'));
 await code.revokeByGrantId('g'); assert.equal(await code.find('c'),undefined); assert.equal(await token.find('t'),undefined);
 t += 10000; assert.equal(await session.find('s'),undefined); store.cleanup(); store.close();
});
