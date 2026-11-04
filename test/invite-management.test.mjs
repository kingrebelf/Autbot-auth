import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import request from 'supertest';
import { createApp } from '../src/app.mjs';
import { createSqliteAdapter } from '../src/oidc-adapter.mjs';
import { ChallengeStore } from '../src/challenge-store.mjs';
import { AccountStore } from '../src/accounts.mjs';
import { AccessStore } from '../src/access-store.mjs';

test('owner manages invitations only through a verified, active session',async()=>{
 const root=mkdtempSync(join(tmpdir(),'autbot-manage-')), db=join(root,'db.sqlite'), issuer='http://127.0.0.1:31234';
 const objects=createSqliteAdapter(db), accounts=new AccountStore(db), challenges=new ChallengeStore(db,'0123456789abcdef0123456789abcdef'), access=new AccessStore(db);
 try {
  const owner=accounts.getOrCreate('owner@example.test'); access.bootstrapOwner('strata',owner.id);
  const jwk=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'jwk'}); Object.assign(jwk,{kid:'test',use:'sig',alg:'RS256'});
  let sent,invitation; const {app}=createApp({issuer,clients:[{client_id:'strata',client_secret:'secret-secret-secret-secret-secret',redirect_uris:['http://localhost:4400/callback'],response_types:['code'],grant_types:['authorization_code']}],jwks:{keys:[jwk]},cookieKeys:['0123456789abcdef0123456789abcdef'],adapter:objects.Adapter,accounts,challenges,access,restrictedClients:['strata'],sendCode:async(email,code)=>{sent={email,code};},sendInvitation:async(email,client)=>{invitation={email,client};}});
  await request(app).get('/manage/strata').expect(403);
  const verifier='a'.repeat(64), challenge=createHash('sha256').update(verifier).digest('base64url');
  const query={client_id:'strata',redirect_uri:'http://localhost:4400/callback',response_type:'code',scope:'openid email',state:'s',code_challenge:challenge,code_challenge_method:'S256'};
  const agent=request.agent(app), a=await agent.get('/auth').query(query).expect(303); const path=new URL(a.headers.location,issuer).pathname;
  await agent.post(path+'/send').set('Origin',issuer).type('form').send({email:owner.email}).expect(200);
  let r=await agent.post(path+'/verify').set('Origin',issuer).type('form').send({code:sent.code}).expect(303);
  let next=new URL(r.headers.location,issuer); r=await agent.get(next.pathname+next.search).expect(303);
  const consent=new URL(r.headers.location,issuer); await agent.get(consent.pathname).expect(200);
  r=await agent.post(consent.pathname+'/consent').set('Origin',issuer).type('form').send({}).expect(303);
  next=new URL(r.headers.location,issuer); await agent.get(next.pathname+next.search).expect(303);
  await agent.get('/manage/strata').expect(200);
  await agent.post('/manage/strata/invite').set('Origin','https://evil.example').type('form').send({email:'guest@example.test'}).expect(403);
  await agent.post('/manage/strata/invite').set('Origin',issuer).type('form').send({email:'guest@example.test'}).expect(303);
  assert.deepEqual(invitation,{email:'guest@example.test',client:'strata'});
  assert.equal(access.hasAccess('strata',accounts.getOrCreate('guest@example.test').id),true);
  const page=await agent.get('/manage/strata').expect(200); assert.match(page.text,/guest@example.test/);
  await agent.post('/manage/strata/revoke').set('Origin',issuer).type('form').send({email:'guest@example.test'}).expect(303);
  assert.equal(access.hasAccess('strata',accounts.byEmail('guest@example.test').id),false);
  accounts.disable(owner.id); await agent.get('/manage/strata').expect(403);
 } finally {access.close();challenges.close();accounts.close();objects.close();rmSync(root,{recursive:true,force:true});}
});
