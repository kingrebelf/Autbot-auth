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

test('restricted app rejects uninvited users and revocation blocks tokens and SSO',async()=>{
 const root=mkdtempSync(join(tmpdir(),'autbot-restricted-')), db=join(root,'db.sqlite'), issuer='http://127.0.0.1:31234';
 const objects=createSqliteAdapter(db), accounts=new AccountStore(db), challenges=new ChallengeStore(db,'0123456789abcdef0123456789abcdef'), access=new AccessStore(db);
 try {
  const owner=accounts.getOrCreate('owner@example.test'); access.bootstrapOwner('strata',owner.id);
  const jwk=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'jwk'}); Object.assign(jwk,{kid:'test',use:'sig',alg:'RS256'});
  let sent; const {app}=createApp({issuer,clients:[{client_id:'strata',client_secret:'secret-secret-secret-secret-secret',redirect_uris:['http://localhost:4400/callback'],response_types:['code'],grant_types:['authorization_code']}],jwks:{keys:[jwk]},cookieKeys:['0123456789abcdef0123456789abcdef'],adapter:objects.Adapter,accounts,challenges,access,restrictedClients:['strata'],sendCode:async(email,code)=>{sent={email,code};}});
  const verifier='a'.repeat(64), challenge=createHash('sha256').update(verifier).digest('base64url');
  const query={client_id:'strata',redirect_uri:'http://localhost:4400/callback',response_type:'code',scope:'openid email',state:'s',code_challenge:challenge,code_challenge_method:'S256'};
  const attempt=async agent=>{
   const a=await agent.get('/auth').query(query).expect(303); const path=new URL(a.headers.location,issuer).pathname;
   await agent.get(path).expect(200); await agent.post(path+'/send').set('Origin',issuer).type('form').send({email:'guest@example.test'}).expect(200);
   return agent.post(path+'/verify').set('Origin',issuer).type('form').send({code:sent.code});
  };
  // Explicitly assert the deny response, then invite the verified address.
  const denied=await attempt(request.agent(app)); assert.equal(denied.status,400);
  access.invite('strata',owner.id,'guest@example.test');
  const agent=request.agent(app), verified=await attempt(agent); assert.equal(verified.status,303);
  let res=await agent.get(new URL(verified.headers.location,issuer).pathname+new URL(verified.headers.location,issuer).search).expect(303);
  let path=new URL(res.headers.location,issuer).pathname; await agent.get(path).expect(200);
  res=await agent.post(path+'/consent').set('Origin',issuer).type('form').send({}).expect(303);
  const resume=new URL(res.headers.location,issuer); res=await agent.get(resume.pathname+resume.search).expect(303);
  const code=new URL(res.headers.location).searchParams.get('code'); assert.ok(code);
  await agent.get('/manage/strata').expect(403);
  const token=await request(app).post('/token').auth('strata','secret-secret-secret-secret-secret').type('form').send({grant_type:'authorization_code',code,redirect_uri:'http://localhost:4400/callback',code_verifier:verifier}).expect(200);
  await request(app).get('/me').set('Authorization',`Bearer ${token.body.access_token}`).expect(200);
  access.revoke('strata',owner.id,'guest@example.test');
  await request(app).get('/me').set('Authorization',`Bearer ${token.body.access_token}`).expect(401);
  const retry=await agent.get('/auth').query(query); assert.equal(retry.status,303,'revoked session should redirect without authorizing');
  const deniedInteraction=new URL(retry.headers.location,issuer);
  assert.equal(deniedInteraction.searchParams.has('code'),false);
  const deniedRedirect=await agent.get(deniedInteraction.pathname+deniedInteraction.search).expect(303);
  const deniedResume=new URL(deniedRedirect.headers.location,issuer);
  const finalRedirect=await agent.get(deniedResume.pathname+deniedResume.search).expect(303);
  const deniedCallback=new URL(finalRedirect.headers.location);
  assert.equal(deniedCallback.searchParams.get('error'),'access_denied');
  assert.equal(deniedCallback.searchParams.has('code'),false);
 } finally {access.close(); challenges.close(); accounts.close(); objects.close(); rmSync(root,{recursive:true,force:true});}
});
