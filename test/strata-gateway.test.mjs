import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import request from 'supertest';
import { createStrataGateway,makeTokenChecker } from '../gateway/strata.mjs';

test('page requires an active invitation; Strata receives the user’s own API key',async()=>{
 let seen,protect=true,modelsRequireKey=true;
 const upstream=http.createServer((req,res)=>{
  if(req.url==='/health'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({api_key:protect}));return;}
  if(req.url==='/v1/models' && !req.headers.authorization && !req.headers['x-api-key']) {res.statusCode=modelsRequireKey?401:200;res.end();return;}
  let body=''; req.on('data',c=>body+=c);req.on('end',()=>{seen={url:req.url,headers:req.headers,body};res.setHeader('Set-Cookie','upstream=1');res.end('upstream-ok');});
 });
 await new Promise(resolve=>upstream.listen(0,'127.0.0.1',resolve));
 const tokens={allowed:{sub:'invited'}};
 try {
  const app=createStrataGateway({publicOrigin:'https://strata.example.test',upstream:`http://127.0.0.1:${upstream.address().port}`,checkToken:async token=>tokens[token]||null});
  await request(app).get('/').set('Authorization','Bearer any-api-key').expect(401);
  await request(app).get('/web/app.js').expect(401);
  await request(app).get('/').set('X-Forwarded-Access-Token','invalid').expect(401);
  const page=await request(app).get('/').set('X-Forwarded-Access-Token','allowed').set('Authorization','Bearer user-key').set('X-Api-Key','secondary-key').set('Cookie','browser-session=1').expect(200);
  assert.equal(seen.headers.authorization,'Bearer user-key'); assert.equal(seen.headers['x-api-key'],'secondary-key');
  assert.equal(seen.headers.cookie,undefined); assert.equal(seen.headers['x-forwarded-access-token'],undefined); assert.equal(page.headers['set-cookie'],undefined);
  await request(app).post('/settings').set('X-Forwarded-Access-Token','allowed').set('Origin','https://evil.example').send({x:1}).expect(403);
  await request(app).post('/settings').set('X-Forwarded-Access-Token','allowed').set('Origin','https://strata.example.test').set('Authorization','Bearer user-key').send({x:1}).expect(200);
  assert.equal(seen.headers.authorization,'Bearer user-key'); assert.match(seen.body,/"x":1/);
  // Existing machine clients can use the API without a browser login, but the
  // upstream must positively prove it is still enforcing API keys.
  await request(app).post('/v1/chat/completions').set('Authorization','Bearer machine-key').send({message:'hello'}).expect(200);
  assert.equal(seen.headers.authorization,'Bearer machine-key'); assert.match(seen.body,/hello/);
  protect=false; await request(app).post('/v1/chat/completions').set('Authorization','Bearer machine-key').send({}).expect(503);
  protect=true; modelsRequireKey=false; await request(app).post('/v1/chat/completions').set('X-Api-Key','machine-key').send({}).expect(503);
  modelsRequireKey=true; await request(app).get('/web/%2e%2e/api-keys').set('X-Forwarded-Access-Token','allowed').expect(400);
  delete tokens.allowed; await request(app).get('/').set('X-Forwarded-Access-Token','allowed').expect(401);
 } finally { await new Promise(resolve=>upstream.close(resolve)); }
});

test('introspection fails closed for wrong clients, expired or inactive tokens',async()=>{
 const good={active:true,client_id:'strata',iss:'https://auth.example.test',sub:'u',exp:Math.floor(Date.now()/1000)+60,token_type:'Bearer'};
 let returned=good;
 const check=makeTokenChecker({issuer:'https://auth.example.test',clientId:'strata',clientSecret:'secret',fetcher:async(_url,options)=>{assert.match(options.headers.authorization,/^Basic /);return {ok:true,json:async()=>returned};}});
 assert.deepEqual(await check('token'),{sub:'u'});
 for(const bad of [{...good,client_id:'other'},{...good,active:false},{...good,iss:'https://other.example'}, {...good,exp:1},{...good,token_type:'refresh_token'}]) {returned=bad;assert.equal(await check('token'),null);}
 const failing=makeTokenChecker({issuer:'https://auth.example.test',clientId:'strata',clientSecret:'secret',fetcher:async()=>{throw new Error('network')}});
 assert.equal(await failing('token'),null);
 assert.throws(()=>makeTokenChecker({issuer:'http://auth.example.test',clientId:'strata',clientSecret:'secret'}));
});
