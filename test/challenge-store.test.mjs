import test from 'node:test';
import assert from 'node:assert/strict';
import { ChallengeStore } from '../src/challenge-store.mjs';
const secret = '0123456789abcdef0123456789abcdef';
const challenge = { interaction: 'one', email: 'person@example.test', ip: '192.0.2.1', code: '01234567' };
test('successful codes are single use and tied to the interaction', () => {
  const s = new ChallengeStore(':memory:', secret);
  assert.equal(s.issue(challenge), true);
  assert.equal(s.verify('other', challenge.code), null);
  assert.equal(s.verify('one', challenge.code), challenge.email);
  assert.equal(s.verify('one', challenge.code), null);
  s.close();
});
test('codes expire and repeated incorrect guesses lock the challenge', () => {
  let now = 0; const s = new ChallengeStore(':memory:', secret, () => now);
  s.issue({...challenge, ttlMs: 100}); now = 100;
  assert.equal(s.verify('one', challenge.code), null);
  now = 101; s.issue(challenge);
  for (let i=0; i<5; i++) assert.equal(s.verify('one', '99999999'), null);
  assert.equal(s.verify('one', challenge.code), null);
  s.close();
});
test('per-email request limits apply across IPs and interactions', () => {
  const s = new ChallengeStore(':memory:', secret);
  for (let i=0; i<3; i++) assert.equal(s.issue({...challenge, interaction: String(i), ip: String(i)}), true);
  assert.equal(s.issue({...challenge, interaction: '4', ip: '4'}), false);
  s.close();
});


test('email send quotas cannot be bypassed by changing letter case', () => {
 const s=new ChallengeStore(':memory:',secret);
 for (const [i,email] of ['Person@example.test','PERSON@example.test','person@example.test'].entries())
   assert.equal(s.issue({...challenge,interaction:String(i),ip:String(i),email}),true);
 assert.equal(s.issue({...challenge,interaction:'four',ip:'four',email:'pErSoN@example.test'}),false);
 s.close();
});
test('cleanup removes expired challenges and rate-limit windows', () => {
 let now=1000; const s=new ChallengeStore(':memory:',secret,()=>now);
 assert.equal(s.issue({...challenge,ttlMs:100}),true);
 now+=3_600_001; const deleted=s.cleanup();
 assert.equal(deleted.challenges,1); assert.equal(deleted.windows,3);
 assert.equal(s.verify(challenge.interaction,challenge.code),null);
 assert.equal(s.issue(challenge),true); s.close();
});


test('persistent global daily send budget is capped and resets', () => {
 let now=1000; const s=new ChallengeStore(':memory:',secret,()=>now);
 for(let i=0;i<80;i++) assert.equal(s.issue({...challenge,interaction:String(i),email:`p${i}@example.test`,ip:`ip${i}`}),true);
 assert.equal(s.issue({...challenge,interaction:'over',email:'over@example.test',ip:'over'}),false);
 now+=86_399_999;
 assert.equal(s.issue({...challenge,interaction:'still-over',email:'still@example.test',ip:'still'}),false);
 now+=2;
 assert.equal(s.issue({...challenge,interaction:'next',email:'next@example.test',ip:'next'}),true);
 s.close();
});
