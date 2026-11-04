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
