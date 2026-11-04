import test from 'node:test';
import assert from 'node:assert/strict';
import { createCode, codeDigest, verifyCode } from '../src/email-code.mjs';

const secret = '0123456789abcdef0123456789abcdef';
test('codes preserve leading zeroes and have eight digits', () => {
  for (let i = 0; i < 100; i++) assert.match(createCode(), /^\d{8}$/);
});
test('code digests are bound to the specific interaction and secret', () => {
  const digest = codeDigest(secret, 'interaction-a', '00001234');
  assert.equal(verifyCode(secret, 'interaction-a', '00001234', digest), true);
  assert.equal(verifyCode(secret, 'interaction-b', '00001234', digest), false);
  assert.equal(verifyCode(secret, 'interaction-a', '00001235', digest), false);
  assert.equal(verifyCode(secret, 'interaction-a', 'garbage', digest), false);
  assert.equal(verifyCode(secret, 'interaction-a', '00001234', Buffer.alloc(0)), false);
  assert.throws(() => codeDigest('weak', 'interaction-a', '00001234'));
});
