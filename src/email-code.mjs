import { createHmac, randomInt, timingSafeEqual } from 'node:crypto';

// An eight-digit code has low entropy. Store only a keyed digest and enforce
// attempt and request limits atomically in the persistent store.
export function createCode() {
  return String(randomInt(0, 100_000_000)).padStart(8, '0');
}

export function codeDigest(secret, interactionId, code) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) throw new Error('A secret of at least 32 bytes is required');
  if (typeof interactionId !== 'string' || !interactionId) throw new Error('Interaction ID is required');
  if (!/^\d{8}$/.test(code)) throw new Error('Invalid code format');
  return createHmac('sha256', secret).update('autbot-auth:email-code:v1\0').update(interactionId).update('\0').update(code).digest();
}

export function verifyCode(secret, interactionId, code, expectedDigest) {
  if (!/^\d{8}$/.test(code) || !Buffer.isBuffer(expectedDigest) || expectedDigest.length !== 32) return false;
  return timingSafeEqual(codeDigest(secret, interactionId, code), expectedDigest);
}
