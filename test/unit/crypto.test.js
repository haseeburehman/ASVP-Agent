import assert from 'node:assert/strict';
import test from 'node:test';
import { decrypt, encrypt, generateEncryptionKey } from '../../src/security/crypto.js';

const plaintext = Buffer.from('sensitive collector result payload', 'utf8');

test('AES-256-GCM encrypt/decrypt round trip preserves plaintext', () => {
  const key = generateEncryptionKey();
  const encrypted = encrypt(plaintext, key);
  assert.deepEqual(decrypt(encrypted.ciphertext, key, encrypted.iv, encrypted.authTag), plaintext);
  assert.equal(encrypted.algorithm, 'aes-256-gcm');
});

test('AES-256-GCM rejects tampered ciphertext', () => {
  const key = generateEncryptionKey();
  const encrypted = encrypt(plaintext, key);
  const tampered = Buffer.from(encrypted.ciphertext, 'base64');
  tampered[0] ^= 0xff;
  assert.throws(
    () => decrypt(tampered.toString('base64'), key, encrypted.iv, encrypted.authTag),
    /authenticate|auth/i,
  );
});

test('AES-256-GCM uses a unique random IV for every encryption', () => {
  const key = generateEncryptionKey();
  const first = encrypt(plaintext, key);
  const second = encrypt(plaintext, key);
  assert.notEqual(first.iv, second.iv);
});
