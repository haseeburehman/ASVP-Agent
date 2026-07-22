import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;

function decodeKey(key) {
  const decoded = Buffer.isBuffer(key) ? key : Buffer.from(key, 'base64');
  if (decoded.length !== KEY_BYTES) throw new Error('AES-256-GCM key must be exactly 32 bytes (base64-encoded when provided as a string)');
  return decoded;
}

export function generateEncryptionKey() {
  return randomBytes(KEY_BYTES).toString('base64');
}

export function encrypt(plaintext, key) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, decodeKey(key), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return {
    algorithm: ALGORITHM,
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64'),
  };
}

export function decrypt(ciphertext, key, iv, authTag) {
  const decipher = createDecipheriv(ALGORITHM, decodeKey(key), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);
}
