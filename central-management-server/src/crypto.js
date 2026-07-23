import { createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { gunzip } from 'node:zlib';

const gunzipAsync = promisify(gunzip);

export function generateAgentSecrets() {
  return {
    authToken: randomBytes(32).toString('base64url'),
    encryptionKey: randomBytes(32).toString('base64'),
  };
}

export function hashToken(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export async function decodeResultEnvelope(envelope, encryptionKey) {
  if (envelope.encryption !== 'aes-256-gcm') throw new Error(`Unsupported encryption: ${envelope.encryption}`);
  if (envelope.contentEncoding !== 'gzip') throw new Error(`Unsupported content encoding: ${envelope.contentEncoding}`);
  const key = Buffer.from(encryptionKey, 'base64');
  if (key.length !== 32) throw new Error('Stored agent encryption key is invalid');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
  const compressed = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]);
  const plaintext = await gunzipAsync(compressed);
  return {
    result: JSON.parse(plaintext.toString('utf8')),
    compressedSizeBytes: compressed.length,
    uncompressedSizeBytes: plaintext.length,
  };
}
