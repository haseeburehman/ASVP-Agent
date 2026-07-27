import { createHmac, timingSafeEqual } from 'node:crypto';

const KEY_DERIVATION_CONTEXT = 'asvp-task-signing-key:v1';

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
}

export function canonicalizeTaskParams(params) {
  if (!params || typeof params !== 'object' || Array.isArray(params)) throw new TypeError('Task params must be an object');
  return JSON.parse(canonicalize(params));
}

export function deriveTaskSigningKey(masterSecret, agentId) {
  if (typeof masterSecret !== 'string' || !masterSecret) throw new TypeError('Task signing master secret must be a non-empty string');
  if (typeof agentId !== 'string' || !agentId) throw new TypeError('Agent ID must be a non-empty string');
  return createHmac('sha256', masterSecret).update(`${KEY_DERIVATION_CONTEXT}:${agentId}`, 'utf8').digest('base64');
}

export function canonicalTaskPayload(envelope) {
  const { signature: _signature, ...payload } = envelope;
  return canonicalize(payload);
}

function decodeSignature(signature) {
  if (typeof signature !== 'string' || signature.length === 0) return null;
  if (/^[a-f\d]{64}$/i.test(signature)) return Buffer.from(signature, 'hex');
  try {
    const decoded = Buffer.from(signature, 'base64');
    return decoded.length === 32 ? decoded : null;
  } catch {
    return null;
  }
}

export function signTaskEnvelope(envelope, signingKey) {
  return createHmac('sha256', Buffer.from(signingKey, 'base64'))
    .update(canonicalTaskPayload(envelope))
    .digest('base64');
}

export function verifyTaskEnvelopeSignature(envelope, signingKey) {
  const supplied = decodeSignature(envelope?.signature);
  if (!supplied) return false;
  const expected = createHmac('sha256', Buffer.from(signingKey, 'base64'))
    .update(canonicalTaskPayload(envelope))
    .digest();
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}
