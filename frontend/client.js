import { sm2, sm4 } from 'sm-crypto-v2';

const PREFIX = 'SMCRYPTO/1';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const b64chars = /^[A-Za-z0-9_-]*$/;
const kidChars = /^[A-Za-z0-9_-]{1,64}$/;
const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
const maxPlaintextBytes = 1024 * 1024;
const maxEnvelopeBytes = 2 * maxPlaintextBytes;

export class ProtocolError extends Error {
  constructor(message = 'Unauthenticated or invalid SM crypto response') {
    super(message);
    this.name = 'ProtocolError';
  }
}

function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function b64encode(value) {
  let binary = '';
  for (let i = 0; i < value.length; i += 8192) {
    binary += String.fromCharCode(...value.subarray(i, i + 8192));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function b64decode(value, bytes) {
  if (typeof value !== 'string' || !b64chars.test(value) ||
      (bytes !== undefined && value.length !== Math.ceil(bytes * 4 / 3))) {
    throw new ProtocolError();
  }
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'));
  const result = Uint8Array.from(binary, c => c.charCodeAt(0));
  if ((bytes !== undefined && result.length !== bytes) || b64encode(result) !== value) {
    throw new ProtocolError();
  }
  return result;
}

function hex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(string) {
  return Uint8Array.from(string.match(/../g), b => Number.parseInt(b, 16));
}

function checkedPath(path, origin) {
  if (typeof path !== 'string' || path.length > 1024 || !/^\/[A-Za-z0-9/_~.-]*$/.test(path) ||
    path.includes('//') || (path !== '/' && path.endsWith('/')) || path.split('/').some(part => part === '.' || part === '..')) {
    throw new TypeError('Use an absolute path without a query or a fragment');
  }
  const url = new URL(path, origin);
  if (url.origin !== origin || url.pathname !== path) {
    throw new TypeError('Use the canonical path on the configured origin');
  }
  return url;
}

async function readJson(response, budget) {
  if (response.redirected || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '') ||
      !response.body) throw new ProtocolError();
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > budget) {
        await reader.cancel();
        throw new ProtocolError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(decoder.decode(all));
}

/**
 * Create a client pinned to a trusted HTTPS origin (HTTP loopback only when explicitly enabled).
 * The host remains responsible for authentication and authorization.
 */
export function createCryptoClient({
  origin = globalThis.location?.origin,
  publicKeyPath = '/crypto/public-key',
  allowInsecureLoopback = false,
  keyCacheMs = 60_000,
  fetchImpl = globalThis.fetch?.bind(globalThis),
} = {}) {
  const parsed = new URL(origin);
  if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash ||
      (parsed.protocol !== 'https:' && !(allowInsecureLoopback && parsed.protocol === 'http:' &&
        loopbackHosts.has(parsed.hostname)))) {
    throw new TypeError('A trusted HTTPS origin is required');
  }
  if (!Number.isSafeInteger(keyCacheMs) || keyCacheMs < 0 || keyCacheMs > 300_000 ||
      typeof fetchImpl !== 'function') throw new TypeError('Invalid client configuration');

  const keyUrl = checkedPath(publicKeyPath, parsed.origin);
  let cachedKey;

  async function getKey(signal) {
    if (cachedKey && cachedKey.expiresAt > Date.now()) return cachedKey;
    try {
      const response = await fetchImpl(keyUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
        redirect: 'error',
        credentials: 'omit',
        signal,
      });
      if (!response.ok) throw new ProtocolError();
      const value = await readJson(response, 4096);
      if (typeof value?.kid !== 'string' || !kidChars.test(value.kid)) throw new ProtocolError();
      const publicKey = b64decode(value.publicKey, 65);
      if (publicKey[0] !== 4) throw new ProtocolError();
      cachedKey = { kid: value.kid, publicKey: hex(publicKey), expiresAt: Date.now() + keyCacheMs };
      return cachedKey;
    } catch (err) {
      if (signal?.aborted) throw err;
      throw new ProtocolError('Could not retrieve the server public key');
    }
  }

  async function post(path, jsonValue, { headers, signal, credentials = 'same-origin' } = {}) {
    const url = checkedPath(path, parsed.origin);
    const body = JSON.stringify(jsonValue);
    if (body === undefined || body.length > maxPlaintextBytes) throw new TypeError('Invalid or oversized JSON input');
    const plaintext = encoder.encode(body);
    if (plaintext.length > maxPlaintextBytes) throw new TypeError('Invalid or oversized JSON input');

    const { kid, publicKey } = await getKey(signal);
    const bundle = randomBytes(32);
    const reqKey = bundle.subarray(0, 16);
    const respKey = bundle.subarray(16);
    try {
      const requestId = b64encode(randomBytes(16));
      const timestamp = Date.now();
      const iv = randomBytes(12);
      const wrappedKey = fromHex('04' + sm2.doEncrypt(bundle, publicKey, 1, { asn1: false }));
      if (wrappedKey.length !== 129) throw new ProtocolError('Unexpected SM2 key package');
      const aad = encoder.encode([PREFIX, 'REQ', kid, requestId, timestamp, 'POST', url.pathname].join('\n'));
      const encrypted = sm4.encrypt(plaintext, reqKey, { iv, associatedData: aad, mode: 'gcm', output: 'array' });
      reqKey.fill(0);
      plaintext.fill(0);
      const outgoing = new Headers(headers);
      outgoing.set('Content-Type', 'application/json');
      outgoing.set('Accept', 'application/json');
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: outgoing,
        cache: 'no-store',
        redirect: 'error',
        credentials,
        signal,
        body: JSON.stringify({
          version: 1, kid, requestId, timestamp, wrappedKey: b64encode(wrappedKey),
          iv: b64encode(iv), ciphertext: b64encode(encrypted.output), tag: b64encode(encrypted.tag),
        }),
      });
      try {
        const envelope = await readJson(response, maxEnvelopeBytes);
        if (envelope?.version !== 1 || envelope.requestId !== requestId) throw new ProtocolError();
        const responseAad = encoder.encode([PREFIX, 'RESP', requestId, response.status].join('\n'));
        const ciphertext = b64decode(envelope.ciphertext);
        if (ciphertext.length > maxPlaintextBytes) throw new ProtocolError();
        const output = sm4.decrypt(ciphertext, respKey, {
          mode: 'gcm', iv: b64decode(envelope.iv, 12), tag: b64decode(envelope.tag, 16),
          associatedData: responseAad, output: 'array',
        });
        return { status: response.status, ok: response.ok, data: JSON.parse(decoder.decode(output)) };
      } catch (err) {
        if (signal?.aborted) throw err;
        throw new ProtocolError();
      }
    } finally {
      bundle.fill(0);
      plaintext.fill(0);
    }
  }

  return { post };
}
