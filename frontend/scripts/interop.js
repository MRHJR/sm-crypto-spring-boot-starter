import assert from 'node:assert/strict';
import { createCryptoClient, ProtocolError } from '../client.js';

// Run only against the built-in demo or a disposable local echo server, never production.
const [, , originInput = 'http://127.0.0.1:8080', path = '/demo/echo', keyPath = '/crypto/public-key'] = process.argv;
const origin = new URL(originInput);
if (!['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname)) {
  throw new Error('This test driver only targets a local echo server');
}

let recorded;
const client = createCryptoClient({
  origin: originInput,
  publicKeyPath: keyPath,
  allowInsecureLoopback: true,
  fetchImpl(url, options) {
    if (options.method === 'POST') recorded = { url, options };
    return fetch(url, { ...options, signal: AbortSignal.timeout(8_000) });
  },
});

const message = 'SM2 + SM4-GCM 双向联调';
const { ok, data } = await client.post(path, { message });
assert(ok, 'The echo request should succeed');
assert.equal(data.message, message);

const replay = await fetch(recorded.url, { ...recorded.options, signal: AbortSignal.timeout(8_000) });
assert.equal(replay.ok, false, 'The endpoint must reject duplicate requests');
await replay.body?.cancel();

const tamperClient = createCryptoClient({
  origin: originInput,
  publicKeyPath: keyPath,
  allowInsecureLoopback: true,
  fetchImpl(url, options) {
    if (options.method !== 'POST') return fetch(url, { ...options, signal: AbortSignal.timeout(8_000) });
    const envelope = JSON.parse(options.body);
    const tag = Buffer.from(envelope.tag, 'base64url');
    tag[0] ^= 1;
    envelope.tag = tag.toString('base64url');
    return fetch(url, { ...options, body: JSON.stringify(envelope), signal: AbortSignal.timeout(8_000) });
  },
});
await assert.rejects(tamperClient.post(path, { message }), ProtocolError);
console.log('PASS: Java ↔ JS double-direction encryption, replay rejection, and tag-tamper rejection');
