import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sm2, sm4 } from 'sm-crypto-v2';
import * as sdk from '../client.js';

const serverPair = sm2.generateKeyPairHex();
const b64 = (value) => Buffer.from(value).toString('base64url');
const b64decode = (value) => Uint8Array.from(Buffer.from(value, 'base64url'));
const utf8 = (value) => new TextEncoder().encode(value);
const json = (value, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });

function mockServer(handler, { tamper = false, wrongStatus = false, failed = false, responseStatus = 200 } = {}) {
  const calls = [];
  const ids = new Set();
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    if (url.pathname === '/crypto/public-key') {
      return json({ kid: 'test-v1', publicKey: b64(Buffer.from(serverPair.publicKey, 'hex')) });
    }
    const envelope = JSON.parse(options.body);
    assert.equal(envelope.version, 1);
    assert.equal(envelope.kid, 'test-v1');
    assert.equal(b64decode(envelope.requestId).length, 16);
    assert(Number.isSafeInteger(envelope.timestamp));
    assert.equal(ids.has(envelope.requestId), false);
    ids.add(envelope.requestId);
    const keyCipher = b64decode(envelope.wrappedKey);
    assert.equal(keyCipher.length, 129);
    assert.equal(keyCipher[0], 4);
    const keys = sm2.doDecrypt(Buffer.from(keyCipher.subarray(1)).toString('hex'),
      serverPair.privateKey, 1, { output: 'array' });
    assert.equal(keys.length, 32);
    assert.notDeepEqual(keys.slice(0, 16), keys.slice(16));
    const plain = sm4.decrypt(b64decode(envelope.ciphertext), keys.slice(0, 16), {
      mode: 'gcm', iv: b64decode(envelope.iv), tag: b64decode(envelope.tag),
      associatedData: utf8(['SMCRYPTO/1', 'REQ', envelope.kid, envelope.requestId,
        envelope.timestamp, options.method, url.pathname].join('\n')), output: 'array',
    });
    const request = JSON.parse(new TextDecoder().decode(plain));
    const payload = handler(request);
    if (failed) return json({ error: 'unauthenticated plaintext' }, 400);
    const status = wrongStatus ? 201 : responseStatus;
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const result = sm4.encrypt(utf8(JSON.stringify(payload)), keys.slice(16), {
      mode: 'gcm', iv, associatedData: utf8(['SMCRYPTO/1', 'RESP', envelope.requestId, status].join('\n')),
      output: 'array',
    });
    if (tamper) result.tag[0] ^= 1;
    return json({ version: 1, requestId: envelope.requestId, iv: b64(iv),
      ciphertext: b64(result.output), tag: b64(result.tag) }, responseStatus);
  };
  return { fetchImpl, calls };
}

test('remote server can unwrap request; client verifies and decodes response over new keys', async () => {
  assert.equal(typeof sdk.createCryptoClient, 'function');
  const { fetchImpl, calls } = mockServer(({ message }) => ({ message, ok: true }));
  const client = sdk.createCryptoClient({ origin: 'https://api.example.test', fetchImpl });
  assert.deepEqual(await client.post('/demo/echo', { message: '联调 ✅' }),
    { status: 200, ok: true, data: { message: '联调 ✅', ok: true } });
  await client.post('/demo/echo', { message: '第二次' });
  assert.equal(calls.filter(({ url }) => url.pathname === '/crypto/public-key').length, 1);
  assert(calls.every(({ options }) => options.redirect === 'error' && options.cache === 'no-store'));
  assert.equal(calls[1].options.body.includes('联调'), false);
});

test('rejects plaintext, a changed tag, and a changed status without retrying', async () => {
  assert.equal(typeof sdk.createCryptoClient, 'function');
  for (const mode of [{ failed: true }, { tamper: true }, { wrongStatus: true }]) {
    const { fetchImpl, calls } = mockServer((request) => request, mode);
    const client = sdk.createCryptoClient({ origin: 'https://api.example.test', fetchImpl });
    await assert.rejects(client.post('/demo/echo', { message: 'secret' }), { name: 'ProtocolError' });
    assert.equal(calls.filter(({ options }) => options.method === 'POST').length, 1);
  }
});

test('rejects insecure non-loopback origins, query strings and cross-origin paths before sending', async () => {
  assert.equal(typeof sdk.createCryptoClient, 'function');
  const fetchImpl = () => assert.fail('no request should be sent');
  assert.throws(() => sdk.createCryptoClient({ origin: 'http://api.example.test', fetchImpl }));
  const client = sdk.createCryptoClient({ origin: 'https://api.example.test', fetchImpl });
  for (const path of ['/demo/echo?x=1', '//other.example.test/api', '/a/../demo/echo', '/demo/echo#x',
    '/demo//echo', '/demo/echo/', '/demo/%65cho', '/demo/echo;foo', '/' + 'a'.repeat(1024)]) {
    await assert.rejects(client.post(path, {}), TypeError);
  }
});

test('exposes authenticated business errors and preserves existing authentication', async () => {
  const { fetchImpl, calls } = mockServer(() => ({ code: 'BUSINESS_ERROR' }), { responseStatus: 422 });
  const client = sdk.createCryptoClient({ origin: 'https://api.example.test', fetchImpl });
  assert.deepEqual(await client.post('/demo/echo', {}, { headers: { Authorization: 'Bearer test-only' } }),
    { status: 422, ok: false, data: { code: 'BUSINESS_ERROR' } });
  assert.equal(calls[1].options.headers.get('Authorization'), 'Bearer test-only');
  assert.equal(calls[0].options.credentials, 'omit');
});

test('supports an encrypted POST on the canonical root path', async () => {
  const { fetchImpl, calls } = mockServer((request) => request);
  const client = sdk.createCryptoClient({ origin: 'https://api.example.test', fetchImpl });
  const payload = { message: 'root' };
  assert.deepEqual(await client.post('/', payload), { status: 200, ok: true, data: payload });
  assert.equal(calls[1].url.pathname, '/');
});
