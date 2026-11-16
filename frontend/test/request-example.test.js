import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequest } from '../examples/request.js';

function setup(overrides = {}) {
  const calls = [];
  const result = { status: 422, ok: false, data: { code: 'INVALID' } };
  const request = createRequest({
    axiosClient: { request: async config => {
      calls.push(['axios', config]);
      return { status: 200, data: { plain: true } };
    } },
    cryptoClient: { post: async (...args) => {
      calls.push(['crypto', ...args]);
      return result;
    } },
    enabled: true,
    excludePaths: ['/api/files/upload', '/api/public/**'],
    ...overrides,
  });
  return { request, calls, result };
}

test('default POST uses the SDK, propagates auth and returns authenticated business errors', async () => {
  const { request, calls, result } = setup({ getCryptoHeaders: () => ({ Authorization: 'Bearer test' }) });
  const data = { orderId: 123 };
  const signal = new AbortController().signal;
  assert.equal(await request({ url: '/api/orders/save', method: 'post', data, signal }), result);
  assert.deepEqual(calls.map(call => call[0]), ['crypto']);
  assert.deepEqual(calls[0].slice(1, 3), ['/api/orders/save', data]);
  assert.equal(calls[0][3].headers.get('authorization'), 'Bearer test');
  assert.equal(calls[0][3].signal, signal);
});

test('non-POST and excluded POST use Axios, with exact and segment-prefix matching', async () => {
  const { request, calls } = setup();
  const upload = new FormData();
  await request({ url: '/api/orders', params: { page: 1 } });
  await request({ url: '/api/files/upload', method: 'POST', data: upload });
  await request({ url: '/api/public', method: 'POST' });
  await request({ url: '/api/public/search', method: 'POST' });
  await request({ url: '/api/publicity', method: 'POST', data: {} });
  await request({ url: '/api/files/upload/child', method: 'POST', data: {} });
  assert.deepEqual(calls.map(call => call[0]), ['axios', 'axios', 'axios', 'axios', 'crypto', 'crypto']);
  assert.equal(calls[1][1].data, upload);
});

test('disabled mode uses Axios for POST without SDK', async () => {
  const { request, calls } = setup({ enabled: false, cryptoClient: undefined });
  const response = await request({ url: '/api/orders/save', method: 'POST', data: {} });
  assert.deepEqual(calls.map(call => call[0]), ['axios']);
  assert.deepEqual(response, { status: 200, ok: true, data: { plain: true } });
});

test('invalid protected paths and request options are rejected before either transport', async () => {
  const { request, calls } = setup();
  for (const url of ['/api/public/../orders', '/api/public%2fsearch', '//host/api/public', '/api/public\n']) {
    await assert.rejects(request({ url, method: 'POST', data: {} }), TypeError);
  }
  await assert.rejects(request({ url: '/api/orders/save', method: 'POST', params: { x: 1 }, data: {} }), TypeError);
  await assert.rejects(request({ url: '/api/orders/save', method: 'POST', data: new FormData() }), TypeError);
  assert.equal(calls.length, 0);
});

test('rejects unsafe exclusion rules', () => {
  for (const rule of ['/**', '/api/*', '/api/public/**/x', '/api/public//**']) {
    assert.throws(() => setup({ excludePaths: [rule] }), TypeError);
  }
});

test('SDK failure is never retried in plaintext', async () => {
  const error = new Error('protocol failure');
  const { request, calls } = setup({ cryptoClient: { post: async () => { throw error; } } });
  await assert.rejects(request({ url: '/api/orders/save', method: 'POST', data: {} }), e => e === error);
  assert.deepEqual(calls, []);
});
