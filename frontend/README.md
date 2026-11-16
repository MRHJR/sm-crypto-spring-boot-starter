# 前端接入指南

这是浏览器端的接入方式，适用于 Vue、React 等使用 Axios 的项目。后端只需正常收发 JSON DTO。

## 1. 安装依赖并复制文件

在**你的前端项目**里执行（已有 Axios 就继续用现有版本）：

```sh
npm install --save-exact sm-crypto-v2@2.0.1
```

- 把 [`client.js`](client.js) 复制到 `src/utils/sm-crypto-client.js`，交给现有打包工具加载。
- 把 [`examples/request.js`](examples/request.js) 复制到 `src/utils/create-request.js`。它是分流示例，可合并到你现有的 `request.js`，不用再造一套业务 API。

## 2. 在 request.js 配一次开关和免加密清单

下面是同源部署示例。已有 Axios 实例时直接复用，保证它返回完整响应（含 `status` 和 `data`），而不是已经拆出的 `response.data`。已有统一的返回值或错误处理约定时，在这里适配，业务页面不需要各自处理 SDK。

```js
import axios from 'axios';
import { createCryptoClient } from './sm-crypto-client.js';
import { createRequest } from './create-request.js';

const enabled = true; // 要和后端 sm-crypto.enabled 同步部署
const origin = window.location.origin;
const api = axios.create({ baseURL: origin }); // 实际项目可换成现有 Axios 实例
const cryptoClient = enabled ? createCryptoClient({ origin }) : undefined;

export default createRequest({
  axiosClient: api,
  cryptoClient,
  enabled,
  // 只列免加密的 POST，与后端 sm-crypto.exclude-paths 保持一致。
  excludePaths: ['/api/files/upload', '/api/public/**'],
});
```

- **开启：**非 POST 走 Axios；白名单里的 POST 也走 Axios；其余 POST 自动走 SDK，无需登记。
- **关闭：**所有请求沿用 Axios。后端如果仍显式标记了 `@EncryptedApi`，这些 POST 仍拒绝明文。
- `/api/public/**`（后端 0.3.0 起）匹配 `/api/public` 和其子路径，不匹配 `/api/publicity`。白名单只免加解密，不免登录。上传、表单等非 JSON 的 POST 如要保留，须明确加入白名单。
- 用 Token 登录时，SDK 自己用 `fetch`，**不会走 Axios 请求拦截器**。从现有登录逻辑取认证头：在上面配置 `getCryptoHeaders: () => ({ Authorization: 'Bearer ' + getToken() })`（`getToken` 换成项目自己的方法），或调用时传 `headers`。如果项目用其他 Header 名称，沿用原名称。同源 Cookie 默认携带。
- 前后端不同源时，`origin` 填可信的 HTTPS API 源，不能带路径；两边分别配好 CORS 和现有凭证策略。用跨源 Cookie 时给 SDK 请求传 `credentials: 'include'`，Axios 分支则配置现有 Axios 实例的 `withCredentials`。
- SDK 默认从 `GET /crypto/public-key` 取 `kid` 和公钥，短期缓存。如果路径含前缀，在 `createCryptoClient` 传入 `publicKeyPath`（如 `/app/crypto/public-key`）。两条分流的实际路径应与后端看到的路径一致；加密 POST 的 URL 写完整路径（如 `/app/api/orders/save`），不要在 Axios 里另拼前缀，也不要把待加密数据写进查询串。

## 3. 业务照常调用 request.js

```js
import request from './utils/request.js';

const { status, ok, data } = await request({
  url: '/api/orders/save',
  method: 'POST',
  data: { orderId: 123 },
});
```

这个例子里，新增 `/api/orders/save` 不需要修改 `request.js`；只有接口需要**免加密**时才调整前后端白名单。加密 POST 传普通 JSON，别传 `FormData` 或 `params`。SDK 成功验密后，业务错误（例如 HTTP 422）也会作为 `{ status, ok: false, data }` 返回，由业务处理。未通过加密协议校验的响应会抛出 `ProtocolError`，不能当业务 JSON 读取；也不要因此明文重发。Axios 分支保留现有 Axios 的 HTTP 错误行为。

## 密钥从哪来

每次加密 POST，SDK 生成两把临时 SM4 密钥，一把加密请求，一把解密响应。两把都用后端 SM2 公钥保护后随请求发送；后端用自己的 SM2 私钥解开。前端留在内存里的响应密钥用于解密这一笔响应，不需要再请求后端，也不写进代码、本地存储或日志。生产环境继续使用 HTTPS。

## 在 Starter 仓库运行前端测试

```sh
cd frontend
npm ci --ignore-scripts
npm test
```

启动本项目的本地 Java 演示后，可跑真实 HTTP 联调：

```sh
npm --prefix frontend run interop -- http://127.0.0.1:18080 /demo/echo
```
