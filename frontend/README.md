# 浏览器客户端

将 `client.js` 放进现有 Vue/React 等项目，让原有打包工具处理 ESM 和
`sm-crypto-v2` 依赖。本目录锁定依赖版本：

```sh
cd frontend
npm ci --ignore-scripts
npm test
```

```js
import { createCryptoClient, ProtocolError } from './client.js';

const client = createCryptoClient({ origin: window.location.origin });
try {
  const { status, ok, data } = await client.post('/demo/echo', { message: '你好' });
  // 即使 ok 为 false，能走到这里的 data 也已经通过认证。
  console.log(status, ok, data);
} catch (error) {
  if (error instanceof ProtocolError) {
    // 未经这层协议认证的响应不能当作业务结果，也不要自动重试提交。
  }
  throw error;
}
```

- `origin` 是受信任的 API 源；默认同源。公钥默认从同源的
  `/crypto/public-key` 获取，默认仅在内存缓存 60 秒。不跟随重定向。
- SDK 不负责登录。请求照常携带会话 Cookie，或通过
  `post(path, payload, { headers, signal })` 传已有认证头。如果跨源部署，
  另行配置 CORS，并明确选择凭证策略。
- 路径用服务端实际收到的完整路径（含 context path），不能带查询串、片段、
  重复斜线、尾斜线或路径转义。只支持 POST JSON。后端 0.2.0 启用后，除免加密白名单外的 POST 都应使用此 SDK；白名单中的 POST 和非 POST 继续用原有客户端。
- 只在本地测试服务器允许 `allowInsecureLoopback: true`；生产保留 HTTPS。
- 不把真实对称密钥写入前端代码、本地存储或日志。受信任的公钥也不是客户端身份凭证。

启动本项目的本地 Java 演示后，用同一个 JS 客户端做真实互操作检查：

```sh
npm --prefix frontend run interop -- http://127.0.0.1:18080 /demo/echo
```
