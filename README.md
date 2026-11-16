# SM Crypto Spring Boot Starter

在指定的 Spring MVC JSON POST 接口上启用 SM2 + SM4-GCM 应用层加密。SM2 只用于封装临时密钥，SM4-GCM 用于验证并加解密请求体和响应体。**仍须使用 HTTPS 和原有登录鉴权**。这不是 TLS 的替代品，也不能阻止浏览器使用者看到自己的明文。

## 下载和安装

先按宿主项目的 **Spring Boot 大版本**选 Starter，再按运行 **JDK** 选 JAR。两种 Starter 不要同时引入。同一个 Starter 的不同 JDK 构建共享 Maven 坐标，只安装与你运行时匹配的一个。

| 宿主 Spring Boot | 可下载 JDK | 下载 | Maven artifactId |
|---|---|---|---|
| 2.x / Servlet MVC（javax） | 8、11、17、21 | [Boot 2 JAR](dist/boot2) | `sm-crypto-spring-boot-starter` |
| 3.x / Servlet MVC（jakarta） | 17、21 | [Boot 3 JAR](dist/boot3) | `sm-crypto-spring-boot3-starter` |

各目录的 `SHA256SUMS` 可用于校验。它们是普通 Maven 依赖，不是独立应用。下面以 **JDK 17** 为例，先下载并安装需要的那一个：

```sh
# Spring Boot 2 项目：
mvn install:install-file -Dfile=dist/boot2/sm-crypto-spring-boot-starter-0.1.0-jdk17.jar -DpomFile=pom.xml

# Spring Boot 3 项目：
mvn install:install-file -Dfile=dist/boot3/sm-crypto-spring-boot3-starter-0.1.0-jdk17.jar -DpomFile=boot3/pom.xml
```

在宿主项目中使用相应的 artifactId。例如 Boot 3：

```xml
<dependency>
  <groupId>io.github.mrhjr</groupId>
  <artifactId>sm-crypto-spring-boot3-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

这两个版本均不支持 WebFlux、流式响应、上传、异步 Controller 或加密 URL/请求头。Boot 2 的包用于兼容旧项目；生产部署仍须确认宿主框架安全维护状态，不要为了使用这个 JAR 去降级。

## 后端接入

用已有的密钥管理流程生成 SM2 密钥对，配置后端私钥标量（32 字节、无填充 Base64URL）；不要提交生产私钥，不要让 Actuator 的 env/configprops 或配置诊断暴露密钥。不同应用和环境使用不同 SM2 密钥对。公开的 SM2 公钥由后端从私钥推导。配置示例：

```yaml
sm-crypto:
  enabled: true
  active-kid: key-1
  private-keys:
    key-1: ${SM_CRYPTO_KEY_1}
  paths:
    - /api/echo
  clock-skew: 2m
  max-body-bytes: 1048576
  replay-capacity: 10000
```

路径必须是加密过滤器看到的完整原始路径（包含 context path，如果配置了），且不带 query；不支持加密路由内部 forward。默认请求上限是整个加密信封的 1 MiB，实际可用 JSON 体积因 Base64URL 编码与信封开销而更小。不应部署在会把同一个加密 Controller 映射到未保护别名的配置中；推荐同时标记 `@EncryptedApi`。Controller 仍然收发普通 JSON DTO，不需要自己处理密钥。公钥端点 `GET /crypto/public-key` 默认返回 `kid` 和 `publicKey`；按需在现有安全配置中放行此端点，不放行受保护的业务端点。

内置去重存储只适合单实例。上线多实例之前提供共享的 `ReplayStore` 实现，在整个窗口内对 ID 做原子占用；同时保留业务自己的幂等键和生产限流。切换 `active-kid` 时，为旧请求保留旧私钥到公钥缓存和在途请求窗口结束。若网关能替换前端代码、公钥或窃取明文登录凭据，不要把这套协议当成对该网关的完整防护。协议不提供应用层前向保密，长期 SM2 私钥泄露时，之前截获的密文可能被解开。

## 浏览器接入

前端源码与测试在 [frontend](frontend)。使用打包器加载 SDK：

```js
import { createCryptoClient } from './frontend/client.js';

const cryptoClient = createCryptoClient({ origin: window.location.origin });
const { status, ok, data } = await cryptoClient.post('/api/echo', { message: '你好' });
```

SDK 经 HTTPS 取 SM2 公钥、短期缓存，每次请求再从客户端安全随机源生成两把 SM4 密钥。前端不持有长期 SM4 密钥或 SM2 私钥，不自动重试业务请求。在网关或容器错误、鉴权拦截及协议校验失败等未进入加密响应流程的场景，SDK 将响应视为协议失败，而不是可信的业务 JSON。

## 线上格式 v1

- 公钥是 Base64URL（无填充）的 65 字节非压缩 SM2 点（`04 || X || Y`）。`wrappedKey` 是 129 字节原始 C1C3C2（C1 含 `04`，非 ASN.1），解出 `K_req || K_resp`，每把 16 字节。
- SM4-GCM：12 字节 IV、16 字节标签。请求和响应使用不同的随机密钥与独立 IV。全部二进制字段采用规范的无填充 Base64URL。
- 请求：`{version,kid,requestId,timestamp,wrappedKey,iv,ciphertext,tag}`。版本为数字 1，`requestId` 为 16 字节随机数的 Base64URL，`timestamp` 为 Unix 毫秒。
- 响应：`{version,requestId,iv,ciphertext,tag}`。成功或业务错误都必须验标签后再读取内容。
- 请求 AAD：UTF-8 文本 `SMCRYPTO/1\nREQ\n<kid>\n<requestId>\n<timestamp>\n<method>\n<path>`；响应 AAD：`SMCRYPTO/1\nRESP\n<requestId>\n<status>`。没有末尾换行。

## 构建

```sh
mvn clean verify  # Boot 2
mvn -f boot3/pom.xml clean verify  # Boot 3（要求 JDK 17+）
npm --prefix frontend ci
npm --prefix frontend test
# 设置 JDK8_HOME、JDK11_HOME、JDK17_HOME、JDK21_HOME 后：
./scripts/build-jdk-matrix.sh
./scripts/build-boot3-matrix.sh
```

运行实际的 Java↔JavaScript 往返测试（本地回环、启动 Java 服务、临时生成测试密钥）：

```sh
./scripts/test-interop.sh boot2
./scripts/test-interop.sh boot3
```

### 本次验证

| Spring Boot | 运行 JDK | Java 测试 |
|---|---|---|
| 2.7.18 | 8、11、17、21 | 每版 27 项通过 |
| 2.6.3 | 8 | 27 项通过 |
| 3.5.16 | 17、21 | 每版 28 项通过 |

前端 4 项单元测试通过。Boot 2 和 Boot 3 都跑过 Java 服务与 JavaScript 客户端的真实 HTTP 联调，覆盖双向加解密、篡改拒绝、防重放，以及加密返回 HTTP 422 业务错误。Boot 3 的实测框架版本是 3.5.16，不代表已经验证所有 3.x 小版本。

Boot 3 模块通过 Maven 从同一份 Java 源码生成 Jakarta Servlet 版本，并使用自己的自动配置注册文件。`boot3/target` 是生成目录；修改通用协议、过滤器和测试时请改仓库根目录的源码，不要修改这个生成目录。
