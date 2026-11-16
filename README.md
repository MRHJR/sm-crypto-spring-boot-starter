# SM Crypto Spring Boot Starter

为 Spring MVC 的 POST 接口提供 SM2 + SM4-GCM 应用层加密。SM2 只用于封装临时密钥，SM4-GCM 用于验证并加解密请求体和响应体。**仍须使用 HTTPS 和原有登录鉴权**。这不是 TLS 的替代品，也不能阻止浏览器使用者看到自己的明文。

## 下载和安装

当前版本是 **0.2.0**，旧的 0.1.0 JAR 仍留在原目录。先按宿主项目的 **Spring Boot 大版本**选 Starter，再按运行 **JDK** 选 JAR。两种 Starter 不要同时引入。同一个 Starter 的不同 JDK 构建共享 Maven 坐标，只安装与你运行时匹配的一个。

| 宿主 Spring Boot | 可下载 JDK | 下载 | Maven artifactId |
|---|---|---|---|
| 2.x / Servlet MVC（javax） | 8、11、17、21 | [Boot 2 JAR](dist/boot2) | `sm-crypto-spring-boot-starter` |
| 3.x / Servlet MVC（jakarta） | 17、21 | [Boot 3 JAR](dist/boot3) | `sm-crypto-spring-boot3-starter` |

各目录的 `SHA256SUMS` 可用于校验。它们是普通 Maven 依赖，不是独立应用。下面以 **JDK 17** 为例，先下载并安装需要的那一个：

```sh
# Spring Boot 2 项目：
mvn install:install-file -Dfile=dist/boot2/sm-crypto-spring-boot-starter-0.2.0-jdk17.jar -DpomFile=pom.xml

# Spring Boot 3 项目：
mvn install:install-file -Dfile=dist/boot3/sm-crypto-spring-boot3-starter-0.2.0-jdk17.jar -DpomFile=boot3/pom.xml
```

在宿主项目中使用相应的 artifactId。例如 Boot 3：

```xml
<dependency>
  <groupId>io.github.mrhjr</groupId>
  <artifactId>sm-crypto-spring-boot3-starter</artifactId>
  <version>0.2.0</version>
</dependency>
```

这两个版本均不支持 WebFlux、流式响应、上传、异步 Controller 或加密 URL/请求头。Boot 2 的包用于兼容旧项目；生产部署仍须确认宿主框架安全维护状态，不要为了使用这个 JAR 去降级。

## 后端接入

默认关闭。**设为 `sm-crypto.enabled: true` 后，所有经过本 Starter 的 Spring MVC POST 默认要求加密 JSON，只有免加密白名单 `exclude-paths` 里的 POST 继续走原来的明文请求和响应。** 不需要再为要加密的接口加注解或逐个列路径。

| 请求 | 启用后的行为 |
|---|---|
| POST，未列入白名单 | 要求加密 JSON 报文，明文或不支持的报文格式会被拒绝 |
| POST，列入白名单 | Starter 不处理加解密；原来的身份认证、权限校验等不受影响 |
| GET、HEAD、PUT、PATCH、DELETE、OPTIONS 等 | 不参与加解密，正常处理；`GET /crypto/public-key` 不需加入白名单 |

只支持 **POST JSON** 加密。上传、表单或其他不能走加密 JSON 的 POST 如果要继续使用，必须明确列入白名单。不要在加密过滤器前启用将 POST 改写为 PUT/PATCH/DELETE 的 HTTP 方法覆盖功能（例如 `HiddenHttpMethodFilter`）。白名单按完整原始路径精确匹配，有 context path 时要写进去；不支持通配符、查询串或尾斜杠（根路径 `/` 除外）。前端 SDK 使用未经转义的规范路径，不支持以 URL 参数传递待加密数据。例如：

```yaml
sm-crypto:
  enabled: true
  active-kid: key-1
  private-keys:
    key-1: "替换成生成的 SM2 私钥"
  exclude-paths:
    - /api/public/search
    - /api/files/upload
  clock-skew: 2m
  max-body-bytes: 1048576
  replay-capacity: 10000
```

### 配置项说明

下表适用于 Boot 2 和 Boot 3，配置项都写在 `sm-crypto:` 下。

| 配置项 | 含义 |
|---|---|
| `enabled: true` | 总开关，默认 `false`。设为 `true` 后，除免加密白名单之外，经过 Starter 的 POST 接口默认要求加密 JSON。其他 HTTP 方法不参与加解密。关闭时，显式标了 `@EncryptedApi` 的 POST 仍不会降级为明文。 |
| `active-kid: key-1` | 当前对前端发布的 SM2 密钥 ID，不是公钥或私钥内容。必须与 `private-keys` 中的某个条目名一致。前端通过公钥接口拿到这个 ID 和对应的公钥，并在加密请求中带上 ID。 |
| `private-keys` | 后端的私钥表，格式是 `密钥 ID: SM2 私钥`。`key-1` 是 ID，右边直接填写生成的私钥；值是 32 字节 SM2 私钥标量的无填充 Base64URL 编码，不是 PEM。后端从私钥推导公钥，私钥永远不会下发。换钥时可暂留旧条目处理在途请求。 |
| `exclude-paths` | 免加密的 POST 白名单，默认空。按完整请求路径精确匹配，包含 context path，不填查询参数，不支持通配符。例如 `/api/files/upload` 命中后，该接口沿用原方式处理请求和响应，不影响鉴权。 |
| `clock-skew: 2m` | 客户端请求时间戳与服务器时间允许相差的最大值，默认前后各 2 分钟。比服务器时间早或晚超过 2 分钟都拒绝，允许范围为 `1ms` 到 `15m`。它不是 HTTP 请求超时时间。 |
| `max-body-bytes: 1048576` | 体积限制，单位是字节，默认 1 MiB，可配 1 KiB 至 8 MiB。请求侧限制的是收到的整个加密 JSON 信封；响应侧限制的是加密前的响应体。请求侧因 Base64URL 和报文开销，可用的明文 JSON 小于 1 MiB。 |
| `replay-capacity: 10000` | 单实例内置防重放缓存最多同时保留多少个已接受、尚未过期的请求 ID，默认 10,000，可配 1 到 1,000,000。重复 ID 会被拒绝；缓存满时不会提前淘汰未过期 ID，而是拒绝新请求。多实例应使用共享 `ReplayStore`，容量由该实现管理。 |

`enabled` 和白名单在启动时读取，改配置后须重启。受保护的 Controller 仍然收发普通 JSON DTO，默认请求上限是整个加密信封的 1 MiB；因 Base64URL 和信封开销，可用 JSON 体积会更小。前端取公钥不携带登录凭据，宿主的 Spring Security 应允许访问准确的 `GET /crypto/public-key`，不要因此放行业务接口。有 context path 或 MVC 路径前缀时，在 SDK 的 `publicKeyPath` 填写完整公钥路径。若请求在更早的安全过滤器里就已处理，不会进入 Starter。

- **升级 0.1.0 → 0.2.0**：删除旧的 `sm-crypto.paths` 配置，再明确列出仍需走明文的 POST；启用时若仍配置旧项，应用会提示迁移而不是静默扩大范围。上线前确认所有应加密的 POST 调用方已接入 SDK。
- **`@EncryptedApi`**：非必需。如果 POST 仍标有这个注解，关掉总开关时该接口仍拒绝明文；如果又把它列入免加密白名单，则视作配置冲突并拒绝请求。需要豁免时，先去掉对应的标记。

后端私钥标量必须来自可信的密钥管理流程（32 字节、无填充 Base64URL）。不要提交生产私钥，不要让 Actuator 的 env/configprops 或配置诊断暴露密钥。不同应用和环境使用不同 SM2 密钥对。公开的 SM2 公钥由后端从私钥推导。

内置去重存储只适合单实例。上线多实例之前提供共享的 `ReplayStore` 实现，在整个窗口内对 ID 做原子占用；同时保留业务自己的幂等键和生产限流。切换 `active-kid` 时，为旧请求保留旧私钥到公钥缓存和在途请求窗口结束。若网关能替换前端代码、公钥或窃取明文登录凭据，不要把这套协议当成对该网关的完整防护。协议不提供应用层前向保密，长期 SM2 私钥泄露时，之前截获的密文可能被解开。

### SM2 私钥配置示例

**1. 生成私钥。** 如果电脑装了 Python 3，在 Windows PowerShell 运行下面这一行，复制它输出的 43 个字符。Linux / macOS 把开头的 `py -3` 换成 `python3` 即可。

```powershell
py -3 -c "import base64,secrets;n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123;print(base64.urlsafe_b64encode((secrets.randbelow(n-1)+1).to_bytes(32,'big')).decode().rstrip('='))"
```

**2. 直接填到本机的 YAML。** 把输出粘到 `private-keys.key-1`，保留引号，然后重启业务应用：

```yaml
sm-crypto:
  enabled: true
  active-kid: key-1
  private-keys:
    key-1: "替换成上面生成的私钥"
```

`key-1` 是可以自定义的名字，改名时两处都要改。私钥只生成一次，不要用随手输入的字符串代替，也不要每次启动都重新生成。配置文件留在本机或服务器，不提交 Git、不打进 JAR。启动后访问 `GET /crypto/public-key`，应看到 `kid` 和自动生成的 `publicKey`，不会返回私钥。

## 浏览器接入

前端源码与测试在 [frontend](frontend)。普通 GET 等请求和白名单内的明文 POST 继续用原有客户端；其他 POST 用此 SDK，不要遇到失败就回退到明文。使用打包器加载 SDK：

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
| 2.7.18 | 8、11、17、21 | 每版 32 项通过 |
| 2.6.3 | 8 | 32 项通过 |
| 3.5.16 | 17、21 | 每版 33 项通过 |

前端 5 项单元测试通过。Boot 2 和 Boot 3 都跑过 Java 服务与 JavaScript 客户端的真实 HTTP 联调，覆盖双向加解密、篡改拒绝、防重放、加密返回 HTTP 422 业务错误，以及默认 POST 拒绝明文、白名单 POST 放行、普通 GET 不受影响。Boot 3 的实测框架版本是 3.5.16，不代表已经验证所有 3.x 小版本。

Boot 3 模块通过 Maven 从同一份 Java 源码生成 Jakarta Servlet 版本，并使用自己的自动配置注册文件。`boot3/target` 是生成目录；修改通用协议、过滤器和测试时请改仓库根目录的源码，不要修改这个生成目录。
