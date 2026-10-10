# Caddy 反向代理配置

## 目的

本文档说明如何用 Caddy 把 `https://link.sast.fun` 分流给本服务与前端，以及第三方 OAuth 绑定回调为何需要一条特例规则。

## 前置事实

本服务的所有路由都注册在**根路径**上。`internal/web/router.go` 创建的是裸 `gin.Engine`，没有任何 `Group`，四个 handler 包注册的都是绝对路径。也就是说进程实际服务的是：

```
POST /user/login
GET  /oauth/github/callback
POST /user/identities/github
GET  /health
```

外部可见的 `/v2` 前缀完全由本反代提供。`JWT_ISSUER`（默认 `https://link.sast.fun/v2`）是 token 的 `iss` claim，同时也是 OIDC discovery 文档拼接 endpoint URL 的基址——两者必须与反代对外呈现的地址一致，否则符合规范的 relying party 会拒绝本服务签发的每一个 ID Token。

因此转发给后端时**必须剥掉 `/v2`**，用 `handle_path` 而不是 `handle`。

## Caddyfile

```caddy
link.sast.fun {
 encode zstd gzip

 # /metrics 只允许内网抓取：匿名公网可达会暴露路由清单、每路由 QPS/延迟
 # 与错误分布（撞库与限流探测的地图）。与 /v2/debug 同一道路径级防线；
 # 抓取走 SSH 本地转发或内网监听，不经过公网路径。单路径 matcher 比
 # /v2/* 更具体，Caddy 排序保证先命中。
 handle /v2/metrics {
  respond 404
 }

 # 其余 /v2/* 是 API。handle_path 会剥掉 /v2 前缀，后端收到的是
 # /oauth/github/callback 这样的根路径。
 handle_path /v2/* {
  reverse_proxy api:8080
 }

 # 其余一切归前端。
 handle {
  reverse_proxy frontend:3000
 }
}
```

### 生产部署：宿主 Caddy

生产机上 Caddy 是宿主的 systemd 进程，不在容器网络内，上游地址必须写成宿主可达的 `127.0.0.1:8080` / `127.0.0.1:3000`，而不是 compose 网络名 `api:8080` / `frontend:3000`。

- 后端限流与登录失败计数按 IP 分桶，反代不传真实客户端 IP 时全站共用一个桶：Caddy 侧转发 `X-Forwarded-For`，服务侧把代理网段配入 `TRUSTED_PROXIES`（见 `.env.example`）。
- `/v2/debug/*`（pprof）在反代层额外钉一道 `respond 404`：`PPROF_ENABLED` 是进程内开关，一次误配即公网暴露，路径级拒绝是与开关取值无关的第二道防线；需要用时走 SSH 本地转发，不经过公网路径。
- `/v2/metrics`（Prometheus）同样钉 `respond 404`：代码侧匿名暴露是刻意的（抓取不携带凭据），但 /health 只泄露存活，/metrics 泄露的是路由清单与流量画像，风险不对等；监控改从内网或 SSH 隧道抓取（上游仍指向 `127.0.0.1:8080`）。

### 为什么这个顺序是可靠的

Caddy 的 `handle` 块是**互斥**的——只有第一个匹配的块会被执行。但「第一个」不是按文件里的书写顺序，而是按 Caddy 自己的 directive 排序算法：同名 directive 先按 matcher 排，带单个路径 matcher 的优先级最高，并且**按路径长度从最具体到最不具体**排序。

官方给出的例子：`/foobar` 比 `/foo` 更具体；`/foo` 比 `/foo*` 更具体；`/foo/*` 比 `/foo*` 更具体。

所以 `/v2/metrics` 一定排在 `/v2/*` 之前，无 matcher 的 `handle` 排在最后。上面的书写顺序与实际生效顺序一致，便于阅读，但即使调换书写顺序行为也不变——不依赖书写顺序是这个方案可靠的原因。

如果确实需要强制按书写顺序执行，用 `route` 块包裹：`route` 内部忽略全部排序，严格按字面顺序运行。这里不需要。

## GitHub OAuth App 的回调注册

| 用途 | 地址 | 由谁处理 |
|------|------|----------|
| 登录回调 | `https://link.sast.fun/v2/oauth/github/callback` | 后端（`handle_path /v2/*` 剥前缀） |
| 绑定回调 | `https://link.sast.fun/oauth/bind/github` | 前端页面（不带 `/v2`，落兜底 `handle` 归前端，无需代理特判） |

GitHub OAuth App 注册两条精确回调，wildcard matching 关闭：

```
Authorization callback URL:
  https://link.sast.fun/v2/oauth/github/callback   (登录)
  https://link.sast.fun/oauth/bind/github          (绑定)
```

关闭 wildcard 后 redirect_uri 必须与某条注册值**完全相等**（host、端口、路径逐字比对），授权码只可能落到这两条路径。GitHub 支持注册多条 callback URL，未显式传 redirect_uri 时回落到第一条。飞书侧的登录/绑定两条地址登记在 Lark 开放平台的重定向白名单，同为精确匹配。

绑定回调不带 `/v2` 前缀是刻意的：它落在代理的兜底规则里，任何 `/v2` 之外的路径都直归前端，因此不需要为它维护代理特判。

## 本地开发不需要反代

本地后端在 `:8080`、前端在 `:3000`，端口不同，因此无法像生产那样靠「同为 443」满足 GitHub 的端口精确匹配。改用 GitHub 为 loopback 地址提供的例外：callback 注册为 `http://127.0.0.1/path` 时，实际 `redirect_uri` **不需要匹配端口**。

```
Authorization callback URL: http://127.0.0.1/oauth
```

**已实测可用**，覆盖两条回调：

| 用途 | 地址 | 端口 | 路径 |
|------|------|------|------|
| 登录回调 | `http://127.0.0.1:8080/oauth/github/callback` | 豁免 | 在 `/oauth` 之下 |
| 绑定页 | `http://127.0.0.1:3000/oauth/bind/github` | 豁免 | 在 `/oauth` 之下 |

两点必须注意：

- **写 `127.0.0.1`，不要写 `localhost`。** 该例外只对字面的 loopback 地址成立，`localhost` 拿不到端口豁免。
- **路径规则依然生效。** 端口被豁免，路径不被豁免，所以两条回调仍然要落在注册路径 `/oauth` 之下。

这个端口豁免**仅限本地**；生产是两条精确回调、无 wildcard（见上节）。本地的绑定页与生产同路径布局（`/oauth/bind/github`），切换环境只改 host 与端口。

## 对应的环境变量

生产：

```bash
OAUTH_GITHUB_ENABLED=true
OAUTH_GITHUB_CLIENT_ID=<Client ID>
OAUTH_GITHUB_CLIENT_SECRET=<Generate 出来的值>
# 外部可达地址，含反代前缀。GitHub 从公网访问它，且在 token 交换阶段
# （RFC 6749 §4.1.3）比对同一个字符串，因此不能填 api:8080 这类内网地址。
OAUTH_GITHUB_REDIRECT_URI=https://link.sast.fun/v2/oauth/github/callback

# 后端回调完成后可 302 到的前端地址，精确匹配，逗号分隔可多条。
# 这个值不注册进 provider——provider 从不看它。
OAUTH_LOGIN_REDIRECTS=https://link.sast.fun/oauth/callback
OAUTH_LOGIN_ERROR_REDIRECT=https://link.sast.fun/oauth/error
```

本地（无反代，故不带 `/v2`）：

```bash
OAUTH_GITHUB_REDIRECT_URI=http://127.0.0.1:8080/oauth/github/callback
OAUTH_LOGIN_REDIRECTS=http://127.0.0.1:3000/oauth/callback
OAUTH_LOGIN_ERROR_REDIRECT=http://127.0.0.1:3000/oauth/error
# 前端绑定页，服务端不读取，由前端作为 redirect_uri 参数回传
OAUTH_GITHUB_BIND_REDIRECT_URI=http://127.0.0.1:3000/oauth/bind/github
```

前端绑定页在调用 `POST /v2/user/identities/github` 时，需要把 `redirect_uri=https://link.sast.fun/oauth/bind/github` 作为 query 参数一并传入——RFC 6749 §4.1.3 要求 token 交换重复签发 code 时使用的那个回调地址。省略时后端会回退到 `OAUTH_GITHUB_REDIRECT_URI`，那是登录回调，与绑定 code 不匹配，provider 会以 `invalid_grant` 拒绝。

## 验证

配置生效后逐项确认：

```bash
# 1. /v2 被剥掉，后端的根路径路由可达
curl -s https://link.sast.fun/v2/health
# 期望 {"status":"ok","db":"ok","redis":"ok"}

# 2. discovery 文档里的 issuer 与 endpoint 都带 /v2
curl -s https://link.sast.fun/v2/.well-known/openid-configuration | jq '.issuer, .token_endpoint'
# 期望 "https://link.sast.fun/v2" 与 "https://link.sast.fun/v2/oauth/token"

# 3. 绑定路径走前端（兜底规则），不是后端的 404
curl -sI https://link.sast.fun/oauth/bind/github | head -1
# 期望前端返回的 200，而非后端 JSON 形态的 404

# 4. 登录跳转可用（authorize 必带 S256 code_challenge，缺参得 400）
curl -s -o /dev/null -w '%{redirect_url}'   "https://link.sast.fun/v2/oauth/github?code_challenge=<任意S256摘要>&code_challenge_method=S256"
# 期望 302 至 github.com/login/oauth/authorize，且 redirect_uri 为 /v2/oauth/github/callback

# 5. /v2/metrics 被代理层拦截
curl -sI https://link.sast.fun/v2/metrics | head -1
# 期望 404
```

第 3 项验证兜底规则确实接管了绑定页；第 5 项验证 metrics 拦截生效。


## 参考

- [Caddyfile handle 指令](https://caddyserver.com/docs/caddyfile/directives/handle)
- [Caddyfile directive 排序算法](https://caddyserver.com/docs/caddyfile/directives#directive-order)
- [GitHub OAuth 回调 URL 匹配规则](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
