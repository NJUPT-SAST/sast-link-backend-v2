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

	# 第三方绑定回调必须先于 /v2/* 声明其意图：它是前端页面，不是 API 路由。
	# 后端没有 /oauth/bind/* 这个路由，落到后端只会得到 404。
	handle /v2/oauth/bind/* {
		reverse_proxy frontend:3000
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

### 为什么这个顺序是可靠的

Caddy 的 `handle` 块是**互斥**的——只有第一个匹配的块会被执行。但「第一个」不是按文件里的书写顺序，而是按 Caddy 自己的 directive 排序算法：同名 directive 先按 matcher 排，带单个路径 matcher 的优先级最高，并且**按路径长度从最具体到最不具体**排序。

官方给出的例子：`/foobar` 比 `/foo` 更具体；`/foo` 比 `/foo*` 更具体；`/foo/*` 比 `/foo*` 更具体。

所以 `/v2/oauth/bind/*` 一定排在 `/v2/*` 之前，无 matcher 的 `handle` 排在最后。上面的书写顺序与实际生效顺序一致，便于阅读，但即使调换书写顺序行为也不变——不依赖书写顺序是这个方案可靠的原因。

如果确实需要强制按书写顺序执行，用 `route` 块包裹：`route` 内部忽略全部排序，严格按字面顺序运行。这里不需要。

## GitHub OAuth App 的回调注册

这条特例规则的目的是让登录与绑定两个回调**共享一个已注册的父路径**。

| 用途 | 地址 | 由谁处理 |
|------|------|----------|
| 登录回调 | `https://link.sast.fun/v2/oauth/github/callback` | 后端（反代剥前缀） |
| 绑定回调 | `https://link.sast.fun/v2/oauth/bind/github` | 前端页面 |

GitHub OAuth App 只允许注册**一条** Authorization callback URL，匹配规则是：host（不含子域）与端口必须精确相等，请求路径必须是已注册路径的**子目录**。官方示例表中，注册 `http://example.com/path` 时 `http://example.com/` 会被拒绝——所以是「等于或位于其下」，不是「同 host 即可」。

把绑定页放进 `/v2/oauth/bind/` 后，两条回调的公共父路径是 `/v2/oauth`，于是注册：

```
Authorization callback URL: https://link.sast.fun/v2/oauth
```

两条回调都明确是它的子目录，落在文档给出的示例形状内。

**不要注册根路径 `https://link.sast.fun`。** GitHub 的文档没有为「注册值本身是根路径」给出任何示例或文字说明，按规则字面推断似乎可行，但这属于未承诺的行为。此外根路径注册意味着该域下**任何**路径都能接收授权码，范围远大于必要。

飞书没有这个限制，其重定向 URL 支持配置多条，把登录与绑定两条地址都填进去即可；不过与 GitHub 保持同一套路径布局可以减少两边配置的差异。

## 对应的环境变量

```bash
OAUTH_GITHUB_ENABLED=true
OAUTH_GITHUB_CLIENT_ID=<Client ID>
OAUTH_GITHUB_CLIENT_SECRET=<Generate 出来的值>
# 外部可达地址，含反代前缀。GitHub 从公网访问它，且在 token 交换阶段
# （RFC 6749 §4.1.3）比对同一个字符串，因此不能填 api:8080 这类内网地址。
OAUTH_GITHUB_REDIRECT_URI=https://link.sast.fun/v2/oauth/github/callback

# 后端回调完成后可 302 到的前端地址，精确匹配，逗号分隔可多条。
OAUTH_LOGIN_REDIRECTS=https://link.sast.fun/oauth/callback
OAUTH_LOGIN_ERROR_REDIRECT=https://link.sast.fun/oauth/error
```

前端绑定页在调用 `POST /v2/user/identities/github` 时，需要把 `redirect_uri=https://link.sast.fun/v2/oauth/bind/github` 作为 query 参数一并传入——RFC 6749 §4.1.3 要求 token 交换重复签发 code 时使用的那个回调地址。省略时后端会回退到 `OAUTH_GITHUB_REDIRECT_URI`，那是登录回调，与绑定 code 不匹配，provider 会以 `invalid_grant` 拒绝。

## 验证

配置生效后逐项确认：

```bash
# 1. /v2 被剥掉，后端的根路径路由可达
curl -s https://link.sast.fun/v2/health
# 期望 {"status":"ok","db":"ok","redis":"ok"}

# 2. discovery 文档里的 issuer 与 endpoint 都带 /v2
curl -s https://link.sast.fun/v2/.well-known/openid-configuration | jq '.issuer, .token_endpoint'
# 期望 "https://link.sast.fun/v2" 与 "https://link.sast.fun/v2/oauth/token"

# 3. 绑定路径走前端，不是后端的 404
curl -sI https://link.sast.fun/v2/oauth/bind/github | head -1
# 期望前端返回的 200，而非后端 JSON 形态的 404

# 4. 登录跳转可用
curl -sI "https://link.sast.fun/v2/oauth/github" | grep -i location
# 期望 302 至 github.com/login/oauth/authorize，且 redirect_uri 为 /v2/oauth/github/callback
```

第 3 项是这条特例规则的唯一目的，务必实测。如果它返回了 `{"code":40400,...}` 形态的响应，说明请求落到了后端，`handle /v2/oauth/bind/*` 没有生效。

## 参考

- [Caddyfile handle 指令](https://caddyserver.com/docs/caddyfile/directives/handle)
- [Caddyfile directive 排序算法](https://caddyserver.com/docs/caddyfile/directives#directive-order)
- [GitHub OAuth 回调 URL 匹配规则](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
