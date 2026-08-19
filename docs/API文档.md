# SAST Link v2 API 文档

## 概述

- **Base URL**: `https://link.sast.fun/v2`
- **认证方式**: JWT Bearer Token（`Authorization: Bearer <access_token>`）
- **Content-Type**: 标准业务接口使用 `application/json`；OAuth Token/Revoke 使用 `application/x-www-form-urlencoded`
- **OAuth 2.1**: 授权端点使用 PKCE-S256，第一方应用无需 client_secret
- **OIDC**: 基于 OAuth 2.1 的 OpenID Connect Provider，scope 含 `openid` 时返回 ID Token
- **响应格式**: 标准业务接口使用标准化响应信封；OAuth/OIDC/健康检查/公开卡片等协议或直出端点见下方例外列表

---

## 标准化响应格式与业务码

### 响应信封

所有标准业务接口统一使用以下响应信封。直出响应例外完整列表见下文。

**成功响应**:

```json
{
  "code": 0,
  "message": "ok",
  "data": { ... }
}
```

**错误响应**:

```json
{
  "code": 40105,
  "message": "密码错误",
  "data": null
}
```

| 字段 | 类型 | 说明 |
| ------ | ------ | ------ |
| `code` | int | 业务状态码，`0` 表示成功，非 `0` 表示错误 |
| `message` | string | 可读的描述信息，成功时为 `"ok"`，错误时为具体错误原因 |
| `data` | object\|array\|null | 业务数据载荷，错误时为 `null` |

> 前文各端点示例中展示的响应体均为 `data` 载荷内容，实际响应均被信封包裹。

**直出响应例外**：

- `/oauth/authorize`：成功重定向至前端授权页（携带 `request_id`）；错误按可重定向性重定向至授权页或客户端 `redirect_uri`（携带 `error` / `error_description`）。授权码在第二段 `/oauth/authorize/consent` 才签发，详见 §5.1。
- `/oauth/token`：请求体为 `application/x-www-form-urlencoded`；成功和错误均使用 OAuth JSON 格式（RFC 6749），字段名使用 `scope`（单数）。
- `/oauth/revoke`：请求体为 `application/x-www-form-urlencoded`；遵循 RFC 7009，成功固定 `200 OK` 且响应体为空，错误使用 OAuth JSON 格式。
- `/userinfo`：成功直出 OIDC UserInfo claims；错误遵循 RFC 6750 Bearer Token 错误格式。
- `/.well-known/openid-configuration`：直出 OIDC Discovery JSON。
- `/.well-known/jwks.json`：直出 JWKS JSON。

`/oauth/authorize/consent` 是 SAST Link 自有端点而非 RFC 定义端点，**使用标准信封**，不在上述例外之列。

- `/health`：直出 `{ "status", "db", "redis" }`。
- `/card/{id}`：**已下线**（见 §3.4），暂不响应。

**OAuth 2.1 错误响应示例**：

```json
{
  "error": "invalid_grant",
  "error_description": "授权码已过期或已被使用"
}
```

### 业务码设计

业务码按 HTTP 状态码分段，5 位数字：`{HTTP状态}{序号}`。

#### 成功

| 业务码 | 说明 |
|--------|------|
| `0` | 成功 |

#### 参数错误（400xx）

| 业务码 | 说明 |
| -------- | ------ |
| `40000` | 请求参数错误（含缺少必要参数、参数格式错误） |
| `40010` | 验证码错误 |
| `40011` | 验证码已过期 |
| `40020` | 邮箱域名不允许（仅限 `@njupt.edu.cn` / `@sast.fun`） |

> 参数类错误统一为 `40000`，不再细分"缺少参数"与"格式错误"：请求体解码是一次严格反序列化，缺字段与类型不符走同一条失败路径，拆成两个码只会让客户端依赖一个服务端无法稳定区分的差别。验证码发送超频返回 `42900`（与其他限流一致），不使用独立业务码。

#### 认证错误（401xx）

| 业务码 | 说明 |
| -------- | ------ |
| `40100` | 未登录（缺少或无效 Authorization Header） |
| `40101` | Access Token 已过期 |
| `40102` | Access Token 无效或已被撤销 |
| `40103` | Register-Ticket 无效或已过期 |
| `40104` | Bind-Ticket 无效或已过期 |
| `40105` | 密码错误 |
| `40106` | 登录邮箱不存在 |
| `40107` | login_code 无效或已过期 |
| `40108` | 刷新请求冲突（30s 宽限窗内被并发刷新，家族保留） |

#### 权限错误（403xx）

| 业务码 | 说明 |
| -------- | ------ |
| `40300` | 无权限。情形包括：角色不足（需 admin / lecturer 角色）；token 打能力接口但无对应 scope（入口门 `该 Access Token 未携带管理接口所需的 scope` / `该 Access Token 未携带访问用户接口所需的 scope`）；路由级 scope 门未通过（`Access Token 缺少所需 scope`）；第三方 token 打严格内部接口（`该 Access Token 由第三方客户端签发，不可用于内部接口`） |
| `40301` | 账号已注销（`state = is_deleted`） |
| `40302` | 非 SAST 企业飞书用户 |

#### 资源不存在（404xx）

| 业务码 | 说明 |
| -------- | ------ |
| `40400` | 资源不存在 |
| `40401` | 用户不存在 |
| `40402` | OAuth 客户端不存在 |

#### 资源冲突（409xx）

| 业务码 | 说明 |
| -------- | ------ |
| `40900` | 资源已存在 |
| `40901` | 邮箱已被注册 |
| `40902` | 学号已被占用 |
| `40903` | 第三方账号已被其他用户绑定 |
| `40904` | 该类型账号已绑定，不可重复绑定 |
| `40905` | 第三方邮箱绑定数量已达上限（2 个） |

#### 业务校验失败（422xx）

| 业务码 | 说明 |
| -------- | ------ |
| `42200` | 业务校验失败 |
| `42201` | 密码长度不足（最短 8 位） |
| `42202` | 新旧密码不能相同 |
| `42203` | 头像未通过内容审核 |

#### 频率限制（429xx）

| 业务码 | 说明 |
|--------|------|
| `42900` | 请求过于频繁，请稍后再试 |

返回 `42900` 时，响应可能附带 `Retry-After` 响应头，值为建议等待的整数秒（由剩余窗口向上取整，最小 `1`）。触发来源有两类：端点固定窗口限流，以及连续登录失败达到阈值后的账号锁定。客户端应优先按该头退避；头缺失时（例如剩余窗口无法确定）自行采用默认退避策略。

#### 服务端错误（500xx）

| 业务码 | 说明 |
| -------- | ------ |
| `50000` | 服务器内部错误 |
| `50001` | 邮件发送失败 |
| `50002` | 对象存储上传失败 |
| `50003` | 数据库错误 |

#### 依赖服务暂不可用（503xx）

| 业务码 | 说明 |
|--------|------|
| `50300` | 依赖服务暂不可用，请稍后重试 |

`50300` 用于 fail-closed 依赖不可用场景：验证码、Register-Ticket、Bind-Ticket、OAuth 授权请求暂存等仅存于 Redis 的状态在 Redis 不可用时无法校验，服务端拒绝请求并返回 `50300`，客户端应提示用户稍后重试。头像内容审核服务（腾讯云 COS 图片审核）不可用时同样返回 `50300`：未审核的图片不放行，客户端应提示用户稍后重试。

> **`50300` 是本文档唯一不满足 `{HTTP状态}{序号}` 规则的业务码**：它对应两个 HTTP 状态。
>
> - **503**：本服务自身依赖不可用（Redis、COS 审核等），重试本服务有意义。
> - **502**：GitHub / 飞书等**第三方 provider** 不可用，出现在 `GET /oauth/{github,lark}/callback`、`POST /user/identities/{github,lark}` 上。此时本服务健康、请求也合法，故障在上游，返回 503 会误导客户端以为重试本服务能解决。
>
> 客户端不应假定 `50300` 必然是 503，两者都要按"稍后重试"处理。

OAuth 的 RFC 端点（`/oauth/authorize`、`/oauth/token`、`/oauth/revoke`、`/userinfo`）不使用上述业务错误码，改用 RFC 6749 / RFC 6750 的 `{error, error_description}` 格式，详见 §5。`/oauth/authorize/consent` 是 SAST Link 自有端点，沿用本表业务码。

密码派生有并发上限（`ARGON2_CONCURRENCY`，未设置时按 GOMAXPROCS 推导，1c1g=1），请求需排队等待槽位。若客户端在排队期间断开或超时，服务端放弃该次派生并返回 `50300`，且**不计入登录失败次数、不写入失败审计**——未完成的校验不构成密码错误的证据。

---

## 1. 认证（Auth）

### 1.1 发送注册验证码

```
POST /auth/register/send-code
```

**Request**:

```json
{
  "login_email": "b2404****@njupt.edu.cn"
}
```

**Response** `200`:

```json
{
  "message": "验证码已发送至邮箱",
  "expires_in": 300
}
```

**校验**: 邮箱域名必须为 `@njupt.edu.cn` 或 `@sast.fun`

---

### 1.2 验证注册验证码

注册第一步：验证邮箱验证码，返回 Register-Ticket。

```
POST /auth/register/verify-code
```

**Request**:

```json
{
  "login_email": "b2404****@njupt.edu.cn",
  "code": "123456"
}
```

**Response** `200`:

```json
{
  "register_ticket": "reg_abc123def456...",
  "expires_in": 300
}
```

**说明**:

- Register-Ticket 存储在 Redis，有效期 5 分钟，一次性使用
- Ticket 内携带已验证的邮箱，第二步凭 Ticket 完成注册，无需再次传入 `login_email`
- 校验邮箱域名必须为 `@njupt.edu.cn` 或 `@sast.fun`

---

### 1.3 完成注册

注册第二步：凭 Register-Ticket + 补充信息完成注册。

> **限流**：按 **Register-Ticket** 固定窗口限流（默认 5 次/5 分钟，`RATE_LIMIT_REGISTER_ATTEMPTS`），不按 IP。该配额限制的是成本：每个被接受的请求执行一次密码哈希派生（默认 argon2id m=19456KiB/t2），而 ticket 恰好代表「一个已验证邮箱」这一应被计量的单位。按 IP 限流会让校园网 NAT 后整栋楼共享一个计数桶，正是新生集中注册的流量形状。
>
> 限流检查排在**全部廉价校验之后**（密码长度、学院枚举、邮箱与学号占用），因此用户填错表单不消耗配额；同时排在 `registration_state` 消费**之前**，故被限流的请求既不消费 Register-Ticket 也不消费 `registration_state`，窗口恢复后可用同一 ticket 重试。窗口不得超过 Register-Ticket 的 5 分钟 TTL——否则窗口尚未恢复而 ticket 已过期，重试无从谈起——服务启动时校验这一约束。限流器故障时 fail-open（PRD §6.0），超限返回 `42900` 并带 `Retry-After`。

```
POST /auth/register
```

**Request**:

```json
{
  "register_ticket": "reg_abc123def456...",
  "password": "your_password",
  "name": "张三",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "student_id": "B2404****",
  "college": "计算机学院、软件学院、网络空间安全学院",
  "major": "软件工程",
  "registration_state": "rs_abc123...",
  "oauth_state": "os_abc123..."
}
```

| 字段 | 必填 | 说明 |
| ------ | ------ | ------ |
| `register_ticket` | 是 | 注册验证码校验后获得的票据 |
| `password` | 是 | 密码，最短 8 位 |
| `name` | 是 | 姓名 |
| `phone_number` | 是 | 手机号 |
| `qq_number` | 是 | QQ 号 |
| `student_id` | 是 | 学号 |
| `college` | 是 | 学院，枚举值见附录 A |
| `major` | 是 | 专业 |
| `registration_state` | 否 | 第三方 OAuth 回调下发的注册暂存令牌（Redis 一次性消费），内含 provider + identity_data + oauth_state |
| `oauth_state` | 否 | 原始 OAuth 授权 state 参数（CSRF 校验值），需与 registration_state 内暂存值匹配 |

**Response** `201`:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "login_email": "b2404****@njupt.edu.cn",
    "name": "张三",
    "role": "freshman",
    "state": "njupter",
    "email_type": "njupt_email",
    "created_at": "2026-05-28T12:00:00Z"
  }
}
```

**说明**: Register-Ticket 已包含验证过的邮箱，无需再次传入 `login_email`；密码最短 8 位；注册成功后自动签发 Token，无需单独登录。

`registration_state` + `oauth_state` 为可选字段，来自第三方 OAuth 回调（GitHub / 飞书）的无绑定分支。两者**必须同时提供或同时省略**，只给一半返回 `40000`。传入双值时：GetDel 一次性消费 `registration_state`，比对其中暂存的 `oauth_state` 与请求传入值，匹配后在**同一事务内**创建账号、资料、第三方绑定与首个会话——注册即绑定是一个原子结果，不会出现建号成功而绑定缺失的中间态。

双重校验的意义：`registration_state` 单独泄露（被分享的 URL、日志、referrer）不足以兑换，还需要与之配对的 `oauth_state`。两者都由回调重定向下发到注册补全页——发起登录的那个页面已被跳转到 provider 时卸载，前端无从自行保留 `oauth_state`。校验失败时 `registration_state` 已被消费且不可重试（该对值已被提交并失败，留活会让持有泄露值的攻击者继续枚举 state）。`registration_state` 只能用于新建账号，**不可**用于给已存在账号追加绑定——后者只能走 §4.2 / §4.3 的登录态接口。

未配置第三方 provider（`OAUTH_*_ENABLED` 均为 false）时传入这对字段返回 `40000`；Redis 不可用时返回 `50300` 而非降级为无绑定注册。

**错误码**: 400xx（参数错误、`registration_state` 无效/已过期/与 `oauth_state` 不匹配/只提供其中一个）、40020（邮箱域名不允许）、40103（Register-Ticket 无效或已过期）、40901（邮箱已被注册）、40902（学号已被占用）、40900（其他唯一性冲突）、42201（密码长度不足）、50300（`registration_state` 存储不可用）

Register-Ticket 在建号成功后才消费。返回 40901/40902/40900 时 ticket 仍然有效，客户端可修正对应字段用同一 ticket 重试，不必重新发送验证码。`registration_state` 的消费排在这些可拒绝校验**之后**，因此邮箱或学号冲突同样不会消耗它，带 OAuth 双值的请求可以用同一对值重试；只有走到双重校验本身才会消费（无论匹配与否）。

---

### 1.4 密码登录

```
POST /user/login
```

> **限流**：按 **调用者 IP** 固定窗口限流（默认 500 次/15 分钟，`RATE_LIMIT_LOGIN_RPM` / `RATE_LIMIT_LOGIN_WINDOW`）。校园网 NAT 后多个用户共享同一出口 IP，因此该上限故意宽松；真正的账号防护是下面的登录失败锁定（`LOGIN_FAILURE_LIMIT`）。限流器故障时 fail-open（PRD §6.0），超限返回 `42900` 并带 `Retry-After`。
>
> 登录失败次数（`LOGIN_FAILURE_LIMIT`，默认 10 次/15 分钟）达到上限后，该账号会被锁定至窗口结束，返回 `42900`（与 IP 限流同码，见 §2 429xx）。锁定按账号计数，限流按 IP 计数，但两者对客户端呈现为同一业务码，只能靠 `Retry-After` 退避、无法区分来源。

**Request**:

```json
{
  "login_email": "b2404****@njupt.edu.cn",
  "password": "your_password"
}
```

**Response** `200`:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "name": "张三",
    "login_email": "b2404****@njupt.edu.cn",
    "role": "freshman",
    "state": "njupter",
    "email_type": "njupt_email",
    "created_at": "2026-05-28T12:00:00Z"
  }
}
```

**说明**:

- 教育邮箱（`@njupt.edu.cn` / `@sast.fun`）查 `user.login_email` 后验证 `user.password`
- 第三方邮箱查 `identities` 表 `provider = 'other_mail'` 的 `provider_id` 反查 `user_id`，同样验证 `user.password`
- 所有密码登录共用同一套密码（`user.password`），第三方邮箱仅作为登录标识

---

### 1.5 刷新 Token

```
POST /auth/refresh
```

> **限流**：按调用方 IP 固定窗口限流（默认 300 次/60s，`RATE_LIMIT_REFRESH_RPM` / `RATE_LIMIT_REFRESH_WINDOW`）。本端点无认证且每次调用执行多条 DB 语句（查 token、查用户、轮换事务），不限流则单一来源可以零成本放大数据库负载。限流检查排在 token 哈希与查库**之前**——限流器若排在它要保护的工作之后就失去意义。与 `/oauth/token` 同为 300 次/60s 一档。限流器故障时 fail-open（PRD §6.0），超限返回 `42900` 并带 `Retry-After`。

**Request**:

```json
{
  "refresh_token": "rt_abc123..."
}
```

> `refresh_token` 可省略：为空时从 httpOnly 会话 cookie（`sl_session`，登录/刷新时下发）读取 refresh token。这是新开标签页 bootstrap 会话的路径——新 tab 没有 sessionStorage 里的 token，但浏览器会带同源 cookie。
>
> 请求体必须为 `Content-Type: application/json` 的 JSON 对象；省略 refresh_token 时发送空对象 `{}`（0 字节空 body 会被拒，返回 400）。

**Response** `200`:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_new_abc456...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**说明**:

- Refresh Token 旋转机制 — 每次使用后旧 token 立即撤销，下发新 token；同时通过 `Set-Cookie` 更新 `sl_session` cookie，保持其与最新 refresh token 同步
- `40108`（刷新请求冲突）出现在多 tab 并发冷启动：同一 cookie 的 refresh token 已被兄弟请求在 30s 宽限窗内轮换，家族保留。客户端应**重读当前 cookie 后重试一次**（此时 cookie 已携带赢家的新 token），不要拿同一枚旧 token 无限重试——超过 30s 宽限窗仍用旧 token 会按真重放处理并撤销整个家族（连带赢家会话）
- 账号已注销（`40301`）时，**cookie 来源**的刷新返回 `401`（错误码仍是 `40301`）而非 `403`：前端只在刷新以 401 结束时清会话并跳登录，已注销的账号必须让标签页脱离死会话壳。请求体携带 `refresh_token` 的调用保持 `403`——调用方已在带内认证，应当得到准确的账号状态
- 此端点用于内部登录（密码/第三方）的 token 刷新；OAuth 客户端刷新请使用 `POST /oauth/token`（grant_type=refresh_token）

---

### 1.6 登出

```
POST /auth/logout
```

**Headers**: `Authorization: Bearer <access_token>`

**Request**:

```json
{
  "refresh_token": "rt_abc123..."
}
```

> `refresh_token` 已不再参与登出，可省略：服务端按当前 access_token 所属的会话 family 撤销，请求体里的 `refresh_token` 字段被忽略。登出成功后服务端清掉 httpOnly 会话 cookie（`Set-Cookie: sl_session=; Max-Age=0`）。
>
> 登出使用**过期宽容认证**：access token 已过期（1h TTL 后）但签名有效时仍能登出——按其会话 family 撤销并清 cookie 返回成功；会话的 access 行已不存在或已撤销时同样幂等清 cookie 返回成功（`40102`）。缺失 Authorization Header 返回 `40100`（未登录）；伪造或签名无效的 token 返回 `40102`。
>
> 会话 cookie 是**浏览器级**的（同一浏览器的所有标签页共享）：单个标签页登出会清掉它，但不影响其他标签页 `sessionStorage` 里的凭据——它们下次刷新会通过 `/auth/refresh` 自动重建 cookie。因此"在一处登出，本浏览器其他标签页仍保有 session 直到其 token 过期"是预期行为。

**Response** `200`:

```json
{
  "message": "已登出"
}
```

**说明**: 撤销当前 access_token（jti）及整条 refresh_token family；同时清掉 httpOnly 会话 cookie。

---

### 1.7 修改密码

```
POST /auth/change-password
```

**Headers**: `Authorization: Bearer <access_token>`

**Request**:

```json
{
  "old_password": "old_password",
  "new_password": "new_password"
}
```

**Response** `200`:

```json
{
  "message": "密码修改成功"
}
```

**说明**: 新密码最短 8 位；修改成功后撤销该用户所有 token family，需重新登录。若新密码与旧密码相同，返回 42202。

**错误码**: 400xx（参数错误）、40105（密码错误）、42201（密码长度不足）、42202（新旧密码相同）

---

### 1.8 发送重置密码验证码

```
POST /auth/forgot-password/send-code
```

**Request**:

```json
{
  "login_email": "b2404****@njupt.edu.cn"
}
```

**Response** `200`:

```json
{
  "message": "重置密码请求已受理",
  "expires_in": 300
}
```

**说明**: 对格式合法且未触发限流的邮箱，接口总是返回同一结果。响应不表示账号存在，也不表示邮件已经送达。服务端把请求放入有界内存队列；worker 只为已注册邮箱生成并发送验证码。队列满、进程重启或邮件依赖失败时任务可能丢失，用户可在限流窗口后重试。

**错误码**: 400xx（参数错误）、429xx（频率限制）

---

### 1.9 重置密码

```
POST /auth/reset-password
```

**Request**:

```json
{
  "login_email": "b2404****@njupt.edu.cn",
  "code": "123456",
  "new_password": "new_password"
}
```

**Response** `200`:

```json
{
  "message": "密码重置成功，请重新登录"
}
```

**说明**: 新密码最短 8 位。若新密码与旧密码相同，返回 42202。

改密与重置密码在同一事务内完成三件事：写入新密码哈希、`token_version + 1`、撤销该用户全部活跃 Access / Refresh Token。同时**作废该用户尚未兑换的 OAuth 授权码**——授权码是一张还没花出去的凭证，Token 端点签发时会现读用户行上的 `token_version`，因此一张跨过重置动作的授权码兑换出来的会话会带着**新的** `token_version`，中间件照单全收。若只撤销 token 而放着授权码不管，就在「因怀疑被入侵而重置密码」这个最要紧的场景里留下一个恰好等于授权码 TTL 宽度的窗口。

**错误码**: 400xx（参数错误）、40106（邮箱不存在）、42201（密码长度不足）、42202（新旧密码相同）

---

## 2. 第三方 OAuth 登录

> 注意本章描述的「SAST Link 作为 OAuth *客户端*」方向，与第 8 章「SAST Link 作为 OAuth *Provider*」方向相反。
>
> **provider 开关**：GitHub 与飞书各由 `OAUTH_GITHUB_ENABLED` / `OAUTH_FEISHU_ENABLED` 独立控制，未启用的 provider 路由仍然注册，调用返回 `40000`（不支持的第三方登录方式）而非 `404`。启用某个 provider 时其 client id / secret / redirect_uri 均为必填，飞书还必须提供 `OAUTH_FEISHU_TENANT_KEY`——留空会关闭租户校验，接受任意飞书企业的用户。
>
> **回调重定向白名单**：`OAUTH_LOGIN_REDIRECTS` 以精确匹配校验回调可返回的前端地址，不支持前缀匹配。回调会把 `login_code` 交给它重定向到的地址，前缀规则会让 `https://link.sast.fun.evil.test` 也通过。不在白名单内的 `redirect` 返回 `40000`。失败的回调重定向到 `OAUTH_LOGIN_ERROR_REDIRECT`，携带 `?error=&error_description=`；该项留空时改为返回标准信封。
>
> **限流**：`GET /oauth/{github,lark}` 按调用方 IP 固定窗口限流（默认 300 次/60s，`RATE_LIMIT_OAUTH_LOGIN_RPM`）。两者与 §8.3 的 `/oauth/authorize` 形状相同——无认证、每次调用写一个带 TTL 的 Redis 键——故采用同一档配额。限流在解析 provider **之前**生效，因此被禁用的 provider 那条仍返回 `40000` 的路由也不是无成本探测面。`POST /oauth/exchange-code` 按 IP 限流（默认 300 次/60s，`RATE_LIMIT_EXCHANGE_CODE_RPM`），且检查排在空 `code` 校验之前——调用方控制输入，先直接拒空会让每次猜测一次 Redis GetDel 的昂贵路径保持敞开。被限流的请求不消费 `login_code`：否则触发限流即可销毁他人活跃凭证。两处均 fail-open（PRD §6.0），超限返回 `42900` 并带 `Retry-After`。
>
> 回调端点（`/oauth/{github,lark}/callback`）不单独限流：它需要一个有效的一次性 `oauth_state` 才能推进，而该 state 由已限流的授权端点签发。
>
> **登录 CSRF 防护**（OAuth 2.0 §10.12）：`GET /oauth/{github,lark}` 响应同时下发 `sl_oauth_state` cookie（HttpOnly、SameSite=Lax、值为 `state` 的 SHA-256 摘要、Path/Secure 与 `sl_session` 相同、有效期与 state TTL 一致）。回调要求浏览器携带与 `state` 匹配的该 cookie，缺失或不匹配按 state 无效处理（重定向到错误页）；state 单次消费，回调结束后 cookie 即清除。

### 2.1 GitHub 登录

```
GET /oauth/github
```

重定向至 GitHub OAuth 授权页。

---

### 2.2 GitHub 回调

```
GET /oauth/github/callback?code=...&state=...
```

**Response** `302` 重定向至前端。

**处理分支**:

- 已有绑定 → 签发一次性 `login_code`（Redis，60s），302 重定向至前端 `?code=<login_code>`
- 无绑定 → 生成 `registration_state`（Redis，15min，暂存 provider + provider_id + identity_data + oauth_state），302 重定向至注册补全页 `?registration_state=<registration_state>&oauth_state=<oauth_state>&provider=github&name=<login>&avatar=<url>`

---

### 2.3 飞书登录

```
GET /oauth/lark
```

重定向至飞书 OAuth 授权页。

---

### 2.4 飞书回调

```
GET /oauth/lark/callback?code=...&state=...
```

**Response** `302` 重定向至前端。

**约束**: 仅限 SAST 企业内飞书用户。

**处理分支**:

- 已有绑定 → 签发一次性 `login_code`（Redis，60s），302 重定向至前端 `?code=<login_code>`
- 无绑定 → 生成 `registration_state`（Redis，15min，暂存 provider + provider_id + identity_data + oauth_state），302 重定向至注册补全页 `?registration_state=<registration_state>&oauth_state=<oauth_state>&provider=lark&name=<name>&avatar=<url>`
- 非 SAST 企业用户 → 拒绝，提示"仅限 SAST 成员登录"

---

### 2.5 交换登录码

用 OAuth 回调中的一次性 `login_code` 换取 token。

回调本身不返回 Token：它是一个到前端的 302，Token 出现在查询串里会进入浏览器历史与 `Referer` 头，因此改为投递一次性 `login_code`（60s），由本端点兑换。本端点**不需要**登录态——兑换 code 正是取得会话的方式。

`login_code` 为 GetDel 一次性消费，并发兑换同一 code 只有一个成功。账号状态在兑换时**重新校验**：code 有 60s 寿命，这期间被注销的账号不得凭它取得会话，返回 `40301`。

```
POST /oauth/exchange-code
```

**Request**:

```json
{
  "code": "lc_abc123..."
}
```

**Response** `200`:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "name": "张三",
    "login_email": "b2404****@njupt.edu.cn",
    "role": "freshman",
    "state": "njupter",
    "email_type": "njupt_email",
    "created_at": "2026-05-28T12:00:00Z"
  }
}
```

**说明**: `login_code` 存储在 Redis，有效期 60 秒，一次性使用；交换成功后立即删除。签发的会话与密码登录完全一致（同一内置客户端、同一 `openid profile email` scope），第三方登录不因此更高或更低权限。

**错误码**: `40000`（`code` 缺失、未知字段或 Content-Type 非 JSON）、`40107`（`login_code` 无效或已过期）、`40301`（账号已注销）、`40401`（用户不存在）、`50300`（Redis 不可用，fail-closed）、`50000`（服务器内部错误）

---

## 3. 用户资料（Profile）

### 3.1 获取当前用户信息

```
GET /user/profile
```

**Headers**: `Authorization: Bearer <access_token>`

**Response** `200`:

```json
{
  "id": 1,
  "name": "张三",
  "login_email": "b2404****@njupt.edu.cn",
  "role": "freshman",
  "state": "njupter",
  "email_type": "njupt_email",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "student_id": "B2404****",
  "college": "计算机学院、软件学院、网络空间安全学院",
  "major": "软件工程",
  "profile": {
    "nickname": "张三",
    "department": "software",
    "intro": "自我介绍",
    "email": "display@example.com",
    "avatar": "https://cos.example.com/avatar/1.jpg",
    "blog_url": "https://blog.example.com",
    "github_url": "https://github.com/example",
    "created_at": "2026-05-28T12:00:00Z",
    "updated_at": "2026-05-28T12:00:00Z"
  },
  "identities": [
    {
      "id": 1,
      "provider": "lark",
      "provider_id": "on_xxx",
      "identity_data": { "name": "张三", "avatar_url": "...", "open_id": "ou_xxx", "union_id": "on_xxx" },
      "token_expires_at": "2026-05-28T14:00:00Z",
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    },
    {
      "id": 2,
      "provider": "github",
      "provider_id": "145339646",
      "identity_data": { "login": "github_username" },
      "token_expires_at": null,
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    }
  ],
  "created_at": "2026-05-28T12:00:00Z",
  "updated_at": "2026-05-28T12:00:00Z"
}
```

> `profile.email` 为对外展示邮箱；登录邮箱为顶层的 `login_email`，第三方登录邮箱在 `identities` 表中。

---

### 3.2 更新当前用户个人信息

```
PUT /user/profile
```

**Headers**: `Authorization: Bearer <access_token>`

更新当前登录用户可自助维护的个人信息。未传字段保持不变；`login_email`、`role`、`state`、`email_type` 等身份与权限字段不可通过此接口修改，传入未知字段返回 `40000`。

**Request**（所有字段均可选，至少传一个）:

```json
{
  "name": "张三",
  "student_id": "B2404****",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "college": "计算机学院、软件学院、网络空间安全学院",
  "major": "软件工程",
  "nickname": "新昵称",
  "department": "software",
  "intro": "新的自我介绍",
  "email": "display@example.com",
  "blog_url": "https://blog.example.com",
  "github_url": "https://github.com/example"
}
```

**字段语义**:

| 字段组 | 归属 | 传空字符串 |
| -------- | ------ | ----------- |
| `nickname` / `department` / `intro` / `email` / `blog_url` / `github_url` | `profile`（可空） | 清空为 `null` |
| `name` / `student_id` / `phone_number` / `qq_number` / `college` / `major` | `user`（NOT NULL） | 返回 `40000` |

- 未传的键与传空字符串语义不同：前者保持不变，后者对可空字段表示清空
- 传 `null` 等同于未传该键（保持不变），**不表示清空**；清空请用空字符串
- `college` 必须是 `college_enum` 完整枚举值（见附录 A），简称如「计算机学院」会被拒绝
- `department` 仅接受 `software` / `media` 或空字符串
- `blog_url` / `github_url` 必须是 http/https 绝对 URL——这两个字段会在公开卡片上渲染为链接，故拒绝 `javascript:`、`data:` 等 scheme
- 所有文本字段拒绝控制字符（NUL、CR、LF、Tab 及其他 C0/C1），返回 `40000`；字段内部的空格保留，仅首尾被裁剪
- 字段长度上限按数据库列宽校验（`name`/`nickname`/`intro`/`email` 255，`phone_number`/`qq_number` 20，`student_id`/`major` 50，两个 URL 512）
- `email` 为展示邮箱（非登录邮箱），非空时校验格式，不合法返回 `40000`
- 可空字段传纯空白（如 `" "`）等同于传空字符串，首尾裁剪后为空即清空为 `NULL`；NOT NULL 字段传纯空白返回 `40000`

**错误码**: `40000`（参数/枚举/长度/链接校验失败、未知字段、无任何待更新字段）、`40902`（学号已被占用）、`40900`（其他唯一性冲突）、`40102`（未认证）、`40301`（账号已注销）、`50000`（服务器内部错误）

审计日志 `update_profile` 的 `detail.changed_fields` 记录本次实际写入的字段名。

**Response** `200`:

```json
{
  "message": "个人信息更新成功",
  "user": {
    "id": 1,
    "name": "张三",
    "login_email": "b2404****@njupt.edu.cn",
    "role": "freshman",
    "state": "njupter",
    "email_type": "njupt_email",
    "phone_number": "13800138000",
    "qq_number": "1234567890",
    "student_id": "B2404****",
    "college": "计算机学院、软件学院、网络空间安全学院",
    "major": "软件工程",
    "profile": { ... },
    "identities": [ ... ],
    "created_at": "2026-05-28T12:00:00Z",
    "updated_at": "2026-05-28T12:30:00Z"
  }
}
```

---

### 3.3 上传头像

```
PUT /user/avatar
```

**Headers**: `Authorization: Bearer <access_token>`
**Content-Type**: `multipart/form-data`

**Request**: `file` 字段（图片，限制 1MB 且任一维 ≤4096，格式 jpg/png/webp；按魔数检测，不信任文件名与 Content-Type。压缩由前端完成，后端只做上限、格式与分辨率校验，不重新编码）

上传链路：后端接收图片 → 上传腾讯云 COS（公开读）→ COS 内容审核（`STORAGE_AUDIT_ENABLED` 开启时）→ 写入 `profile.avatar` → 返回公开 URL。审核 fail-closed：审核服务不可用时上传失败，未审核图片不放行。旧头像对象在写库成功后删除（失败仅记日志，不影响响应）。

**错误码**: `40000`（非 jpg/png/webp、超 1MB 或任一维超 4096、文件损坏或为空、缺少 `file` 字段）、`42203`（头像未通过内容审核）、`42900`（请求过于频繁，按用户限流）、`40102`（未认证）、`40301`（账号已注销）、`50002`（对象存储未配置/上传失败）、`50300`（内容审核服务不可用，fail-closed）、`50003`（数据库错误）

**Response** `200`:

```json
{
  "avatar_url": "https://cos.example.com/avatar/1/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.jpg"
}
```

---

### 3.4 获取个人卡片

**已下线**（路由注释，暂不响应）。顺序 ID 的公开 URL 可枚举全站成员名单，隐私重设计中。重开后为 owner-only + 不可枚举标识，不会原样启用。以下为下线前的契约，供重设计参考。

```
GET /card/:id
```

> **限流**：按调用方 IP 固定窗口限流（默认 300 次/60s，`RATE_LIMIT_CARD_RPM`）。本端点无认证且路径参数是连续的用户 ID，不限流即等于开放全站公开卡片的抓取。限流检查排在 ID 合法性校验**之前**——无效 ID 得到的 `404` 本身就是枚举者要读的信号。
>
> 配额按「共享出口 IP 下的成员墙」定档：一页渲染数十张卡片，不能让一位访客耗尽整个 NAT 当分钟的额度。这一档只能减缓而非阻止抓取——公开卡片的批量读取应交由反向代理缓存承担，容量防线本就在那一层。限流器故障时 fail-open（PRD §6.0），超限返回 `42900` 并带 `Retry-After`。

**Path Parameters**:

| 参数 | 说明 |
|------|------|
| `id` | 用户 ID |

**Response** `200`:

```json
{
  "id": 1,
  "nickname": "张三",
  "department": "software",
  "intro": "自我介绍",
  "avatar": "https://cos.example.com/avatar/1.jpg",
  "blog_url": "https://blog.example.com",
  "github_url": "https://github.com/example"
}
```

**说明**: 返回 `profile` 表中公开字段，用于公开个人主页、homepage 友链展示。用户 ID 不存在或已注销（`state = is_deleted`）时返回 404（`40401`），两者不区分；ID 格式非法（非正整数、含非数字字符）同样返回 `40401`，避免探测哪些 ID 曾经存在。

**错误码**: `40401`（用户不存在、已注销或 ID 格式非法）、`50000`（服务器内部错误）

该端点**不使用**标准响应信封（见 §10.1），字段直接位于顶层。未填写的展示字段返回 `null`；用户无 `profile` 记录时除 `id` 外全部为 `null`。`id` 非正整数或含非数字字符时同样返回 404。

---

### 3.5 设备列表

```
GET /user/devices
```

**Headers**: `Authorization: Bearer <access_token>`

**Response** `200`:

```json
{
  "devices": [
    {
      "device_id": "6da1d5dd-02ec-4fc6-840e-67dc0dae52ac",
      "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
      "ip": "10.0.0.2",
      "login_time": "2026-07-22T10:05:00Z",
      "last_seen": "2026-07-22T11:30:00Z"
    },
    {
      "device_id": "e99286a4-eef2-4fff-8ff2-cd4b647ee5de",
      "ua": "SAST-Link-App/1.0",
      "ip": "10.0.0.1",
      "login_time": "2026-07-22T10:00:00Z",
      "last_seen": "2026-07-22T10:00:00Z"
    }
  ]
}
```

**说明**:

- 按最近登录时间倒序返回（最新在前），每台设备对应一次登录会话（密码登录、注册、GitHub/Lark 第三方登录统一登记）
- `device_id` 即 token family_id（UUID）：一次登录即一台设备，设备生命周期与 token 会话生命周期同步
- 设备记录存于 Redis（`sastlink:devices:{user_id}` 有序集合 + `sastlink:device:{device_id}` Hash），最多 5 台，超出时淘汰登录时间最早的一台并**撤销该设备的全部 token**（被淘汰设备的 refresh token 立即失效，无法继续刷新）；TTL 30 天
- 登录/注册时登记设备；刷新 Token 时更新 `last_seen`（有效记录不续期 TTL，30 天不活跃则记录过期；过期后设备再次刷新会重新登记，同样受 5 台上限约束、超出时淘汰最旧并撤销其会话——会话还在使用就不该变成列表里看不见的幽灵）；登出删除单台；修改/重置密码时清空全部设备
- 会话终止一律同步清除设备记录并写审计：登出 `logout`、登出指定设备 `logout_device`、淘汰 `evict_device`、改密/重置 `change_password`/`reset_password`、刷新重放/轮换失败/过期（refresh 三态 outcome）；管理员角色降级（触发会话撤销时）与注销账号也会清空该用户设备记录
- Redis 不可用时降级返回空数组（fail-open），不影响登录能力

**错误码**: `40102`（未认证）、`40301`（账号已注销）、`50000`（服务器内部错误）

---

### 3.6 登出指定设备

```
DELETE /user/devices/{device_id}
```

**Headers**: `Authorization: Bearer <access_token>`

**Path 参数**: `device_id` — 设备 ID（token family_id，UUID），非数字字符串

**Response** `200`:

```json
{
  "message": "该设备已登出"
}
```

**说明**:

- 流程：校验设备归属当前用户（Redis 归属校验，fail-closed）→ 撤销该设备所属 token family 的全部令牌 → 删除设备记录 → 审计 `logout_device`
- 设备不存在或不属于当前用户均返回 `40400`，不区分两者，避免探测他人设备；空/空白的 `device_id` 同样走 `40400`（handler 先 trim 再判断），本端点不产生 `40000`
- 登出后该设备的 Access Token 与 Refresh Token 立即全部失效（token family 级联撤销），其他设备不受影响
- 当前设备登出请使用 `POST /auth/logout`（不依赖设备记录，不受 Redis 故障影响）
- 按用户限流，60s 内最多 3 次（`42900`，带 Retry-After）；按用户而非 IP，避免校园网 NAT 共享配额
- Redis 不可用时拒绝执行（fail-closed：无法校验归属时不执行撤销）

**错误码**: `40102`（未认证）、`40301`（账号已注销）、`40400`（设备不存在或不属于当前用户）、`42900`（操作过于频繁）、`50300`（设备服务暂不可用）、`50000`（服务器内部错误）

---

## 4. 第三方账号绑定（Identities）

### 4.1 获取绑定列表

```
GET /user/identities
```

**Headers**: `Authorization: Bearer <access_token>`

**Response** `200`:

```json
{
  "identities": [
    {
      "id": 1,
      "provider": "lark",
      "provider_id": "on_xxx",
      "identity_data": { "name": "张三", "avatar_url": "...", "open_id": "ou_xxx", "union_id": "on_xxx" },
      "token_expires_at": "2026-05-28T14:00:00Z",
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    },
    {
      "id": 2,
      "provider": "github",
      "provider_id": "145339646",
      "identity_data": { "login": "github_username" },
      "token_expires_at": null,
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    },
    {
      "id": 3,
      "provider": "other_mail",
      "provider_id": "myemail@qq.com",
      "identity_data": null,
      "token_expires_at": null,
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    }
  ]
}
```

**错误码**: `40102`（未认证）、`40301`（账号已注销）、`50000`（服务器内部错误）

---

### 4.2 绑定飞书

> 本节与 §4.3（绑定 GitHub）只接受登录态调用，`code` 走 query 参数。绑定路径**不接受** `registration_state`：该值只证明有人走完了一次第三方回调，不证明是哪个 SAST 账号在操作，因此追加绑定一律由 Bearer token 认定调用者。每个用户每种 provider 最多一条绑定（V001 partial unique index）：该第三方账号已属他人返回 `40903`，调用者自己已绑同类型返回 `40904`。
>
> **`code` 从哪里来**：绑定与登录走**不同的回调地址**，因此需要在 provider 后台各注册一条。
>
> 登录用的回调（`OAUTH_*_REDIRECT_URI`）指向**本后端**的 `/oauth/{lark,github}/callback`，由后端消费 code 后 302 到前端。绑定用的回调是**前端页面**（例如 `/oauth/bind/lark`）：已登录用户在前端发起 provider 授权，provider 把 code 交给该前端页面，前端再带着 `code` 与自己那个回调地址调用本接口。
>
> 两条回调都要登记进 provider 应用的重定向白名单。飞书的重定向 URL 支持配置多条，两条都填即可。
>
> GitHub OAuth App 只能配**一条** callback URL，匹配规则是 host（不含子域）与端口精确相等、请求路径必须位于已注册路径**之下**（官方示例表中，注册 `/path` 时 `/` 会被拒绝）。因此两条回调必须共享一个已注册的父路径：生产上把绑定页放在 `/v2/oauth/bind/{provider}`、与登录回调同处 `/v2/oauth` 之下，注册 `https://link.sast.fun/v2/oauth`；本地则利用 loopback 免端口匹配的例外，注册 `http://127.0.0.1/oauth`。完整配置与 Caddy 分流规则见 `docs/runbooks/caddy-reverse-proxy.md`。
>
> 为绑定单独开一个 OAuth App **行不通**：`Bind()` 用 `OAUTH_GITHUB_CLIENT_ID/SECRET` 这一套凭据交换 code，另一个 App 签发的 code 会被拒绝。若要走这条路，需先为绑定增加一组 client 配置项。

```
POST /user/identities/lark
```

**Headers**: `Authorization: Bearer <access_token>`

**Query Parameters**:

| 参数 | 必填 | 说明 |
|------|------|------|
| `code` | 是 | 飞书 OAuth 授权码 |
| `redirect_uri` | 否 | 签发该 `code` 时使用的回调地址，即前端的绑定回调页。RFC 6749 §4.1.3 要求 token 交换重复这个值，飞书注册了多条回调时不一致会返回 `invalid_grant`。省略时回退到 `OAUTH_FEISHU_REDIRECT_URI`（登录回调），仅在绑定与登录共用同一回调地址时才适用 |

**Response** `200`:

```json
{
  "message": "飞书账号绑定成功",
  "identity": {
    "id": 1,
    "provider": "lark",
    "provider_id": "on_xxx",
    "identity_data": { "name": "张三", "avatar_url": "...", "open_id": "ou_xxx", "union_id": "on_xxx" },
    "token_expires_at": null,
    "created_at": "2026-05-28T12:00:00Z",
    "updated_at": "2026-05-28T12:00:00Z"
  }
}
```

**约束**: 每个用户只能绑定一个飞书账号；每个飞书账号只能绑定一个用户。

---

### 4.3 绑定 GitHub

```
POST /user/identities/github
```

**Headers**: `Authorization: Bearer <access_token>`

**Query Parameters**:

| 参数 | 必填 | 说明 |
|------|------|------|
| `code` | 是 | GitHub OAuth 授权码 |
| `redirect_uri` | 否 | 签发该 `code` 时使用的回调地址，即前端的绑定回调页。省略时回退到 `OAUTH_GITHUB_REDIRECT_URI`（登录回调）。GitHub 在 token 交换阶段用它校验与签发 code 时是否一致，见 §4.2 的回调说明 |

**Response** `200`:

```json
{
  "message": "GitHub 账号绑定成功",
  "identity": {
    "id": 2,
    "provider": "github",
    "provider_id": "145339646",
    "identity_data": { "login": "github_username" },
    "token_expires_at": null,
    "created_at": "2026-05-28T12:00:00Z",
    "updated_at": "2026-05-28T12:00:00Z"
  }
}
```

**约束**: 每个用户只能绑定一个 GitHub 账号；每个 GitHub 账号只能绑定一个用户。

---

### 4.4 绑定其他邮箱

```
POST /user/identities/email
```

**Headers**: `Authorization: Bearer <access_token>`

**Request**:

```json
{
  "email": "myemail@qq.com"
}
```

**Response** `200`:

```json
{
  "bind_ticket": "be_abc123def456...",
  "expires_in": 300
}
```

**说明**: Bind-Ticket 存储在 Redis，有效期 5 分钟，一次性使用，内部携带待绑定邮箱地址。

---

### 4.5 确认绑定其他邮箱

```
POST /user/identities/email/verify
```

**Headers**: `Authorization: Bearer <access_token>`

**Request**:

```json
{
  "bind_ticket": "be_abc123def456...",
  "code": "123456"
}
```

**Response** `200`:

```json
{
  "message": "邮箱绑定成功",
  "identity": {
    "id": 3,
    "provider": "other_mail",
    "provider_id": "myemail@qq.com",
    "identity_data": null,
    "token_expires_at": null,
    "created_at": "2026-05-28T12:00:00Z",
    "updated_at": "2026-05-28T12:00:00Z"
  }
}
```

**约束**: 每个用户最多绑定 2 个第三方邮箱。

---

### 4.6 解绑第三方账号

```
DELETE /user/identities/:id
```

**Headers**: `Authorization: Bearer <access_token>`

**Request**:

```json
{
  "password": "current_password"
}
```

**Response** `200`:

```json
{
  "message": "解绑成功"
}
```

**约束**:

- 必须输入当前密码进行二次确认——仅凭 Access Token 不足以摘除账号的登录方式
- 主邮箱（`user.login_email`）不在 identities 中，不可通过此接口解绑
- 不能解绑唯一登录方式（解绑后无其他登录手段则拒绝）
- 单个用户 60s 内最多解绑 3 次，超出返回 `42900` 并带 `Retry-After`；限流在密码校验之前生效，密码错误的请求同样消耗配额
- 并发解绑同一条记录由数据库串行化，只有一个能删到行，另一个返回 `40400`

**错误码**: `40000`（`password` 缺失、未知字段或 Content-Type 非 JSON）、`40105`（密码错误）、`40400`（绑定记录不存在或不属于当前用户）、`42200`（不能解绑唯一的登录方式）、`42900`（解绑过于频繁，带 `Retry-After`）、`40301`（账号已注销）、`50300`（密码派生被中断，依赖暂不可用）、`50000`（服务器内部错误）

不属于当前用户的绑定 ID 与不存在的 ID 均返回 `40400`，不区分两者，避免探测他人绑定记录是否存在。

---

## 5. OAuth 2.1 授权服务端

### 5.1 授权端点

```
GET /oauth/authorize
```

**Query Parameters**:

| 参数 | 必填 | 说明 |
| ------ | ------ | ------ |
| `response_type` | 是 | 固定 `code` |
| `client_id` | 是 | 客户端标识 |
| `redirect_uri` | 是 | 回调地址 |
| `scope` | 是 | 授权范围，空格分隔，取值：`openid`（必选）/ `profile` / `email` / `admin:read` / `admin:write` / `user:read` / `user:write`；线协议字段为 OAuth 标准单数 `scope`，数据库列仍为 `scopes` |
| `state` | 是 | CSRF 防护，客户端生成随机字符串，回调时原样返回。最长 512 字符 |
| `code_challenge` | 是 | PKCE challenge，固定 43 字符 base64url（`BASE64URL(SHA256(verifier))` 的长度）；其他长度返回 `invalid_request` |
| `code_challenge_method` | 是 | 固定 `S256`；不接受 `plain` |
| `nonce` | 否 | OIDC nonce，最长 255 字符 |

`code_challenge` 与 `nonce` 的长度上限对应 `oauth_authorizations` 表中这两列的 `VARCHAR(255)` 宽度。校验放在第一段而非第二段，是因为超长值若拖到写库时才失败，用户会拿到一个不可重试的 `500`——此时一次性暂存已被消费，只能从头再来；在第一段拒绝则是客户端可以直接修正的可重定向 `invalid_request`。

**行为**: 授权分两段完成。本端点**不需要认证**——从第三方跳转来的浏览器不会携带 `Authorization` header。

```
第三方 app
  └─> GET /oauth/authorize?client_id=..&redirect_uri=..&code_challenge=..
        校验参数 → 暂存请求（20min，`OAUTH_AUTHORIZE_REQUEST_TTL`）→ 302
  └─> {OAUTH_CONSENT_URL}?request_id=ar_xxx&client_name=..&scope=..&expires_in=1200
        前端展示授权页，读取本地 access_token
        expires_in 为暂存剩余秒数，供页面显示截止时间并在超时后
        阻止提交（否则用户会提交进一个没有预告的 400）
  └─> POST /oauth/authorize/consent   （见 §5.2）
        Authorization: Bearer <access_token>
        → 200 { redirect_uri }
  └─> 前端 navigate 至 redirect_uri（携带 code 与 state）
```

采用两段式而非 cookie session，是为了保持 PRD §7.1「JWT 不存 cookie，不存在 CSRF 攻击面」；保留标准的 `GET /oauth/authorize` 入口 URL，则是为了让第三方 OAuth 库无需特殊适配。

**错误重定向规则**：错误分两条路径，取决于 `redirect_uri` 是否已通过校验。

| 阶段 | 错误 | 去向 |
|------|------|------|
| `client_id` / `redirect_uri` 校验通过**之前** | `invalid_request`、`invalid_client`、`temporarily_unavailable`（限流或 Redis 暂存写入失败）、`server_error`（查库失败） | 302 至 `OAUTH_CONSENT_URL`，携带 `error` / `error_description`，**不带 `state`** |
| 校验通过**之后** | `unsupported_response_type`、`invalid_scope`、`unauthorized_client`、`invalid_request` | 302 至客户端 `redirect_uri`，携带 `error` / `error_description` / `state` |

RFC 6749 §4.1.2.1 禁止把错误重定向到未经校验的 `redirect_uri`——否则任何人填入任意地址即可让本服务把浏览器重定向到那里，端点退化为 open redirector。`redirect_uri` 必须与 `oauth_clients.redirect_uris` 之一**精确字符串相等**，前缀匹配不成立（`https://app.example.com/cb/../evil` 会被拒绝）。

**scope 限制**：任何客户端（含 `first_party`）只能请求注册时声明的子集，超出返回 `invalid_scope`。`admin:read` / `admin:write` 仅 `third_party`（机密）客户端可持有；`user:read` / `user:write` 无客户端类型约束，任何客户端皆可持有——`/user/*` 每个端点只操作 token 主体本人的记录，持有 user scope 的应用不会是查他人凭据。

`admin:read` / `admin:write` 在注册值约束之上再加一条限制：**仅 `third_party` 客户端可持有**，`first_party` 客户端请求任一 admin scope 返回 `invalid_scope`，即使其注册值中含有。原因是凭证能力——`first_party` 是公开客户端，token 端点仅凭 PKCE 认证它，因此从授权码被签出到管理 token 存在之间只有 `redirect_uri` 精确匹配一道屏障，而机密客户端有两道独立屏障。委派管理不应跑在更薄的那一侧。

`user:read` / `user:write` 无客户端类型约束，任何客户端（含 `first_party` 与 `third_party`）皆可持有。它们 gate `/user/*` 自助面——token 以当前用户本人身份操作其账号（读/改资料、绑/解绑身份、改密码、登出设备），每个端点都只操作 token 主体本人的记录，因此持有 user scope 的应用永远不会成为「查任意人」凭据，主体由 token 钉死，与签发客户端无关。

**限流**：按调用方 IP 固定窗口限流（默认 300 次/60s，`RATE_LIMIT_AUTHORIZE_RPM`）。本端点无认证且每次调用写一个 Redis 暂存键，若不限流可被灌满键空间。限流器故障时 fail-open（PRD §6.0）。

**PKCE 说明**：协议层与当前 V002 数据库约束均为 S256-only，不接受 `plain`；V001 曾允许 `plain` 仅作为早期 schema 历史。

---

### 5.2 授权确认端点

```
POST /oauth/authorize/consent
```

授权流程的第二段。这是 SAST Link 自有端点而非 RFC 定义端点，因此**使用标准响应信封**。

**Headers**: `Authorization: Bearer <access_token>`
**Content-Type**: `application/json`

**Request**:

```json
{
  "request_id": "ar_3f2a1b...",
  "approve": true
}
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `request_id` | 是 | `GET /oauth/authorize` 重定向携带的暂存标识 |
| `approve` | 是 | 用户决定。字段缺失返回 `40000`，不默认为拒绝 |

**Response** `200`:

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "redirect_uri": "https://app.example.com/callback?code=ac_abc123&state=xyz"
  }
}
```

前端拿到 `redirect_uri` 后自行 navigate。此处返回 JSON 而非 302，是因为调用方是授权页自身的 fetch——302 会被 fetch 跟随，浏览器不会跳转。

**说明**：

- 用户身份取自校验过的 access token，**不从请求体读取**
- 授权码的 client / scope / PKCE challenge / nonce 全部取自暂存内容，不采信请求体回传值。否则调用方可以确认一个请求而为另一个客户端或另一组 scope 签发授权码
- 暂存内容以 GetDel 原子消费，一个 `request_id` 最多产出一个授权码；并发重复提交只有一个成功，其余返回 `40000`
- `approve: false` 同样返回 `200` 与一个 `redirect_uri`，其中携带 `error=access_denied` 与原始 `state`（RFC 6749 §4.1.2.1 要求把拒绝告知客户端，而非静默丢弃）
- 授权码有效期 5min，一次性使用，`family_id` 在此刻生成并由授权码传递给后续 token pair
- 客户端状态、`redirect_uri` 与 `scopes` 在本段**重新校验**：两段之间客户端被停用返回 `40402`，暂存的 `redirect_uri` 或 `scopes` 已不在客户端当前注册值中则返回 `40000`。管理员摘掉一个被攻陷的回调地址、或收回一个客户端的 admin scope 之后，不应该还有授权码继续按旧注册签发
- 按**用户**限流（`RATE_LIMIT_CONSENT_RPM`，默认 60/min），且只对 approve 路径计费——`approve: false` 的拒绝不铸码、不消耗配额；被限流的 approve 在消费暂存**之前**即返回 `42900`，窗口恢复后可用同一 `request_id` 重试，无需重新发起授权

**错误码**: `40000`（`request_id` / `approve` 缺失、未知字段、Content-Type 非 JSON、暂存已过期或已消费、`redirect_uri` 已不在客户端注册值中、暂存的 `scopes` 已超出客户端当前注册范围）、`40100`/`40101`/`40102`（未登录、token 已过期或 token 无效）、`40402`（两段之间客户端被停用，HTTP 状态为 `404`）、`40301`（账号已注销——本端点在 JWT 中间件之后，注销账号在中间件即被拦下，返回 `40301` 而非 service 层的 `40300`）、`42900`（请求过于频繁，按用户限流，仅 approve 路径计费，带 Retry-After）、`50300`（Redis 暂存不可读，fail-closed）、`50000`（服务器内部错误）

> `40402` 在本端点对应 HTTP `404` 而非 `401`。调用方是已登录的用户，其自身凭证没有问题，出问题的是第三方客户端；返回 `401` 会让授权页把用户推去重新登录，而重新登录无法解决客户端被停用。这也让业务码与 `{HTTP 状态}{序号}` 的编号规则保持一致。

**同路径 GET：同意页元数据**

```
GET /oauth/authorize/consent?request_id=ar_3f2a1b...
```

**Headers**: `Authorization: Bearer <access_token>`

同意页在渲染前调用本端点，读取**服务端校验过**的客户端元数据，而不是信任 consent URL 上可被伪造的 `client_name` / `scope` 参数——攻击者可以构造一条指向同意页的链接：带自己发起的合法 `request_id`，却伪造一个可信应用名，受害者看到的是 SAST、点「同意」实际授权给恶意应用。展示值必须来自本端点。

**Response** `200`:

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "client_name": "Evento",
    "scopes": ["openid", "profile"],
    "expires_in": 600
  }
}
```

| 字段 | 说明 |
|------|------|
| `client_name` | 应用名，取自暂存（authorize 时从已验证客户端记录写入），URL 无法覆盖 |
| `scopes` | 该授权请求申请的 scope，同样来自暂存 |
| `expires_in` | 暂存剩余秒数，供页面显示截止时间并阻止超时后提交 |

**说明**：

- **peek 不消费**：读取暂存但不用 GetDel，查看页面不烧掉请求，用户随后仍可正常提交 `POST /oauth/authorize/consent`
- `request_id` 为 128-bit 随机值，不可枚举
- 本端点按**用户**限流（`RATE_LIMIT_CONSENT_INFO_RPM`，默认 60/min），而非 IP——校园 egress 共享一个 NAT IP，按 IP 限流会被单个学生耗尽全校配额；认证用户随机打 `request_id` 刷 Redis GET 有上限
- 暂存不存在或已过期返回 `40000`；Redis 暂存不可读返回 `50300`（fail-closed，同 POST）

**错误码**: `40000`（`request_id` 缺失 / 无效或已过期）、`40100`/`40101`/`40102`、`40301`（账号已注销）、`42900`（请求过于频繁，按用户限流）、`50300`、`50000`

---

### 5.3 Token 端点

```
POST /oauth/token
```

支持 `authorization_code` 和 `refresh_token` 两种 grant_type。第一方应用使用 PKCE 无需 `client_secret`，第三方应用需提供 `client_secret`。scope 包含 `openid` 时响应额外返回 `id_token`（EdDSA / Ed25519 签名 JWT）。此端点不遵循标准响应信封，请求体使用 `application/x-www-form-urlencoded`，成功和错误均使用 RFC 6749 格式。

**Request**（第一方应用 / PKCE，`application/x-www-form-urlencoded`）:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=auth_code_abc123...&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5&code_verifier=pkce_verifier_raw_string...
```

**Request**（第三方应用 / client_secret，`application/x-www-form-urlencoded`）:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=auth_code_abc123...&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&client_id=9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5&client_secret=3K7mDzX434GbFm9YAePJ9FXQNjT6MF0U&code_verifier=pkce_verifier_raw_string...
```

**Response** `200`:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJFZERTQSIs...",
  "scope": "openid profile"
}
```

**说明**：响应体固定额外返回 `id_token`（EdDSA / Ed25519 签名 JWT），详见 [8.4 ID Token](#84-id-token)。本服务要求所有 scope 都必须包含 `openid`（授权端点与客户端注册时均强制校验），因此不存在不返回 `id_token` 的情形；不含 `openid` 的授权请求会以 `invalid_scope` 被拒绝，纯 OAuth2（非 OIDC）模式不受支持。

**Access Token 的适用范围**：此处签发的 `access_token` 用于 `/userinfo` 及其他以本服务为 resource server 的 OAuth 受保护资源。token 的 `azp` claim 记录签发对象：内部会话端点（`/auth/logout` 等）只接受内置 first-party 客户端签发的 token，第三方 token 会得到 `403`（业务码 `40300`）。这不是限流或临时限制，而是权限边界：第三方获得用户授权意味着可以读取被授权的 claims，不意味着可以代替用户修改账号。要访问 `/user/*` 自助面需 `user:*` scope（任何客户端可申请，只操作本人记录，见 §5.1、§6.7）；要访问 `/admin/*` 管理面需 `admin:*`（仅 `third_party` 可持有，且用户须为管理员，见 §6.7）。

**Refresh Token 模式**（第一方应用，`application/x-www-form-urlencoded`）:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=rt_abc123...&client_id=9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5
```

**Refresh Token 模式**（第三方应用，`application/x-www-form-urlencoded`）:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=rt_abc123...&client_id=9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5&client_secret=3K7mDzX434GbFm9YAePJ9FXQNjT6MF0U
```

**响应头**：成功响应固定携带 `Cache-Control: no-store` 与 `Pragma: no-cache`（RFC 6749 §5.1）。若被共享缓存缓存，一个客户端的 token 可能被投递给另一个客户端。

**错误响应**（RFC 6749 §5.2，不使用标准信封）:

```json
{
  "error": "invalid_grant",
  "error_description": "授权码无效"
}
```

| HTTP | `error` | 触发条件 |
| ------ | --------- | ---------- |
| `400` | `invalid_request` | 缺少必填参数、Content-Type 非 `application/x-www-form-urlencoded`、重复参数 |
| `400` | `invalid_grant` | 授权码无效/已过期/已使用、PKCE 校验失败、`redirect_uri` 不一致、授权码或 refresh token 不属于该客户端、refresh token 已撤销或过期、账号已注销 |
| `400` | `unsupported_grant_type` | `grant_type` 非 `authorization_code` / `refresh_token` |
| `400` | `unauthorized_client` | 客户端未注册该 grant type |
| `400` | `invalid_scope` | 授权码携带的 scope 已不在客户端当前注册范围内（签发后被管理员收回）。该授权码仍被消耗，不可重放 |
| `401` | `invalid_client` | 客户端认证失败（RFC 6749 §5.2 单独规定此项为 401，其余皆为 400）。**不附带 `WWW-Authenticate`**：本服务只从表单体读取 `client_secret`，discovery 仅通告 `none` 与 `client_secret_post`，通告未实现的 Basic 方案会让客户端反复重试并始终失败 |
| `429` | `temporarily_unavailable` | 按调用方 IP 限流（`RATE_LIMIT_TOKEN_RPM`，默认 300 次/60s），附带 `Retry-After`。`/oauth/revoke` 与本端点共用同一限流器 |
| `500` | `server_error` | 服务器内部错误 |

**客户端认证**：

- 公开客户端（`oauth_clients.client_secret` 为 NULL）仅凭 PKCE 认证，**不得携带 `client_secret`**。携带则返回 `invalid_client`——这说明客户端搞错了自己的类型，静默接受会掩盖配置错误
- **所有客户端认证失败共用同一条 `error_description`（`客户端认证失败`）**，不区分「客户端不存在」「公开客户端多带了 secret」「机密客户端少带了 secret」「secret 不匹配」。文案若不同，调用方拿一个已知 `client_id` 各发一次带/不带 secret 的请求，就能判定该客户端是否存在、以及它是公开还是机密——`client_id` 本身按设计公开（出现在授权 URL 与前端代码里），需要保护的是客户端的配置，而「目标是公开客户端」对攻击者有价值。`/oauth/authorize` 出于同样理由对「停用」与「不存在」也回答一致，两个端点不应互相矛盾。具体失败原因保留在服务端日志与审计记录中
- 机密客户端必须提供 `client_secret`，以 SHA-256 + 常量时间比较校验
- 请求参数只从**请求体**读取，query string 被忽略。授权码与 refresh token 若出现在 URL 中会进入访问日志与浏览器历史
- 重复参数（如两个 `grant_type`）直接拒绝（RFC 6749 §3.2）。若择一采用，本服务与链路上的代理/网关可能对生效值产生分歧，即典型的参数走私缺口

**授权码模式行为**：

- 授权码单次使用。**PKCE 校验失败同样消耗授权码**——否则窃得授权码的攻击者可对着一个始终有效的 code 无限枚举 `code_verifier`
- 授权码重放（第二次兑换）触发 `family_id` 全链级联撤销：首次兑换签发的 access / refresh token 一并作废并失效其 auth-state 缓存（PRD §4.10）
- 授权码过期不触发级联撤销：过期的 code 从未被兑换，没有需要惩罚的 family

**Refresh Token 模式行为**：

- 轮换式：旧 refresh token 立即撤销，`sequence + 1`
- 重放已轮换的 refresh token 触发整条 family 级联撤销。轮换后 30s 内（`refreshGracePeriod`）的并发刷新视为良性，不触发级联撤销；超出窗口的重放才撤销整条 family
- **不支持 scope 收窄**。RFC 6749 §6 允许 refresh 时请求更小的 scope，但当前仓储层要求轮换后的 token pair 携带与当前完全一致的 scope，因此轮换后 scope 原样继承。客户端如需更小的 scope，须重新走一次授权流程。这是已知偏差
- 轮换不是重新认证，因此 ID Token 的 `auth_time` 保持该 family 首个 refresh token 的创建时刻
- **能力 family 生命周期封顶**：携带 `admin:*` / `user:*` 能力 scope 的 refresh family 受 `JWT_REFRESH_CAPABILITY_MAX_LIFETIME`（默认 `168h`，`0` 关闭）约束——从 family 首次授权起算，首个 refresh token 与每次轮换都按 `origin+cap` 夹紧到期时间，family 到点即撤销并返回 `invalid_grant`（审计 `refresh_family_expired`），客户端必须重新走授权。普通 OIDC family 与内部会话 family 不受此约束

---

### 5.4 Token 撤销

```
POST /oauth/revoke
```

**Request**（`application/x-www-form-urlencoded`）:

```http
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=rt_abc123...&token_type_hint=refresh_token&client_id=9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5
```

| 参数 | 必填 | 说明 |
| ------ | ------ | ------ |
| `token` | 是 | 待撤销的 refresh token 或 access token |
| `token_type_hint` | 否 | `refresh_token` / `access_token`，仅调整查找顺序 |
| `client_id` | 是 | 客户端标识 |
| `client_secret` | 条件 | 机密客户端必填 |

**Response** `200`：空响应体。

**说明**:

- 撤销整条 token family。客户端要求撤销 family 中任一 token，意味着结束该会话；若只撤销单个 token，同族 access token 在其 TTL 内仍然可用，与调用方意图相悖
- 未知、已撤销的 token **一律返回 `200`**（RFC 7009 §2.2）。客户端的诉求是「该 token 不再可用」，这已经成立；反之则会把本端点变成探测 token 是否存在的 oracle
- `token_type_hint` 猜错只影响查找顺序，token 仍会被撤销（RFC 7009 §2.1）
- 撤销 access token 时**验证签名**后取其 `jti`，而非仅解码 JWT。未验签的 claim 是攻击者可控的，若信任其中的 `jti`，任何人伪造一个即可撤销任意 family
- **提交已过期的 access token 同样会撤销整条 family**，而不是当作「查不到」直接回 `200`。本端点的语义是 family 级：提交的那个 access token 自己失效，不代表它所属的 family 失效——同族 refresh token 可能还有数十天寿命（默认 `JWT_REFRESH_TOKEN_EXPIRY=720h`），而客户端闲置后登出时，手上的 access token 恰恰通常已经过期。此时只放宽 `exp` 一项校验：签名、`kid`、`iss`、`aud`、`nbf` 全部照验，归属仍以数据库行的 `client_id` 判定，因此伪造 `jti` 换不到别人的 family
- 不属于该客户端的 token 视为「未找到」，同样返回 `200`，因此一个客户端无法结束另一个客户端的会话
- 客户端认证失败返回 `401 invalid_client`，`token` 缺失返回 `400 invalid_request`，限流返回 `429 temporarily_unavailable`（与 `/oauth/token` 共用同一按 IP 限流器）
- **撤销事务失败返回 `500 server_error`，不返回 `200`**。RFC 7009 的成功语义是「该 token 不再可用」；数据库故障时谎报 `200` 会让客户端以为会话已终止而不再重试，实际 token 在其整个 TTL 内仍然有效

---

### 5.5 授权应用管理

用户在同意页授权过的应用在本节管理。两个端点都要求 Bearer 认证，使用标准信封。

```
GET /oauth/grants
```

**Headers**: `Authorization: Bearer <access_token>`

**Response** `200`:

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "grants": [
      {
        "client_id": 3,
        "client_key": "9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5",
        "client_name": "Evento",
        "client_type": "third_party",
        "redirect_uris": ["https://evento.sast.fun/oauth"],
        "is_active": true,
        "scopes": ["openid", "profile"],
        "last_authorized_at": "2026-05-28T12:00:00Z"
      }
    ]
  }
}
```

**说明**：

- 返回该用户授权过的**不同应用**，每个客户端一行，取最近一次授权记录：`last_authorized_at` 是该用户对该客户端最近一次点击同意的时间，`scopes` 为那次授权的 scope
- 授权记录是**长效持久化**的（V009 起存于独立的 `oauth_grants` 表，与一次性授权码分离），不会随授权码过期或定时清理消失；同一个应用重复授权是**覆盖**记录而非累积
- 客户端被停用（`is_active: false`）仍会列出——用户需要看到「我授权过但已失效」的应用，而不是凭空消失；此时该客户端的 token 已被停用事务撤销
- `client_id` 是客户端**主键**（与客户端列表的 `id` 一致，即 `DELETE /oauth/grants/:client_id` 要用的值）；`client_key` 才是客户端对外标识（授权端点与 token 交换里的 `client_id`）

> **限流**：列表与撤销按**用户**分别计费（`RATE_LIMIT_GRANTS_RPM`，默认各 60/min），fail-open（PRD §6.0）。两者共用键值会把「读列表」的配额与「切掉可疑应用」的配额混在一起——一个轮询列表的页面会耗尽用户用于撤销的预算，而撤销恰是用户想赶在攻击窗口内完成的动作；故拆成独立预算。超限返回 `42900` 并带 `Retry-After`，与 consent 提交一致。

```
DELETE /oauth/grants/:client_id
```

**Headers**: `Authorization: Bearer <access_token>`

**Response** `200`:

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "message": "已撤销该应用的授权"
  }
}
```

**说明**：

- `:client_id` 为客户端主键（`GET /oauth/grants` 返回的 `client_id`）
- 撤销语义是「断开该应用的访问」：先撤销该用户持有该客户端的全部活跃 Access / Refresh Token 并失效对应 auth-state 缓存，再在一个事务内删除该客户端的授权记录（`oauth_grants`）**和在途授权码**（`oauth_authorizations`）。应用随即从已授权列表消失，下次使用必须重新走同意页；在途授权码一并删除，撤销前几分钟签发的 code 也不会再兑换出新 token
- 两步各为独立事务，token 撤销在前：即使删除授权历史失败，该应用的访问已被切断（fail-closed），只是列表仍可能短暂显示它
- 撤销一个从未授权过的客户端返回 `200`（幂等）：用户的诉求「该应用不再有我的授权」已经成立
- 审计 action 为 `oauth_grant_revoke`（`resource = oauth`）。`resource_id` 是被撤销客户端的主键，`actor_client_id` 是调用方自己的 `azp`：这条 action 的行为主体与被操作对象不是同一个客户端

**错误码**：`40000`（`client_id` 非正整数）、`40100`/`40101`/`40102`（未登录、token 已过期或无效）、`40301`（账号已注销，JWT 中间件即拦下）、`50000`

---

## 6. 管理后台（Admin）

> **实现状态**：本章全部端点已注册。
>
> 以下四处对 OpenAPI 契约做了收紧，实现按本文档为准：
>
> 1. **`PUT /admin/users/:id` 不接受 `state: is_deleted`**，返回 `422`。注销必须走 `DELETE`，恢复必须走 `PUT .../restore` —— 只有这两条路径会在同一事务内撤销该用户的全部 Token。若允许 PUT 直接置为 `is_deleted`，会留下「账号已注销但 Refresh Token 仍可换新 Access Token」的窗口。对已注销用户执行 PUT 同样返回 `422`，需先恢复。
> 2. **`email_type` 只能与 `login_email` 一同提交，且必须与其域名一致**，否则返回 `400`。V001 触发器 `auto_set_email_type` 仅在 `login_email` 出现在 UPDATE 列中时才重算该字段，单独提交 `email_type` 会写入与邮箱域名矛盾的值。
> 3. **`page_size` 上限统一为 100**（含 `/admin/audit-logs`，契约未定上限）。超出上限按 100 截断，不报错。`page` / `page_size` 传非正整数或非数字返回 `400`，不静默回落默认值。`page` 另有上限 2^30：偏移量由 `page × page_size` 算出，`page` 过大时该乘积会整数溢出，`4611686018427387905` 恰好绕回 0，会在回显所请求页码的同时返回第一页——溢出按 `400` 拒绝而非截断，避免答非所问。
> 4. **`keyword` 长度上限 255**（所匹配列的最宽列宽）。超长返回 `400`：该参数会展开为三个无法走索引的 `ILIKE` 加一次全表 `COUNT(*)`，且本组端点未接入限流。
> 5. **批量接口单次上限**：`GET /admin/users/batch` 的 `ids` 最多 100 个、`PUT /admin/users` 的 `ids` 最多 500 个，超出返回 `400`（不截断——静默截断会让调用方拿到的结果无法与其输入对齐）。
>
> 另有三条契约未写明的管理员自我保护规则，均返回 `403`：不可修改自己的 `role`；不可注销自己的账号；不可将系统中最后一名活跃管理员降权或注销（「活跃」指 `role = admin` 且 `state <> is_deleted`）。三者都是不可自行恢复的锁死场景 —— 能撤销该操作的端点正是被交出的那一个。
>
> `department` 筛选跨表关联 `profile`，采用 `LEFT JOIN`，因此无 `profile` 行的用户在**不带** `department` 筛选时正常出现在列表中（`department` 为 `null`）；带该筛选时自然被排除。

**鉴权：两道互不蕴含的门**

本章每个端点同时经过角色门与 scope 门，缺任一均返回 `403 40300`：

- **角色门**回答「这个用户是否被允许」。角色取自数据库行而非 token claim，因此降权在下一个请求即生效。
- **scope 门**回答「这个凭证是否被授权」，只约束委派调用。内置控制台 token（`azp` 等于 `INTERNAL_OAUTH_CLIENT_ID` 或无 `azp`）豁免此门，其上限即角色门。

**委派调用**：任何 `third_party` 客户端，只要其注册的 `scopes` 含 admin scope，即可代管理员调用本章端点 —— 读端点接受 `admin:read` 或 `admin:write`，写端点要求 `admin:write`。不持有 admin scope 的第三方 token 一律被拒，无论其用户角色为何。

判定依据只有注册表的 `scopes` 一列，不存在被硬编码的客户端名单：任何客户端的可请求 scope 都被钉死在其注册值内，而 `first_party` 无论注册值如何都拿不到 admin scope（见 §5.1），因此「token 携带 admin scope」本身就证明了「该注册被授予过它」。授予由 `POST` / `PUT /admin/oauth-clients` 把守，条件见 §6.7。

委派 token 的 `sub` 仍是那位管理员本人，权限上限始终是该用户的角色——普通成员持 admin scope 被角色门拒绝，admin 角色用户才能让 admin scope 生效，降权下一请求即失效。admin scope 允许 `refresh_token`：`/admin` 的角色门从数据库行读取主体角色，刷新一个 admin-scoped token 不会拓宽谁能用它；但携带能力 scope 的 refresh family 受 `JWT_REFRESH_CAPABILITY_MAX_LIFETIME`（默认 `168h`）**生命周期封顶**，从首次授权起算、到点即撤销并需重新授权（§5.4）。停用方式是把该客户端置为 `is_active = false`，同一操作会撤销它的全部存活 token。

**一个接入方用一个客户端即可**：一个 `third_party` 机密客户端可同时持有 `admin:*`（管理）与 `user:*`（自助），refresh 允许（受同一生命周期封顶约束）。普通用户经它自助读/改自己的资料，admin 角色用户经它查人/改角色/封禁——能力由 `/admin` 的角色门按 token 主体区分，无需拆客户端。第三方应用读当前登录用户只能经 `/userinfo`（§8.3）。

**`/user/*` 自助面**：token 必须携带 `user:read` / `user:write` 才能访问，`user` scope 对任何客户端类型开放（§5.1、§6.7）——`/user/*` 每个端点都只操作 token 主体本人的记录，所以应用持有 `user:*` 只是代表用户本人自助，不是查他人。被授予对应 user scope 的客户端（经控制台 `POST` / `PUT /admin/oauth-clients`），其 token 即可访问相应 `/user/*` 端点——读端点接受 `user:read` 或 `user:write`，写端点要求 `user:write`，内置控制台 token 豁免 scope 门。没有 user scope 的 token 一律 `403 40300`。要读当前登录用户的 OIDC 视图，用 `GET /userinfo`（见 §8.3）——它是全服务唯一不要求能力 scope 就服务第三方 token 的端点。字段对应关系：`login_email` → `email`，`nickname` → `preferred_username`（无昵称时回落为真名），`avatar` → `picture`，用户 ID 为字符串形式的 `sub`，角色为 `role`（`profile` scope，取自签发时的数据库行）。`/userinfo` **不返回** `state`、`student_id`、`college`、`major`、`phone_number`、`qq_number`；需要这些字段的第一方应用直接读 `/user/profile`（返回全部报名字段），第三方则需 admin token 走 `GET /admin/users/:id`。

客户端可以共用同一组 `redirect_uris`：`redirect_uri` 只需存在于**该 client 自己**的注册列表中，不要求全局唯一，因此一个应用用一个回调端点承载两条腿即可，按 `state` 区分。

### 6.1 用户列表

```
GET /admin/users
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin / lecturer 角色），委派调用需 `admin:read` 或 `admin:write` scope

**Query Parameters**:

| 参数 | 说明 |
| ------ | ------ |
| `page` | 页码，默认 1 |
| `page_size` | 每页条数，默认 20，最大 100 |
| `role` | 筛选角色：freshman / member / lecturer / admin |
| `state` | 筛选状态：on_sast / retired_sast / njupter / is_deleted |
| `department` | 筛选部门：software / media |
| `student_id` | 筛选学号 |
| `keyword` | 搜索关键词（姓名/学号/邮箱模糊匹配，大小写不敏感；`%`、`_`、`\` 按字面量处理，不作通配符） |

**说明**：不带 `state` 筛选时列表包含已注销用户（`state = is_deleted`），否则无法找到并恢复它们。

**错误码**：`40000`（分页参数非法 / `role`、`state`、`department` 取值非法）、`40100`、`40300`。

**Response** `200`:

```json
{
  "users": [
    {
      "id": 1,
      "name": "张三",
      "student_id": "B2404****",
      "college": "计算机学院、软件学院、网络空间安全学院",
      "major": "软件工程",
      "login_email": "b2404****@njupt.edu.cn",
      "role": "freshman",
      "state": "njupter",
      "email_type": "njupt_email",
      "phone_number": "13800138000",
      "qq_number": "1234567890",
      "department": "software",
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    }
  ],
  "total": 500,
  "page": 1,
  "page_size": 20
}
```

---

### 6.2 用户详情

```
GET /admin/users/:id
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin / lecturer 角色），委派调用需 `admin:read` 或 `admin:write` scope

**说明**：`id` 非数字或非正整数一律返回 `404`（与用户不存在同一响应），不区分两者。`identities` 不含第三方 `access_token` / `refresh_token`，也不含 `identity_data`——该字段存的是第三方返回的完整用户对象（飞书含 `mobile`、`email`、`enterprise_email`、`employee_no`），本端点 lecturer 亦可读，列出绑定不等于交出绑定背后的联系方式。

**错误码**：`40100`、`40300`、`40401`。

**Response** `200`:

```json
{
  "id": 1,
  "name": "张三",
  "student_id": "B2404****",
  "college": "计算机学院、软件学院、网络空间安全学院",
  "major": "软件工程",
  "login_email": "b2404****@njupt.edu.cn",
  "role": "freshman",
  "state": "njupter",
  "email_type": "njupt_email",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "profile": { ... },
  "identities": [ ... ],
  "created_at": "2026-05-28T12:00:00Z",
  "updated_at": "2026-05-28T12:00:00Z"
}
```

---

### 6.3 更新用户

```
PUT /admin/users/:id
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Request**（所有字段可选，仅传需要修改的字段）:

```json
{
  "name": "张三",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "student_id": "B2404****",
  "college": "计算机学院、软件学院、网络空间安全学院",
  "major": "软件工程",
  "login_email": "b2404****@njupt.edu.cn",
  "role": "member",
  "state": "on_sast",
  "email_type": "njupt_email"
}
```

**说明**：

- 至少传一个字段，否则返回 `400`。未知字段（含 `password`、`token_version`、`id`、`profile`）一律返回 `400`，不静默忽略。
- `name` / `phone_number` / `qq_number` / `student_id` 不可传空串（列为 `NOT NULL`）；`major` 可置空。长度按 V001 列宽校验，中文按字符数而非字节数计。
- `login_email` 域名限 `@njupt.edu.cn` / `@sast.fun`，会被规范化为小写；修改后触发器重算 `email_type`。
- `role` 实际发生变化时，同一事务内递增 `token_version` 并撤销该用户全部 Token，响应 `message` 变为 `"用户信息更新成功，已撤销该用户的全部 Token"`。仅提交与当前值相同的 `role` 不算变化，不触发撤销。
- `state` 可在 `njupter` / `on_sast` / `retired_sast` 之间任意修改（供管理员纠错），但不接受 `is_deleted`。

**错误码**：`40000`（字段校验失败 / 未知字段 / 无可更新字段）、`40100`、`40300`（改自己的 role / 降权最后一名管理员）、`40401`、`40901`（邮箱已被占用）、`40902`（学号已被占用）、`42200`（`state` 为 `is_deleted` 或目标已注销）。

**Response** `200`:

```json
{
  "message": "用户信息更新成功"
}
```

---

### 6.4 注销用户（软删除）

```
DELETE /admin/users/:id
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Response** `200`:

```json
{
  "message": "用户已注销"
}
```

**说明**: 将 `user.state` 设为 `is_deleted`，保留数据；同一事务内递增 `token_version` 并撤销该用户全部 Access / Refresh Token（应用层逐个撤销，非 DB 级联删除），撤销的 JTI 写入 outbox，worker 失效其 auth-state 缓存。

不可注销自己的账号，也不可注销系统中最后一名活跃管理员，均返回 `403`。重复注销返回 `422`。

**错误码**：`40100`、`40300`、`40401`、`42200`（用户已注销）。

---

### 6.5 恢复已注销用户

```
PUT /admin/users/:id/restore
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Response** `200`:

```json
{
  "message": "用户已恢复"
}
```

**说明**: 将 `user.state` 从 `is_deleted` 恢复至 `njupter`。不记忆注销前的状态 —— 原 `on_sast` 成员恢复后为 `njupter`，需管理员另行调整。已撤销的 token 不恢复，需用户重新登录。

对未注销的用户调用返回 `422`。

**错误码**：`40100`、`40300`、`40401`、`42200`（用户未被注销）。

---

### 6.5.1 批量查询用户（按 ID）

```
GET /admin/users/batch?ids=1,2,3
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin / lecturer 角色），委派调用需 `admin:read` 或 `admin:write` scope

**Query Parameters**:

| 参数 | 说明 |
| ------ | ------ |
| `ids` | 逗号分隔的用户 ID 列表，单次最多 **100** 个，超过需分页调用 |

**说明**：

- 返回的 `users` 数组**按请求顺序**排列（People 的邮件批次目标 / 阅卷列表需要与输入对齐），重复 ID 只返回一次（按首次出现位置）。
- **不存在的 ID 直接缺席**（不报错，调用方自行 diff 重试）；已注销用户照常返回（与 `GET /admin/users/:id` 一致）。
- 每条记录字段与 `GET /admin/users/:id` 完全一致（含 `profile` / `identities`），People 可直接复用现有转换逻辑。
- `ids` 缺失、含非数字/非正整数段（如 `1,abc,2`、`1,,2`）、超过 100 个，均返回 `400`——静默丢弃非法段会返回一个无法与输入对齐的列表。

**错误码**：`40000`（ids 缺失 / 非法 / 超上限）、`40100`、`40300`。

**Response** `200`:

```json
{
  "users": [
    {
      "id": 1,
      "name": "张三",
      "student_id": "B2404****",
      "college": "计算机学院、软件学院、网络空间安全学院",
      "major": "软件工程",
      "login_email": "b2404****@njupt.edu.cn",
      "role": "freshman",
      "state": "njupter",
      "email_type": "njupt_email",
      "phone_number": "13800138000",
      "qq_number": "1234567890",
      "profile": { ... },
      "identities": [ ... ],
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    }
  ]
}
```

---

### 6.5.2 批量修改用户角色

```
PUT /admin/users
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Request**:

```json
{
  "ids": [1, 2, 3],
  "role": "member"
}
```

**说明**：

- `ids` 单次最多 **500** 个（招新录取批量升级一次可覆盖），重复 ID 去重后只执行一次；`role` 枚举与单条接口一致：freshman / member / lecturer / admin。
- **逐条独立执行（非原子）**：每个 ID 走与 `PUT /admin/users/:id` 完全相同的守卫与事务——不可修改自己的角色（403 语义）、系统至少保留一名管理员、已注销用户拒绝（需先恢复）；角色实际变化时同一事务递增 `token_version` 并撤销该用户全部 Token。**freshman→member 批量录取后，被录取者需重新登录一次**（与单条行为一致）。
- 请求本身合法即返回 `200`，**失败是逐条数据而非传输错误**：`results` 与去重后的 ids 一一对应，调用方对失败项重试或告警。
- 未知字段 / 尾部多余内容返回 `400`（strict 解码）。
- 审计：每个 ID 各记一条 `admin_user_update`，detail 含 `"batch": true` 标记，便于控制台区分批量操作与单条编辑。

**错误码**：`40000`（ids 为空 / 超过 500 / 含非正整数 / role 取值非法 / 未知字段）、`40100`、`40300`。

**Response** `200`:

```json
{
  "results": [
    { "id": 1, "success": true, "role": "member" },
    { "id": 2, "success": false, "reason": "用户不存在" },
    { "id": 3, "success": false, "reason": "用户已注销，请先恢复后再编辑" }
  ]
}
```

`reason` 取值：`用户不存在` / `用户已注销，请先恢复后再编辑` / `不可修改自己的角色` / `系统中至少需要保留一名管理员` / `服务器内部错误`。

---

### 6.6 OAuth 客户端列表

```
GET /admin/oauth-clients
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:read` 或 `admin:write` scope

**Response** `200`:

```json
{
  "clients": [
    {
      "id": 1,
      "client_id": "9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5",
      "client_name": "Evento",
      "client_type": "first_party",
      "redirect_uris": ["https://evento.sast.fun/oauth"],
      "grant_types": ["authorization_code", "refresh_token"],
      "scopes": ["openid", "profile"],
      "is_active": true,
      "created_at": "2026-05-28T12:00:00Z",
      "updated_at": "2026-05-28T12:00:00Z"
    }
  ]
}
```

---

### 6.7 注册 OAuth 客户端

```
POST /admin/oauth-clients
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Request**:

```json
{
  "client_name": "新应用",
  "client_type": "third_party",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile"]
}
```

**Response** `201`:

```json
{
  "id": 3,
  "client_id": "9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5",
  "client_secret": "3K7mDzX434GbFm9YAePJ9FXQNjT6MF0U",
  "client_name": "新应用",
  "client_type": "third_party",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile"],
  "is_active": true,
  "created_at": "2026-05-28T12:00:00Z",
  "updated_at": "2026-05-28T12:00:00Z"
}
```

**说明**:

- `first_party` 不返回 `client_secret`：它是公开客户端，仅靠 PKCE。PKCE 对 `third_party` 同样强制，两者的差别只是后者还需再带 `client_secret`。
- `scopes` 对两类客户端一律生效：注册 `["openid"]` 的客户端请求 `profile` 会被 `/oauth/authorize` 拒绝，需要新增 scope 就得改注册（留下 `update_oauth_client` 审计行）。第一方曾被豁免此校验，已移除。
  - 其他边界：`client_id` 由服务端随机生成，无法冒充内置客户端；`first_party` token 的 `azp` 不等于 `INTERNAL_OAUTH_CLIENT_ID`，因此**打不到内部接口**（`/user/*`、`/auth/*`）；同意页展示的是服务端暂存的 scope，不是同意 URL 里的值。
- `client_secret` 只在本次响应中出现一次，服务端仅存哈希，事后无法再取回。丢失只能重新注册客户端。
- `client_id` 由服务端生成，请求中不接受该字段。传入 `client_id`、`client_secret` 或 `id` 会返回 `400`，而非被忽略。
- `redirect_uris` 校验规则（注册阶段拒绝，返回 `400`）：
  - 仅允许 `https`；`http` 只允许 loopback 主机（`localhost`、`127.0.0.1`、`[::1]`），供本地开发使用。`localhost` 按 ASCII 大小写折叠（`LOCALHOST` 可以），但不接受 Unicode 折叠等价写法（如 `localhoſt`）——那是 DNS 视角下的另一个主机名
  - 不得包含 fragment（`#...`）、userinfo（`user:pass@`）
  - 必须是绝对 URI，不允许相对路径或 `//host/path` 形式
  - 不得有首尾空白：`/oauth/authorize` 按字节精确匹配，带空白的注册值永远匹配不上
  - 最多 10 条，单条最长 2048 字符，不允许重复
- `grant_types` 只允许 `authorization_code` 与 `refresh_token`，且必须包含 `authorization_code`。
- `scopes` 必须包含 `openid`，且仅含受支持的值，与 `/oauth/authorize` 使用同一套校验。
- **`scopes` 可包含 `admin:read` / `admin:write`，即「委派管理」**：持有 admin scope 的注册，其 token 可代授权管理员访问 `/admin/*`。委派身份**只由注册表的 scopes 决定**，不存在被硬编码的客户端名单——因此接入一个新的运维工具是一次控制台操作，不需要改代码或写迁移。授予须同时满足以下四条，任一不满足即拒：
  - 目标必须是 `third_party`（`400`）。`first_party` 是公开客户端，token 端点仅凭 PKCE 认证它，从授权码被签出到管理 token 存在之间只剩 `redirect_uri` 精确匹配一道屏障；机密客户端有两道。`/oauth/authorize` 同样拒绝第一方的 admin scope，所以这里挡住的是一条永远无法行使的授予
  - `grant_types` 两种取值（`authorization_code`、`refresh_token`）均允许，即使客户端持有 admin scope——`/admin` 的角色门从数据库行读取主体角色，刷新一个 admin-scoped token 不会拓宽谁能用它；携带能力 scope 的 refresh family 受 `JWT_REFRESH_CAPABILITY_MAX_LIFETIME`（默认 `168h`）生命周期封顶，到点需重新授权（§5.4）。`authorization_code` 必须包含。
  - 发起该请求的凭证必须是内置控制台客户端（`403`）。委派 token 不能授予或维护委派——否则委派客户端可互相注册、互相复活，管理能力的集合将脱离运维人员的批准而自行增长
  - 授予 admin scope 与改写 `redirect_uris` 不可在同一请求内完成（`400`）。这两件事各自都值得单独审计
- 注意 `/oauth/authorize` 的校验器同样接受 admin scope（它是共享的「scope 集是否合法」判定），因此上述能力规则由本接口把守，而非由授权端点把守。
- scope 可事后修改（见 §6.8），收窄与授予都会连带撤销该客户端的存量 token。

---

### 6.8 更新 OAuth 客户端

```
PUT /admin/oauth-clients/:id
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Request**:

```json
{
  "client_name": "已更名应用",
  "client_type": "third_party",
  "redirect_uris": ["https://new-app.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile"],
  "is_active": false
}
```

**Response** `200`:

```json
{
  "message": "客户端信息更新成功"
}
```

停用（`is_active` 由 `true` 改为 `false`）时，会在同一事务内撤销该客户端已签发的全部 Access / Refresh Token，此时 message 为：

```json
{
  "message": "客户端信息更新成功，已撤销该客户端的全部 Token"
}
```

**说明**:

- 五个字段可改，均为可选；未出现的字段保持不变：`client_name`、`redirect_uris`、`grant_types`、`scopes`、`is_active`。
- `client_id`、`client_secret`、`client_type`、`id` **不可修改**，请求中出现这些字段返回 `400`（strict decoder 拒未知字段，而非静默忽略）——标识符只能由服务端生成，管理员不能把自己的客户端注册成既有标识符。`client_type` 同样不可就地翻转：它决定客户端的凭据模型（有无 `client_secret`）与 scope 授予规则，翻转而不重发 secret 会产生无凭据的第三方客户端；换类型请重新注册一个客户端。
- `scopes` 中出现 `admin:read` / `admin:write` 即授予委派管理，前置条件与注册接口完全一致（见 §6.7）。判定基于**合并后的状态**而非本次提交的字段：给已持有 admin scope 的客户端单独追加 `refresh_token` 是允许的——`/admin` 角色门从数据库行读取主体角色，刷新不拓宽谁能用它（携带能力 scope 的 refresh family 受 `JWT_REFRESH_CAPABILITY_MAX_LIFETIME` 生命周期封顶，见 §5.4）；但向已持有能力 scope 的客户端改写 `redirect_uris`（`403`）、或在授予能力 scope 的同一次请求中改写 `redirect_uris`（`400`）都会被拒，拆包请求无法绕过。
- **已持有能力 scope 的客户端受额外保护**（均返回 `403`）：不可改写 `redirect_uris`（能力级授权码被投递到运维人员自选的主机，等于把整个授权交出去）；只能由控制台维护，委派 token 对其任何字段的修改都会被拒。停用它仍然允许，那是委派管理的 kill switch。
- **能力变化会连带撤销 token**，这是与其他字段的关键区别：
  - **收窄 `scopes`**（旧集合中有值不在新集合里）：在同一事务内撤销该客户端全部存量 Access / Refresh Token。access token 携带的是签发时的 scope，若不撤销，注册表已收窄而凭证仍在断言被收回的能力
  - **新授予能力 scope（admin 或 user）**：同样撤销该客户端存量 token。签发 token pair 时总会一并铸出 refresh 半边，被提升的客户端因此在库中已有休眠的 refresh family；撤销它们才能强制在新 scope 集下重新授权
  - **扩大 `scopes`** 不撤销：存量 token 不会因此获得新 scope，撤销只会为一次不增加其权限的变更而把用户登出
  - 改 `grant_types` 本身不撤销，只约束后续授权流程
- 收回 admin scope 是**即时生效**的，三个时间窗口全部关闭：存量 token 当场撤销；已暂存但未提交同意的授权请求在 `/oauth/authorize/consent` 处被重新校验并拒绝；已签发但未兑换的授权码在 `/oauth/token` 处被重新校验并拒绝（该 code 仍会被消耗，不能重放）。
- `redirect_uris` 的校验规则与注册时一致。
- 停用是安全动作，语义是「立即断开」：已签发的 Access Token 立刻失效（失效 auth-state 缓存 + DB 撤销），Refresh Token 无法再续期，该客户端也无法再发起新的授权请求。
- 重复对已停用的客户端提交 `is_active: false` 不会重复撤销。
- `:id` 为客户端主键（列表接口返回的 `id`，非 `client_id`）。非数字或非正整数返回 `404`。
- **内置客户端受保护**：`INTERNAL_OAUTH_CLIENT_ID`（默认 `sast-link-web`）不可停用，不可改写 `redirect_uris`，也不可修改 `scopes` 与 `grant_types`，四者均返回 `403`；改名允许。修改它的 `scopes` 是一次延迟自毁：服务启动时会断言该客户端的 scope 为规范值，进程当下照常运行，下次重启却直接拒绝引导，只能直连数据库恢复；若是收窄，还会立刻触发上述撤销逻辑，一次性切断全体用户的内部会话。修改它的 `grant_types` 同样是自毁：V003 种子值为 `authorization_code` + `refresh_token`，控制台自身的 OAuth 会话经该客户端的 refresh grant 续期（token 端点对 refresh 活查 `grant_types`），收窄会立即切断续期；且 V003 的 drift 检测把该行钉死在种子值上，改动会中止下一次 `migrate up`。内部会话流程通过 `is_active = TRUE` 解析该客户端，停用它会立刻中断全站登录、刷新与注册，并撤销所有内部会话 token——包括执行该操作的管理员自己的，此后无人能登录回来把开关拨正，只能直连数据库恢复。改写它的 `redirect_uris` 则会把第一方授权码投递到他处。
- 被拒的更新同样写入审计日志；客户端不存在（`404`）也会留下审计记录，避免有人靠遍历主键探测哪些 id 存在而不留痕迹。

---

### 6.9 轮换 OAuth 客户端密钥

```
POST /admin/oauth-clients/:id/rotate-secret
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Response** `200`:

```json
{
  "id": 3,
  "client_secret": "3K7mDzX434GbFm9YAePJ9FXQNjT6MF0U"
}
```

**说明**:

- 为机密（`third_party`）客户端生成新的 `client_secret`，仅其 hash 入库；新明文在本次响应中返回**一次**，之后不可再取回（响应带 `Cache-Control: no-store`），未及时保存只能再次轮换。公开（`first_party`）客户端没有 `client_secret` 可轮换，返回 `400`。
- 发起请求的凭证必须是内置控制台客户端（`403`，委派 token 不能轮换 secret）。
- 存量 Access / Refresh Token **不受影响**：它们从不依赖 client_secret，轮换切断泄露的 secret 而无需把用户登出；token 端点自下次请求起用新 secret 认证。若泄露的是 refresh token 而非 secret，须通过收窄 scope / 停用客户端来切断。
- `:id` 为客户端主键（列表接口返回的 `id`，非 `client_id`）。非数字或非正整数返回 `404`。被拒的轮换同样写入审计日志（`admin_oauth_client_rotate_secret`）。

---

### 6.10 删除 OAuth 客户端

```
DELETE /admin/oauth-clients/:id
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:write` scope

**Response** `200`:

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "message": "客户端已删除，已撤销该客户端的全部 Token"
  }
}
```

**说明**:

- **物理删除，不可恢复**：删除 `oauth_clients` 行，其全部授权码 / Access / Refresh Token 元数据经 `ON DELETE CASCADE` 级联清除；删前在同一事务内撤销活跃 token 并失效 auth-state 缓存，故已签发的 token **即刻全部失效**（不再能通过 `/userinfo` 或任何受保护端点）。`data.message` 在删除触发 token 撤销时提示已撤销该客户端的全部 Token；未撤销任何 token 时消息为「客户端已删除」。撤销计数（审计 `revoked_tokens`）含活跃 Access Token 与未撤销的 Refresh Token（每家族一条）——客户端 Access 已全部过期、仅剩活跃 Refresh 会话时同样计入。
- 内置客户端（`INTERNAL_OAUTH_CLIENT_ID`，默认 `sast-link-web`）**不可删除**（`403`）：内部会话流程按 client_id 解析它，删除会使全站登录 / 刷新 / 注册立即中断，且控制台没有路径恢复（只能直连数据库）。
- 带能力 scope（`admin:*` / `user:*`）的客户端**无额外限制**：删除移除了凭据与其携带的 scope，控制台或委派管理员均可执行——与授予时"仅控制台"（防委派蔓延）不同，删减委派不需要那道收紧。
- `:id` 为客户端主键（列表接口返回的 `id`，非 `client_id`）。非数字或非正整数返回 `404`。被拒的删除（内置客户端、未知 id）同样写入审计日志（`admin_oauth_client_delete`，success=false）。

---

### 6.11 查询审计日志

```
GET /admin/audit-logs
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:read` 或 `admin:write` scope

**Query Parameters**:

| 参数 | 说明 |
| ------ | ------ |
| `page` | 页码，默认 1 |
| `page_size` | 每页条数，默认 50，最大 100 |
| `user_id` | 按用户筛选（正整数） |
| `action` | 按操作类型筛选（精确匹配） |
| `resource` | 按资源类型筛选（精确匹配） |
| `success` | 是否成功：仅接受 `true` / `false`，`1` / `yes` / `TRUE` 返回 `400` |
| `actor_client_id` | 按执行操作的 OAuth 客户端筛选（精确匹配），回答「这个客户端做过什么」 |
| `start_time` | 开始时间（RFC 3339，含时区偏移），**含**该时刻 |
| `end_time` | 结束时间（RFC 3339，含时区偏移），**不含**该时刻 |

**说明**：时间参数必须带时区偏移（如 `2026-07-01T00:00:00Z`），不带偏移返回 `400` —— `created_at` 是 `timestamptz`，擅自按 UTC 解释会使窗口偏移数小时。`end_time` 早于 `start_time` 返回 `400`。排序为 `created_at DESC, id DESC`（`id` 用于同一时刻内的稳定分页）。

管理端写操作在审计日志中的 `action` 为 `admin_user_update` / `admin_user_delete` / `admin_user_restore`（`resource = user`）与 `admin_oauth_client_create` / `admin_oauth_client_update`（`resource = oauth_client`）。OAuth 侧的 `action` 包括 `oauth_grant_revoke`（用户在授权应用列表撤销某个客户端，`resource = oauth`）。失败的操作同样记录，`success = false` 且 `err_code` 为对应业务码。`detail.changed_fields` 只记字段名，不记提交值——`redirect_uris` 列表冗长，事后要问的是「管理员改了哪些属性、是否切断了现有会话」。委派管理能力的变化是唯一的例外，会额外记录取值：`admin_scope_granted`（本次授予的 admin scope 列表）、`admin_scope_revoked`（布尔）与 `scopes_removed`（被移除的 scope 列表）。事后复盘一次管理事件的起点正是「这个客户端不再持有哪些 scope」，而这个问题无法从字段名加一份事后快照推出。

`user_name` 是展示字段：随查询取回对应用户显示名，best-effort。软删除（`state = is_deleted`）的行仍在表里，名字照常返回；仅当用户行被物理删除、或显示名回查失败时为 `null`，此时前端应回退显示 `user_id`。

`actor_client_id` 记录**执行**该操作的 OAuth 客户端（行为主体，而非被操作对象——后者在 `resource_id`）。控制台操作记录内置客户端 id，委派调用记录该第三方客户端的 `client_id`，两者据此可区分「管理员亲自操作」与「工具代其操作」。

目前写入该字段的是管理端五个 action、OAuth 协议端点的 `oauth_authorize` / `oauth_token` / `oauth_revoke`，以及 `/user` 自助面的 `logout` / `change_password` / `update_profile` / `upload_avatar` / `oauth_bind` / `oauth_unbind` / `bind_email_send_code` / `logout_device`（`user:*` 第三方 token 执行时记其 `azp`，控制台会话显式记内置客户端 id）。其余情形为 `null`，且 `null` 是有意义的取值：**没有任何 OAuth 凭证授权该操作** —— 未认证流程（登录、注册、重置密码）、后台任务，以及 V007 迁移之前写入的历史行。历史行的这层歧义会随 90 天保留期自行消失。

**错误码**：`40000`（参数格式非法 / 时间窗口倒置）、`40100`、`40300`。

**Response** `200`:

```json
{
  "logs": [
    {
      "id": 1,
      "user_id": 1,
      "user_name": "张三",
      "action": "login",
      "resource": "user",
      "resource_id": "1",
      "detail": { "method": "password" },
      "client_ip": "10.0.0.1",
      "user_agent": "Mozilla/5.0...",
      "success": true,
      "err_code": null,
      "actor_client_id": null,
      "created_at": "2026-05-28T12:00:00Z"
    }
  ],
  "total": 1500,
  "page": 1,
  "page_size": 50
}
```

---

### 6.12 统计概览

```
GET /admin/stats
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色），委派调用需 `admin:read` 或 `admin:write` scope

控制台概览页的一次性数据源，聚合账户、客户端与最近审计三条视图。

**Response** `200`:

```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "users": {
      "total": 1450,
      "by_role": { "freshman": 300, "member": 900, "lecturer": 250, "admin": 50 },
      "by_state": { "njupter": 400, "on_sast": 900, "retired_sast": 150, "is_deleted": 50 },
      "by_department": { "software": 400, "media": 300 },
      "no_department": 800
    },
    "clients": {
      "total": 10,
      "active": 8
    },
    "audit": {
      "recent": []
    }
  }
}
```

**说明**：

- `users` 为账户聚合，枚举见附录 A。本仓软删除是状态位而非 `deleted_at` 列，因此口径为：**`total` / `by_role` / `by_department` / `no_department` 均只统计未注销账户**（`state ≠ is_deleted`），避免「账户总数」被已注销账户虚增；`by_state` 保留全部状态，`is_deleted` 作为独立 bucket 可见注销数。
  - `by_role` / `by_state` 按 `user` 表分组统计（`by_state` 含 `is_deleted`，其余两个维度不含）
  - `by_department` 按 `profile` 表 `LEFT JOIN` 分组统计；`no_department` 是没有 `profile` 行或部门未设（新生、尚未招新的 `njupter`）的用户数
- `clients` 含全部注册（停用的也在内）：`total` 为注册总数，`active` 为 `is_active = true` 的数量
- `audit.recent` 为最近 5 条审计日志（与 §6.11 同一排序 `created_at DESC`），条目结构同 §6.11；该路读取失败时记 WARN 日志并返回空列表（best-effort），不影响其余两路
- `users` 或 `clients` 聚合失败返回 `500`，不复用缓存——概览数据即时性优先

**错误码**：`40100`、`40300`、`50000`。

---

## 7. 健康检查

### 7.1 健康检查

```
GET /health
```

**Response** `200`:

```json
{
  "status": "ok",
  "db": "ok",
  "redis": "ok"
}
```

只有 PostgreSQL 是必需依赖。Redis 不可用时服务仍可依赖 PostgreSQL 提供认证能力，因此返回 `200` 且标记为降级：

```json
{
  "status": "ok",
  "db": "ok",
  "redis": "degraded"
}
```

`db` 检查失败时返回 `500`，`status` 与 `db` 均为 `error`。

| 字段 | 取值 | 说明 |
| ------ | ------ | ------ |
| `status` | `ok` / `error` | 仅由必需依赖决定；`error` 时 HTTP 500 |
| `db` | `ok` / `error` | PostgreSQL，必需依赖 |
| `redis` | `ok` / `degraded` | Redis，可选依赖，故障不影响 `status` |

---

## 8. OIDC Provider

SAST Link v2 作为 OpenID Connect Provider，在 OAuth 2.1 授权服务之上提供标准化的身份认证层。OIDC 协议栈：

- 授权码流（Authorization Code Flow + PKCE）— 推荐，opaque redirect-based
- EdDSA（Ed25519）签名 ID Token + JWKS 公钥分发
- Discovery 元数据（`.well-known/openid-configuration`）

**触发条件**：授权请求的 `scope` 包含 `openid` 时，Token 端点响应额外返回 `id_token`。

### 8.1 Discovery

```
GET /.well-known/openid-configuration
```

**Response** `200`:

```json
{
  "issuer": "https://link.sast.fun/v2",
  "authorization_endpoint": "https://link.sast.fun/v2/oauth/authorize",
  "token_endpoint": "https://link.sast.fun/v2/oauth/token",
  "userinfo_endpoint": "https://link.sast.fun/v2/userinfo",
  "jwks_uri": "https://link.sast.fun/v2/.well-known/jwks.json",
  "revocation_endpoint": "https://link.sast.fun/v2/oauth/revoke",
  "scopes_supported": ["openid", "profile", "email", "admin:read", "admin:write", "user:read", "user:write"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["EdDSA"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "nonce",
    "name", "picture", "preferred_username", "role",
    "email", "email_verified", "updated_at"
  ],
  "code_challenge_methods_supported": ["S256"],
  "response_modes_supported": ["query"],
  "claim_types_supported": ["normal"],
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "claims_parameter_supported": false
}
```

**说明**：

- 各端点 URL 由 `JWT_ISSUER` 派生而非独立配置。OIDC 要求本文档的 `issuer` 与每个 ID Token 的 `iss` claim 完全一致，两者同源可确保不漂移
- 本文档不使用标准信封——通用 OIDC 客户端库不解析本项目的信封格式
- `token_endpoint_auth_methods_supported` 中的 `none` 指公开客户端仅凭 PKCE 认证；不支持 HTTP Basic
- 声明的能力与实现严格一致：信任本文档却被拒绝的 relying party 没有申诉渠道

---

### 8.2 JWKS 公钥集

```
GET /.well-known/jwks.json
```

**Response** `200`:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "use": "sig",
      "kid": "link-v2-active",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  ]
}
```

**说明**：公钥用于验证 ID Token 和 Access Token 的 EdDSA（Ed25519）签名，格式为 RFC 8037 OKP。`kid` 与 JWT Header 中的 `kid` 对应，支持密钥轮换。

---

### 8.3 UserInfo

```
GET /userinfo
POST /userinfo
```

**Headers**: `Authorization: Bearer <access_token>`

**Response** `200`（根据 scope 返回不同 claims）：

`openid` scope 时至少返回 `sub`：

```json
{
  "sub": "1"
}
```

`openid profile email` scope 时返回完整信息：

```json
{
  "sub": "1",
  "name": "张三",
  "picture": "https://cos.example.com/avatar/1.jpg",
  "preferred_username": "张三",
  "role": "on_sast",
  "email": "b2404****@njupt.edu.cn",
  "email_verified": true,
  "updated_at": 1717396400
}
```

**错误响应**：

```json
{
  "error": "invalid_token",
  "error_description": "Access Token 无效或已过期"
}
```

**说明**：

- `sub` 为用户唯一标识（`user.id` 字符串），始终返回
- `email` 为注册邮箱（非对外展示邮箱）。`email_verified` 固定为 `true`（SAST Link 注册时已校验邮箱）
- `updated_at` 为 Unix timestamp
- `role` 是 SAST Link 自有 claim（非 OIDC 标准），随 `profile` scope 返回，取值见附录 A 的 `user_role`。它取自**签发那一刻的数据库行**，而非请求方 token 里的 `role` claim——后者是签发时快照，用户降权后仍带原角色。客户端应把它当展示提示用：它与所在 token 同样会过期，不应作为授权判断依据（本服务自己的鉴权也不读 token 的 role claim，见 §7.1）
- 本端点按设计服务第三方 token（`AuthenticateAnyClient`，不要求能力 scope）。读取当前登录用户的 OIDC 视图经由此处；`/user/*` 需 `user:*` scope（任何客户端可申请，只操作本人记录，见 §5.1、§6.7），`/admin/*` 需 `admin:*`（仅 `third_party` 可持有，见 §6.7）
- `admin:read` / `admin:write` 不贡献任何 claim：只持有 admin scope 的 token 在此处只得到 `sub`
- 响应体为裸 claim 集合，**不使用标准信封**——通用 OIDC 客户端库不解析本项目的信封格式
- 授权范围之外的 claim **完全不出现**，而非返回空值。relying party 无法区分 `"name": ""` 与「该用户没有名字」
- `preferred_username` 取 `profile.nickname`，未设置或为空白时回退到 `user.name`，保证 relying party 总有可展示的值
- 仅当 scope 含 `profile` 时才查询 profile 表；限定为 `openid` 或 `email` 的 token 完全不触碰该表
- 响应携带 `Cache-Control: no-store`
- 同时支持 `GET` 与 `POST`。`GET` 使 token 留在 header 中，`POST` 供偏好该方式的客户端使用
- 本端点自行完成认证而不挂在 JWT 中间件之后，目的是按 RFC 6750 格式应答；token 校验逻辑复用中间件的 `AuthenticateAnyClient`，两条路径不会漂移。注意是 `AuthenticateAnyClient` 而非内部接口用的 `Authenticate`：后者带 `azp` 内置客户端闸门，会拒绝第三方 token，而接受第三方 token 恰是本端点存在的意义

**错误响应**（RFC 6750 §3）：token 被拒时返回 `401`，并携带 `WWW-Authenticate` 挑战头：

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="sast-link", error="invalid_token"
Content-Type: application/json

{
  "error": "invalid_token",
  "error_description": "Access Token 无效或已过期"
}
```

挑战头是 RFC 6750 与 RFC 6749 错误格式的关键差异：符合规范的 OIDC 客户端读取此 header 来判断是否需要刷新 token。签名无效、已过期、已撤销、`token_version` 不匹配、账号已注销等情形统一归为 `invalid_token`——RFC 6750 对「token 被拒」只有这一个错误码。

注意 header 中**不含 `error_description`**：RFC 6750 §3 规定挑战头的引号值只能使用可打印 US-ASCII（`%x20-21` / `%x23-5B` / `%x5D-7E`），而本服务的描述文案为中文。按规范校验的客户端遇到非 ASCII 字节可能整条丢弃该 header，连 `error` 码一起丢掉，反而拿不到「需要刷新」这个信号。完整中文描述始终通过 JSON body 返回。

---

### 8.4 ID Token

当 scope 包含 `openid` 时，Token 端点（`POST /oauth/token`）的响应额外包含 `id_token` 字段：

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImxpbmstdjItYWN0aXZlIiwidHlwIjoiSldUIn0...",
  "scope": "openid profile email"
}
```

**ID Token Payload 示例**（解码后）：

```json
{
  "iss": "https://link.sast.fun/v2",
  "sub": "1",
  "aud": "9f3a1c7d2e5b40a8c6d1f4b7a2e9c3d5",
  "exp": 1717400000,
  "iat": 1717396400,
  "auth_time": 1717396400,
  "nonce": "n-0S6_WzA2Mj",
  "name": "张三",
  "picture": "https://cos.example.com/avatar/1.jpg",
  "preferred_username": "张三",
  "role": "on_sast",
  "email": "b2404****@njupt.edu.cn",
  "email_verified": true,
  "updated_at": 1717396400
}
```

**ID Token Claims 说明**：

| Claim | Scope 要求 | 说明 |
| ------- | ----------- | ------ |
| `iss` | — | Issuer，固定为 `https://link.sast.fun/v2` |
| `sub` | `openid` | 用户唯一标识（`user.id` 字符串） |
| `aud` | — | 客户端 `client_id` |
| `exp` | — | 过期时间（Unix timestamp） |
| `iat` | — | 签发时间（Unix timestamp） |
| `auth_time` | — | **授权确认时间，不是真正的认证时间**；会签发但**不在 `claims_supported` 中通告**，见下方说明 |
| `nonce` | — | 防重放值，与授权请求参数一致（可选） |
| `name` | `profile` | 真实姓名 |
| `picture` | `profile` | 头像 URL |
| `preferred_username` | `profile` | 昵称 |
| `role` | `profile` | 用户当前角色（SAST Link 自有 claim，非 OIDC 标准）。取自签发时的数据库行；与所在 token 同样会过期，仅作展示提示，不应用于授权判断 |
| `email` | `email` | 注册邮箱 |
| `email_verified` | `email` | 邮箱已验证，固定 `true` |
| `updated_at` | `profile` | 用户信息最后修改时间 |

> **`auth_time` 语义偏差（已知限制）**
>
> OIDC Core 定义 `auth_time` 为**终端用户完成认证**的时刻。本服务目前能拿到的最接近值是**用户在授权页点击同意**的时刻（授权码流取授权码创建时间，refresh 轮换取该 family 首个 refresh token 的创建时间）。因为服务端尚未在任何地方持久化真实的认证时刻。
>
> 后果：用户三天前登录、会话仍有效，今天走第三方授权，`auth_time` 会被报成今天——**高报**了认证的新鲜度，而这恰是该 claim 存在的意义。
>
> 因此该 claim **会签发但不在 `claims_supported` 中通告**：不通告就不构成承诺，省略可选 claim 是正确的行为，通告一个错值才是误导。同时 `max_age` 与 `prompt` 均未实现，RP 无法据此要求重新认证。
>
> 真正修复需要：登录时持久化认证时刻 → 经授权确认写入授权码行 → 传递到 token family。涉及数据库迁移，留待后续实现，届时再把 `auth_time` 加回 `claims_supported`。

**OIDC 授权码流完整交互**：

```
RP (Relying Party)          浏览器 / 前端授权页          SAST Link v2 (OIDC Provider)
      |                            |                              |
      | 302 至 /oauth/authorize    |                              |
      |--------------------------->|                              |
      |                            | GET /oauth/authorize?        |
      |                            |   response_type=code         |
      |                            |   client_id=xxx              |
      |                            |   redirect_uri=https://rp.example/cb
      |                            |   scope=openid+profile+email |
      |                            |   state=random_state         |
      |                            |   code_challenge=S256(verifier)
      |                            |   code_challenge_method=S256 |
      |                            |   nonce=random_nonce         |
      |                            |   （无 Authorization header）|
      |                            |----------------------------->|
      |                            |                              | 校验参数 → Redis 暂存
      |                            | 302 {OAUTH_CONSENT_URL}?     |
      |                            |   request_id=ar_xxx          |
      |                            |   &client_name=..&scope=..   |
      |                            |<-----------------------------|
      |                            |                              |
      |                            | 展示授权页，用户点击「同意」 |
      |                            | POST /oauth/authorize/consent|
      |                            |   Authorization: Bearer <at> |
      |                            |   { request_id, approve }    |
      |                            |----------------------------->|
      |                            |                              | GetDel 消费暂存
      |                            |                              | → 建授权码（新 family）
      |                            | 200 { redirect_uri }         |
      |                            |<-----------------------------|
      |                            |                              |
      | 前端 navigate 至 redirect_uri（?code=..&state=..）        |
      |<---------------------------|                              |
      |                            |                              |
      | POST /oauth/token（RP 后端直连，不经浏览器）              |
      |   grant_type=authorization_code                           |
      |   code=auth_code                                          |
      |   redirect_uri=https://rp.example/cb                      |
      |   client_id=xxx                                           |
      |   code_verifier=verifier                                  |
      |---------------------------------------------------------->|
      |                            |            校验 client / code / redirect_uri / PKCE
      | { access_token, refresh_token, id_token, expires_in, scope }
      |<----------------------------------------------------------|
      |                            |                              |
      | 验证 id_token 签名（/.well-known/jwks.json）              |
      | 对比 nonce / iss / aud                                    |
      |                            |                              |
      | GET /userinfo                                             |
      |   Authorization: Bearer <access_token>                    |
      |---------------------------------------------------------->|
      | { sub, name, email, ... }                                 |
      |<----------------------------------------------------------|
```

时序图中 `code_verifier` 与 `code_challenge` 的关系：`code_challenge = BASE64URL(SHA256(code_verifier))`，RP 在发起授权时发送 challenge，兑换时发送原始 verifier。`nonce` 由服务端写入 ID Token 的 claim，RP 需自行比对——本服务不校验 nonce，它的用途正是让 RP 检测 ID Token 重放。

---

## 附录

### A. 枚举值参考

| 枚举类型 | 值 |
| ---------- | ----- |
| `user_role` | `freshman` / `member` / `lecturer` / `admin` |
| `state` | `njupter` / `on_sast` / `retired_sast` / `is_deleted` |
| `department` | `software` / `media` |
| `email_type` | `njupt_email` / `sast_email` |
| `login_method` | `github` / `lark` / `other_mail` |
| `client_type` | `first_party` / `third_party` |

### B. HTTP 状态码与业务码对应

| HTTP 状态码 | 说明 | 对应业务码段 |
| ------------- | ------ | ------------- |
| 200 | 成功 | `0` |
| 201 | 创建成功 | `0` |
| 204 | 无内容（删除成功） | `0` |
| 302 | 重定向（OAuth 流程） | — |
| 400 | 请求参数错误 | `400xx` |
| 401 | 未认证 | `401xx` |
| 403 | 无权限 | `403xx` |
| 404 | 资源不存在 | `404xx` |
| 409 | 资源冲突（如重复绑定） | `409xx` |
| 422 | 业务校验失败 | `422xx` |
| 429 | 请求频率限制 | `429xx` |
| 500 | 服务器内部错误 | `500xx` |
| 503 | 依赖服务暂不可用 | `503xx` |

### C. Token 生命周期

| Token 类型 | 有效期 |
| ------------ | -------- |
| Access Token (JWT) | 1 小时 |
| Refresh Token | 30 天 |
| Register-Ticket（Redis） | 5 分钟 |
| login_code（Redis） | 60 秒 |
| oauth_state（Redis） | 10 分钟 |
| Bind-Ticket（Redis） | 5 分钟 |
| 授权码（Authorization Code） | 5 分钟 |
| 验证码（Redis） | 5 分钟 |
| 密码重置验证码（Redis） | 5 分钟 |
