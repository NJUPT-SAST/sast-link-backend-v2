# SAST Link v2 API 文档

## 概述

- **Base URL**: `https://link.sast.fun/v2`
- **认证方式**: JWT Bearer Token（`Authorization: Bearer <access_token>`）
- **Content-Type**: `application/json`
- **OAuth 2.1**: 授权端点使用 PKCE-S256，第一方应用无需 client_secret
- **OIDC**: 基于 OAuth 2.1 的 OpenID Connect Provider，scope 含 `openid` 时返回 ID Token
- **响应格式**: 所有接口统一使用标准化响应信封，OAuth 端点遵循 RFC 6749 错误格式

---

## 标准化响应格式与业务码

### 响应信封

所有接口（除 OAuth 2.1 端点外）统一使用以下响应信封：

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
  "code": 40104,
  "message": "密码错误",
  "data": null
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `code` | int | 业务状态码，`0` 表示成功，非 `0` 表示错误 |
| `message` | string | 可读的描述信息，成功时为 `"ok"`，错误时为具体错误原因 |
| `data` | object\|array\|null | 业务数据载荷，错误时为 `null` |

> 前文各端点示例中展示的响应体均为 `data` 载荷内容，实际响应均被信封包裹。

**OAuth 2.1 端点**（`/oauth/authorize`、`/oauth/token`、`/oauth/revoke`）遵循 [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) 错误格式：

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
|--------|------|
| `40000` | 请求参数错误 |
| `40001` | 缺少必要参数 |
| `40002` | 参数格式错误 |
| `40010` | 验证码错误 |
| `40011` | 验证码已过期 |
| `40012` | 验证码发送频率过高 |
| `40020` | 邮箱域名不允许（仅限 `@njupt.edu.cn` / `@sast.fun`） |

#### 认证错误（401xx）

| 业务码 | 说明 |
|--------|------|
| `40100` | 未登录（缺少或无效 Authorization Header） |
| `40101` | Access Token 已过期 |
| `40102` | Access Token 无效或已被撤销 |
| `40103` | Register-Ticket 无效或已过期 |
| `40104` | Bind-Ticket 无效或已过期 |
| `40105` | 密码错误 |
| `40106` | 登录邮箱不存在 |
| `40107` | login_code 无效或已过期 |

#### 权限错误（403xx）

| 业务码 | 说明 |
|--------|------|
| `40300` | 无权限（需 admin / lecturer 角色） |
| `40301` | 账号已注销（`state = is_deleted`） |
| `40302` | 非 SAST 企业飞书用户 |

#### 资源不存在（404xx）

| 业务码 | 说明 |
|--------|------|
| `40400` | 资源不存在 |
| `40401` | 用户不存在 |
| `40402` | OAuth 客户端不存在 |

#### 资源冲突（409xx）

| 业务码 | 说明 |
|--------|------|
| `40900` | 资源已存在 |
| `40901` | 邮箱已被注册 |
| `40902` | 学号已被占用 |
| `40903` | 第三方账号已被其他用户绑定 |
| `40904` | 该类型账号已绑定，不可重复绑定 |
| `40905` | 第三方邮箱绑定数量已达上限（2 个） |

#### 业务校验失败（422xx）

| 业务码 | 说明 |
|--------|------|
| `42200` | 业务校验失败 |
| `42201` | 密码长度不足（最短 8 位） |
| `42202` | 新旧密码不能相同 |
| `42203` | 不能解绑唯一登录方式 |

#### 频率限制（429xx）

| 业务码 | 说明 |
|--------|------|
| `42900` | 请求过于频繁，请稍后再试 |

#### 服务端错误（500xx）

| 业务码 | 说明 |
|--------|------|
| `50000` | 服务器内部错误 |
| `50001` | 邮件发送失败 |
| `50002` | 对象存储上传失败 |
| `50003` | 数据库错误 |

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
  "oauth_state": "os_abc123..."
}
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `register_ticket` | 是 | 注册验证码校验后获得的票据 |
| `password` | 是 | 密码，最短 8 位 |
| `name` | 是 | 姓名 |
| `phone_number` | 是 | 手机号 |
| `qq_number` | 是 | QQ 号 |
| `student_id` | 是 | 学号 |
| `college` | 是 | 学院，枚举值见附录 A |
| `major` | 是 | 专业 |
| `oauth_state` | 否 | 第三方 OAuth 回调的绑定凭证 |

**Response** `201`:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
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

**说明**: Register-Ticket 已包含验证过的邮箱，无需再次传入 `login_email`；密码最短 8 位；注册成功后自动签发 Token，无需单独登录。`oauth_state` 为可选字段，来自第三方 OAuth 回调（GitHub / 飞书）的无绑定分支——传入后注册成功的同时自动创建对应的 identities 绑定记录。

---

### 1.4 密码登录

```
POST /user/login
```

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
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
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

**Request**:
```json
{
  "refresh_token": "rt_abc123..."
}
```

**Response** `200`:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "rt_new_abc456...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**说明**:
- Refresh Token 旋转机制 — 每次使用后旧 token 立即撤销，下发新 token
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

**Response** `200`:
```json
{
  "message": "已登出"
}
```

**说明**: 撤销当前 access_token（jti）及整条 refresh_token family。

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

**说明**: 新密码最短 8 位；修改成功后撤销该用户所有 token family，需重新登录。

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
  "message": "验证码已发送至邮箱",
  "expires_in": 300
}
```

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

**说明**: 新密码最短 8 位。

---

## 2. 第三方 OAuth 登录

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
- 无绑定 → 生成 `oauth_state`（Redis，10min，暂存 provider + provider_id + identity_data），302 重定向至注册补全页 `?oauth_state=<oauth_state>&provider=github&name=<login>&avatar=<url>`，供注册时自动绑定

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
- 无绑定 → 生成 `oauth_state`（Redis，10min，暂存 provider + provider_id + identity_data），302 重定向至注册补全页 `?oauth_state=<oauth_state>&provider=lark&name=<name>&avatar=<url>`，供注册时自动绑定
- 非 SAST 企业用户 → 拒绝，提示"仅限 SAST 成员登录"

---

### 2.5 交换登录码

用 OAuth 回调中的一次性 `login_code` 换取 token。

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
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
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

**说明**: `login_code` 存储在 Redis，有效期 60 秒，一次性使用；交换成功后立即删除。

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

更新当前登录用户可自助维护的个人信息。未传字段保持不变；`login_email`、`role`、`state`、`email_type` 等身份与权限字段不可通过此接口修改。

**Request**:
```json
{
  "name": "张三",
  "student_id": "B2404****",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "college": "计算机学院",
  "major": "软件工程",
  "nickname": "新昵称",
  "department": "software",
  "intro": "新的自我介绍",
  "email": "display@example.com",
  "blog_url": "https://blog.example.com",
  "github_url": "https://github.com/example"
}
```

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
    "college": "计算机学院",
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

**Request**: `file` 字段（图片，限制 5MB，格式 jpg/png/webp）

**Response** `200`:
```json
{
  "avatar_url": "https://cos.example.com/avatar/1.jpg"
}
```

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

---

### 4.2 绑定飞书

```
POST /user/identities/lark
```

**Headers**: `Authorization: Bearer <access_token>`

**Query Parameters**:

| 参数 | 说明 |
|------|------|
| `code` | 飞书 OAuth 授权码 |

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

| 参数 | 说明 |
|------|------|
| `code` | GitHub OAuth 授权码 |

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
- 必须输入当前密码进行二次确认
- 主邮箱（`user.login_email`）不在 identities 中，不可通过此接口解绑
- 不能解绑唯一登录方式（解绑后无其他登录手段则拒绝）

---

## 5. OAuth 2.1 授权服务端

### 5.1 授权端点

```
GET /oauth/authorize
```

**Query Parameters**:

| 参数 | 必填 | 说明 |
|------|------|------|
| `response_type` | 是 | 固定 `code` |
| `client_id` | 是 | 客户端标识 |
| `redirect_uri` | 是 | 回调地址 |
| `scopes` | 是 | 授权范围，空格分隔，取值：`openid`（必选）/ `profile` / `email` |
| `state` | 是 | CSRF 防护，客户端生成随机字符串，回调时原样返回 |
| `code_challenge` | 是 | PKCE challenge |
| `code_challenge_method` | 是 | `S256` 或 `plain` |
| `nonce` | 否 | OIDC nonce |

**行为**: 检查用户登录状态 → 展示授权页 → 用户同意后重定向至 `redirect_uri`，携带 `code` 和 `state`。

---

### 5.2 Token 端点

```
POST /oauth/token
```

支持 `authorization_code` 和 `refresh_token` 两种 grant_type。第一方应用使用 PKCE 无需 `client_secret`，第三方应用需提供 `client_secret`。scope 包含 `openid` 时响应额外返回 `id_token`（RS256 签名 JWT）。此端点不遵循标准响应信封，成功和错误均使用 RFC 6749 格式。

**Request**（第一方应用 / PKCE）:
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_abc123...",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "381c34b9-14a4-4df9-a9db-40c2455be09f",
  "code_verifier": "pkce_verifier_raw_string..."
}
```

**Request**（第三方应用 / client_secret）:
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_abc123...",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "381c34b9-14a4-4df9-a9db-40c2455be09f",
  "client_secret": "3K7mDzX434GbFm9YAePJ9FXQNjT6MF0U",
  "code_verifier": "pkce_verifier_raw_string..."
}
```

**Response** `200`:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scopes": "openid profile"
}
```

**说明**：scope 包含 `openid` 时响应体额外返回 `id_token`（RS256 签名 JWT），详见 [8.4 ID Token](#84-id-token)。scope 不含 `openid` 时不返回 `id_token` 字段。

**Refresh Token 模式**（第一方应用）:
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "rt_abc123...",
  "client_id": "381c34b9-14a4-4df9-a9db-40c2455be09f"
}
```

**Refresh Token 模式**（第三方应用）:
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "rt_abc123...",
  "client_id": "381c34b9-14a4-4df9-a9db-40c2455be09f",
  "client_secret": "3K7mDzX434GbFm9YAePJ9FXQNjT6MF0U"
}
```

---

### 5.3 Token 撤销

```
POST /oauth/revoke
```

**Request**:
```json
{
  "token": "rt_abc123...",
  "token_type_hint": "refresh_token",
  "client_id": "381c34b9-14a4-4df9-a9db-40c2455be09f"
}
```

**Response** `200`:
```json
{
  "message": "ok"
}
```

**说明**: 撤销整条 token family。

---

## 6. 管理后台（Admin）

### 6.1 用户列表

```
GET /admin/users
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin / lecturer 角色）

**Query Parameters**:

| 参数 | 说明 |
|------|------|
| `page` | 页码，默认 1 |
| `page_size` | 每页条数，默认 20，最大 100 |
| `role` | 筛选角色：freshman / member / lecturer / admin |
| `state` | 筛选状态：on-sast / retired-sast / njupter / is_deleted |
| `department` | 筛选部门：software / media |
| `college` | 筛选学院，枚举值见附录 A |
| `major` | 筛选专业 |
| `keyword` | 搜索关键词（姓名/学号/邮箱模糊匹配） |

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

**Headers**: `Authorization: Bearer <access_token>`（需 admin / lecturer 角色）

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

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

**Request**（所有字段可选，仅传需要修改的字段）:
```json
{
  "name": "张三",
  "phone_number": "13800138000",
  "qq_number": "1234567890",
  "student_id": "B2404****",
  "college": "计算机学院、软件学院、网络空间安全学院",
  "major": "软件工程",
  "role": "member",
  "state": "on-sast",
  "email_type": "njupt_email"
}
```

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

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

**Response** `200`:
```json
{
  "message": "用户已注销"
}
```

**说明**: 将 `user.state` 设为 `is_deleted`，保留数据；应用层查找该用户所有 token family 并逐个撤销（非 DB 级联删除），同时失效所有 Redis session。

---

### 6.5 恢复已注销用户

```
PUT /admin/users/:id/restore
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

**Response** `200`:
```json
{
  "message": "用户已恢复"
}
```

**说明**: 将 `user.state` 从 `is_deleted` 恢复至 `njupter`。已撤销的 token 不恢复，需用户重新登录。

---

### 6.6 OAuth 客户端列表

```
GET /admin/oauth-clients
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

**Response** `200`:
```json
{
  "clients": [
    {
      "id": 1,
      "client_id": "381c34b9-14a4-4df9-a9db-40c2455be09f",
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

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

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
  "client_id": "a1b2c3d4-...",
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

**说明**: 第一方应用（`first_party`）不返回 `client_secret`，使用 PKCE 即可。

---

### 6.8 更新 OAuth 客户端

```
PUT /admin/oauth-clients/:id
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

**Request**:
```json
{
  "client_name": "已更名应用",
  "redirect_uris": ["https://new-app.example.com/callback"],
  "is_active": false
}
```

**Response** `200`:
```json
{
  "message": "客户端信息更新成功"
}
```

---

### 6.9 查询审计日志

```
GET /admin/audit-logs
```

**Headers**: `Authorization: Bearer <access_token>`（需 admin 角色）

**Query Parameters**:

| 参数 | 说明 |
|------|------|
| `page` | 页码，默认 1 |
| `page_size` | 每页条数，默认 50 |
| `user_id` | 按用户筛选 |
| `action` | 按操作类型筛选 |
| `resource` | 按资源类型筛选 |
| `success` | 是否成功：true / false |
| `start_time` | 开始时间（ISO 8601） |
| `end_time` | 结束时间（ISO 8601） |

**Response** `200`:
```json
{
  "logs": [
    {
      "id": 1,
      "user_id": 1,
      "action": "login",
      "resource": "user",
      "resource_id": "1",
      "detail": { "ip": "10.0.0.1" },
      "client_ip": "10.0.0.1",
      "user_agent": "Mozilla/5.0...",
      "success": true,
      "err_code": null,
      "created_at": "2026-05-28T12:00:00Z"
    }
  ],
  "total": 1500,
  "page": 1,
  "page_size": 50
}
```

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

---

## 8. OIDC Provider

SAST Link v2 作为 OpenID Connect Provider，在 OAuth 2.1 授权服务之上提供标准化的身份认证层。OIDC 协议栈：

- 授权码流（Authorization Code Flow + PKCE）— 推荐，opaque redirect-based
- RS256 签名 ID Token + JWKS 公钥分发
- Discovery 元数据（`.well-known/openid-configuration`）

**触发条件**：授权请求的 `scopes` 包含 `openid` 时，Token 端点响应额外返回 `id_token`。

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
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
    "name", "picture", "preferred_username", "profile",
    "email", "email_verified", "updated_at"
  ],
  "code_challenge_methods_supported": ["S256", "plain"],
  "response_modes_supported": ["query"],
  "claim_types_supported": ["normal"],
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "claims_parameter_supported": false
}
```

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
      "kty": "RSA",
      "use": "sig",
      "kid": "link-v2-2026-06",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLgX...",
      "e": "AQAB"
    }
  ]
}
```

**说明**：公钥用于验证 ID Token 和 Access Token 的 RS256 签名。`kid` 与 JWT Header 中的 `kid` 对应，支持密钥轮换。

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
  "profile": "https://link.sast.fun/card/1",
  "email": "b2404****@njupt.edu.cn",
  "email_verified": true,
  "updated_at": 1717396400
}
```

**错误响应**：

```json
{
  "error": "invalid_token",
  "error_description": "The access token is invalid or expired"
}
```

**说明**：
- `sub` 为用户唯一标识（`user.id` 字符串），始终返回
- `email` 为注册邮箱（非对外展示邮箱）。`email_verified` 固定为 `true`（SAST Link 注册时已校验邮箱）
- `updated_at` 为 Unix timestamp

---

### 8.4 ID Token

当 scope 包含 `openid` 时，Token 端点（`POST /oauth/token`）的响应额外包含 `id_token` 字段：

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxpbmstdjItMjAyNi0wNiIsInR5cCI6IkpXVCJ9...",
  "scopes": "openid profile email"
}
```

**ID Token Payload 示例**（解码后）：

```json
{
  "iss": "https://link.sast.fun/v2",
  "sub": "1",
  "aud": "381c34b9-14a4-4df9-a9db-40c2455be09f",
  "exp": 1717400000,
  "iat": 1717396400,
  "auth_time": 1717396400,
  "nonce": "n-0S6_WzA2Mj",
  "name": "张三",
  "picture": "https://cos.example.com/avatar/1.jpg",
  "preferred_username": "张三",
  "profile": "https://link.sast.fun/card/1",
  "email": "b2404****@njupt.edu.cn",
  "email_verified": true,
  "updated_at": 1717396400
}
```

**ID Token Claims 说明**：

| Claim | Scope 要求 | 说明 |
|-------|-----------|------|
| `iss` | — | Issuer，固定为 `https://link.sast.fun/v2` |
| `sub` | `openid` | 用户唯一标识（`user.id` 字符串） |
| `aud` | — | 客户端 `client_id` |
| `exp` | — | 过期时间（Unix timestamp） |
| `iat` | — | 签发时间（Unix timestamp） |
| `auth_time` | — | 用户认证时间（授权确认时间） |
| `nonce` | — | 防重放值，与授权请求参数一致（可选） |
| `name` | `profile` | 真实姓名 |
| `picture` | `profile` | 头像 URL |
| `preferred_username` | `profile` | 昵称 |
| `profile` | `profile` | 用户主页 URL |
| `email` | `email` | 注册邮箱 |
| `email_verified` | `email` | 邮箱已验证，固定 `true` |
| `updated_at` | `profile` | 用户信息最后修改时间 |

**OIDC 授权码流完整交互**：

```
RP (Relying Party)                         SAST Link v2 (OIDC Provider)
      |                                              |
      | GET /oauth/authorize?                        |
      |   response_type=code                         |
      |   client_id=xxx                              |
      |   redirect_uri=https://rp.example/cb         |
      |   scopes=openid+profile+email                |
      |   state=random_state                         |
      |   code_challenge=S256(challenge)             |
      |   code_challenge_method=S256                 |
      |   nonce=random_nonce                         |
      |--------------------------------------------->|
      |                                              | 用户登录 + 授权确认
      | 302 ?code=auth_code&state=random_state       |
      |<---------------------------------------------|
      |                                              |
      | POST /oauth/token                            |
      |   grant_type=authorization_code              |
      |   code=auth_code                             |
      |   redirect_uri=https://rp.example/cb         |
      |   client_id=xxx                              |
      |   code_verifier=challenge                   |
      |--------------------------------------------->|
      |                                              | 校验 code / PKCE / nonce
      | { access_token, refresh_token,               |
      |   id_token, expires_in, scopes }             |
      |<---------------------------------------------|
      |                                              |
      | 验证 id_token 签名 (/.well-known/jwks.json)   |
      | 对比 nonce / iss / aud                       |
      |                                              |
      | GET /userinfo                                |
      |   Authorization: Bearer <access_token>       |
      |--------------------------------------------->|
      | { sub, name, email, ... }                    |
      |<---------------------------------------------|
```

---

## 附录

### A. 枚举值参考

| 枚举类型 | 值 |
|----------|-----|
| `user_role` | `freshman` / `member` / `lecturer` / `admin` |
| `state` | `njupter` / `on-sast` / `retired-sast` / `is_deleted` |
| `department` | `software` / `media` |
| `email_type` | `njupt_email` / `sast_email` |
| `login_method` | `github` / `lark` / `other_mail` |
| `client_type` | `first_party` / `third_party` |

### B. HTTP 状态码与业务码对应

| HTTP 状态码 | 说明 | 对应业务码段 |
|-------------|------|-------------|
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

### C. Token 生命周期

| Token 类型 | 有效期 |
|------------|--------|
| Access Token (JWT) | 1 小时 |
| Refresh Token | 30 天 |
| Register-Ticket（Redis） | 5 分钟 |
| login_code（Redis） | 60 秒 |
| oauth_state（Redis） | 10 分钟 |
| Bind-Ticket（Redis） | 5 分钟 |
| 授权码（Authorization Code） | 5 分钟 |
| 验证码（Redis） | 5 分钟 |
| 密码重置验证码（Redis） | 5 分钟 |
