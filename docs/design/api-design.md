# SAST Link Backend V2 API 设计文档

> 版本：v1.3（字段规范化版）
> 日期：2026-05-20
> 状态：已定稿
> 兼容目标：老后端 API 完全兼容，字段名遵循 Go/GORM 标准规范

---

## 目录

1. [概述](#1-概述)
2. [认证流程 API](#2-认证流程-api)
3. [用户管理 API](#3-用户管理-api)
4. [OAuth 登录 API](#4-oauth-登录-api)
5. [错误码体系](#5-错误码体系)
6. [请求响应 Schema](#6-请求响应-schema)
7. [附录](#7-附录)

---

## 1. 概述

### 1.1 基础信息

| 项 | 值 |
|---|---|
| Base URL | `/api/v1` |
| 协议 | HTTPS |
| 数据格式 | JSON（除文件上传外） |
| 字符编码 | UTF-8 |

### 1.2 统一响应格式

```json
{
  "Success": true,
  "Data": {},
  "ErrCode": 200,
  "ErrMsg": ""
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `Success` | `bool` | `true` 表示成功，`false` 表示失败 |
| `Data` | `any` | 成功时返回业务数据，失败时为 `null` |
| `ErrCode` | `int` | 错误码，`200` 表示成功，非 200 表示具体错误 |
| `ErrMsg` | `string` | 错误描述，成功时为空字符串 |

**成功响应 `ErrCode = 200`。失败响应示例：**

```json
{
  "Success": false,
  "Data": null,
  "ErrCode": 10005,
  "ErrMsg": "password error"
}
```

### 1.3 认证机制

#### Token 传输

所有需要认证的请求，通过 `Token` Header 传输（与老后端兼容）：

```
Token: {jwt_token}
```

> **同时支持** `Authorization: Bearer {jwt_token}`（标准方式，推荐新接入方使用）。后端按优先级读取：`Token` > `Authorization: Bearer` > Query `token`。

#### Ticket 机制

| Ticket 类型 | Header 名称 | 有效期 | 用途 |
|------------|------------|--------|------|
| Register-Ticket | `REGISTER-TICKET` | 5 分钟 | 注册流程阶段凭证 |
| Login-Ticket | `LOGIN-TICKET` | 5 分钟 | 登录流程阶段凭证 |
| ResetPwd-Ticket | `RESETPWD-TICKET` | 6 分钟 | 密码重置流程阶段凭证 |
| OAuth-Ticket | `OAUTH-TICKET` | 3 分钟 | OAuth 绑定流程凭证 |

#### Token 机制

| Token 类型 | 有效期 | 存储位置 | 用途 |
|-----------|--------|---------|------|
| Login-Token | 7 天 | 客户端 localStorage + Redis `sastlink:token:{uid}` | API 鉴权 |

单 Token 模式，与老后端完全一致。

### 1.4 通用请求规范

- 学号（username）：`^[BPFQbpfq](1[7-9]|2[0-9])([0-3])\d{5}$`，自动补全为 `@njupt.edu.cn`
- 验证码：`S-\d{5}`，5 位数字，前缀 `S-`
- 密码：`^[a-zA-Z0-9!@#$%^&*()_=+]{6,32}$`，后端额外校验至少含字母和数字

---

## 2. 认证流程 API

### 2.1 验证账号 —— POST /verify/account

**Query Parameters：** `username`, `flag`（0=注册，1=登录，2=重置密码）

**响应：** 返回对应类型的 Ticket（registerTicket / loginTicket / resetPwdTicket），`ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | username 或 flag 缺失/格式错误 |
| `10007` | 重复注册 | flag=0 时账号已注册 |
| `10011` | 用户不存在 | flag=1 或 flag=2 时账号未注册 |
| `30003` | 邮箱格式错误 | username 不符合学号规则 |

---

### 2.2 发送验证邮件 —— POST /sendEmail

**Auth：** REGISTER-TICKET 或 RESETPWD-TICKET

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | 未提供任何 Ticket |
| `20007` | Ticket不正确 | Ticket 无效或过期 |
| `30001` | 发送邮件失败 | SMTP 服务异常 |

**限流：** 同一账号 3 次/分钟。

---

### 2.3 验证验证码 —— POST /verify/captcha

**Auth：** Ticket（REGISTER-TICKET / LOGIN-TICKET / RESETPWD-TICKET）
**Content-Type：** `application/x-www-form-urlencoded`
**Body：** `captcha`（格式 `S-xxxxx`，前端自动拼接 `S-` 前缀）

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | captcha 缺失或格式错误 |
| `20007` | Ticket不正确 | Ticket 无效或过期 |
| `30002` | 验证码错误 | 验证码不匹配 |
| `20008` | Ticket不存在 | Ticket 已过期 |

**限流：** 5 次/分钟/IP。

---

### 2.4 用户注册 —— POST /user/register

**Auth：** REGISTER-TICKET
**Content-Type：** `application/x-www-form-urlencoded`
**Body：** `password`（6-32 位，必须同时包含字母和数字）

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | password 缺失或格式不合规 |
| `20007` | Ticket不正确 | REGISTER-TICKET 无效或过期 |
| `10007` | 重复注册 | 该邮箱已注册 |
| `10003` | 密码错误 | 密码格式不符 |

**详细流程：**

1. 验证 REGISTER-TICKET 有效性
2. 检查 Ticket 状态是否为 "verified"
3. 校验 password 格式（正则 + 字母数字组合）
4. 使用 SHA-512 对密码进行哈希（与老后端完全一致）
5. 创建 users 记录（uid=学号, email=完整邮箱, password_hash）
6. 创建 user_profiles 记录（nickname 默认为学号, org_id=-1）
7. 标记 Ticket 状态为 "used"
8. 返回成功

---

### 2.5 用户登录 —— POST /user/login

**Auth：** LOGIN-TICKET
**Content-Type：** `multipart/form-data`
**Body：** `password`（FormData）

**响应：** `ErrCode = 200`，`Data.loginToken`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | password 缺失 |
| `20007` | Ticket不正确 | LOGIN-TICKET 无效或过期 |
| `10011` | 用户不存在 | 用户不存在或已删除 |
| `10005` | 登录失败 | 密码不匹配 |
| `10010` | OAuth用户未注册或未绑定 | OAUTH-TICKET 无效或绑定出错 |

**详细流程：**

1. 验证 LOGIN-TICKET 有效性
2. 从 Ticket 中提取 email，查询 users 表
3. 校验 password：使用 SHA-512 哈希比对（与老后端完全一致）
4. 若提供了 OAUTH-TICKET，验证并创建 user_oauths 绑定记录
5. 生成 Login Token（7 天有效期），存入 Redis `sastlink:token:{uid}`
6. 返回 loginToken

**限流：** 5 次/分钟/账号。连续 5 次失败封禁 15 分钟。

---

### 2.6 重置密码 —— POST /user/resetPassword

**Auth：** RESETPWD-TICKET
**Content-Type：** `application/x-www-form-urlencoded`
**Body：** `newPassword`（6-32 位，必须同时包含字母和数字）

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | newPassword 缺失或格式不合规 |
| `20007` | Ticket不正确 | RESETPWD-TICKET 无效或过期 |
| `10011` | 用户不存在 | 用户不存在 |
| `10004` | 密码为空 | 新密码与旧密码相同 |
| `10003` | 密码错误 | 新密码不符合格式要求 |

**详细流程：**

1. 验证 RESETPWD-TICKET 有效性
2. 检查 Ticket 状态是否为 "verified"
3. 校验 newPassword 格式
4. 从 Ticket 中提取 email，查询 users 表
5. 检查新密码是否与旧密码相同（SHA-512 比对）
6. 使用 SHA-512 哈希新密码
7. 更新 users.password_hash
8. 使该用户的所有已有 Token 失效（删除 Redis `sastlink:token:{uid}`）
9. 标记 RESETPWD-TICKET 为已使用
10. 返回成功

---

## 3. 用户管理 API

### 3.1 用户登出 —— POST /user/logout

**Auth：** Login-Token（`Token` Header）

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `20004` | Token错误 | Token 缺失或无效 |

**流程：** 从 Token header 提取 Login Token，解析 JWT 获取 uid，删除 Redis 中 `sastlink:token:{uid}` 记录。

---

### 3.2 修改密码 —— POST /user/changePassword

**Auth：** Login-Token
**Body：** `oldPassword`, `newPassword`

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | oldPassword 或 newPassword 缺失 |
| `20004` | Token错误 | Token 无效或过期 |
| `10005` | 登录失败 | oldPassword 不正确 |
| `10003` | 密码错误 | newPassword 不符合格式要求 |
| `10004` | 密码为空 | oldPassword 验证失败 |

**流程：** 验证 Token -> 校验 oldPassword（SHA-512）-> 校验新密码格式 -> SHA-512 哈希新密码 -> 更新数据库 -> 删除 Redis `sastlink:token:{uid}`。

---

### 3.3 获取用户信息 —— GET /user/info

**Auth：** Login-Token

**响应：** `ErrCode = 200`，`Data = { email, userId }`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `20004` | Token错误 | Token 无效或过期 |
| `10011` | 用户不存在 | 用户已被删除 |

---

### 3.4 获取用户资料 —— GET /profile/getProfile

**Auth：** Login-Token

**响应：** `ErrCode = 200`，`Data = UserProfile`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `20004` | Token错误 | Token 无效或过期 |
| `10011` | 用户不存在 | 用户不存在 |
| `80000` | 用户profile不存在 | 用户资料不存在 |

> **badge 时间字段**：返回 `created_at`（Go/GORM 标准命名）。前端需同步调整。

---

### 3.5 修改用户资料 —— POST /profile/changeProfile

**Auth：** Login-Token
**Body (JSON)：** `nickname`, `org_id`, `bio`, `link`, `hide`

**响应：** `ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | 字段格式错误 |
| `20004` | Token错误 | Token 无效或过期 |
| `10011` | 用户不存在 | 用户不存在 |
| `80001` | 组织填写错误 | org_id 不在 [-1, 26] |
| `80002` | 填写隐藏信息不合法 | hide 包含非允许值 |

---

### 3.6 上传头像 —— POST /profile/uploadAvatar

**Auth：** Login-Token
**Content-Type：** `multipart/form-data`
**Body：** `avatarFile`（图片文件，强制转换为 `.jpg`，最大 5MB）

**响应：** `ErrCode = 200`，`Data = { filePath: string }`

```json
{
  "Success": true,
  "Data": { "filePath": "https://cos.sast.fun/avatar/xxx.jpg" },
  "ErrCode": 200,
  "ErrMsg": ""
}
```

> **注意**：前端期望 `{ filePath: string }` 对象（老后端返回纯字符串，二者不兼容）。V2 返回对象以兼容前端。

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | 未上传文件或文件格式错误 |
| `20004` | Token错误 | Token 无效或过期 |
| `90002` | 图片URL地址错误 | 对象存储服务异常 |

**流程：** 验证 Token -> 读取文件 -> 校验大小 -> 强制转 .jpg -> 生成唯一文件名 -> 上传 COS/S3 -> 更新 avatar 字段 -> 返回 URL 字符串。

---

### 3.7 获取 OAuth 绑定状态 —— GET /profile/bindStatus

**Auth：** Login-Token

**响应：** `ErrCode = 200`，`Data = ["lark", "github"]`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `20004` | Token错误 | Token 无效或过期 |
| `10011` | 用户不存在 | 用户不存在 |

---

## 4. OAuth 登录 API

### 4.1 概述

标准 Authorization Code 流程。所有 OAuth 端点均不需要认证。

**State 管理：** 后端生成随机 state 存入 Cookie（`oauthstate`），回调时比对，验证通过后删除 Cookie。Cookie 属性：`HttpOnly; Secure; SameSite=Lax; Max-Age=600`。

**绑定决策：**

```
[OAuth 回调]
    |
    ▼
[检查 provider_user_id 是否已绑定]
    |
    ├─ 已绑定 ──→ [生成 Login Token] ──→ 返回 loginToken
    |
    └─ 未绑定
           |
           ▼
    [检查 provider_email 是否匹配已有用户]
           |
           ├─ 匹配 ──→ [可选自动绑定] ──→ 生成 Login Token
           |
           └─ 不匹配 ──→ [生成 OAuth-Ticket] ──→ 返回 oauthTicket
```

---

### 4.2 飞书登录

> **命名映射说明**：Provider 内部实现名称为 `feishu`，API 端点使用 `/login/lark`（兼容老后端），`bindStatus` 返回 `"lark"`（兼容前端）。三者指向同一身份源。

#### 4.2.1 登录入口 —— GET /login/lark

**Query：** `redirect_url`

**响应：** HTTP 302 重定向到飞书授权页面，同时设置 `oauthstate` Cookie。

#### 4.2.2 回调处理 —— GET /login/lark/callback

**Query：** `code`, `state`

**响应：** 已绑定返回 `loginToken`，未绑定返回 `oauthTicket`。`ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | code 或 state 缺失 |
| `20007` | Ticket不正确 | state 不匹配或已过期 |
| `50000` | 未知错误 | 飞书 API 调用失败 |
| `10010` | OAuth用户未注册或未绑定 | 用户信息获取失败 |

---

### 4.3 GitHub 登录

#### 4.3.1 登录入口 —— GET /login/github

**Query：** `redirect_url`

**响应：** HTTP 302 重定向到 GitHub 授权页面（scope=`user:email`），设置 `oauthstate` Cookie。

#### 4.3.2 回调处理 —— GET /login/github/callback

**Query：** `code`, `state`

**响应：** 已绑定返回 `loginToken`，未绑定返回 `oauthTicket`。`ErrCode = 200`

**错误码：**

| ErrCode | 说明 | 场景 |
|---------|------|------|
| `10001` | 请求参数错误 | code 或 state 缺失 |
| `20007` | Ticket不正确 | state 不匹配或已过期 |
| `50000` | 未知错误 | GitHub API 调用失败 |
| `10010` | OAuth用户未注册或未绑定 | 用户信息获取失败 |

---

### 4.4 Microsoft 登录（预留）

**状态：** V1 暂不实现。

| 方法 | 路径 |
|------|------|
| `GET` | `/login/microsoft` |
| `GET` | `/login/microsoft/callback` |

使用 `common` 租户 + PKCE 增强安全性。

---

### 4.5 QQ 登录（预留）

**状态：** V1 暂不实现。

| 方法 | 路径 |
|------|------|
| `GET` | `/login/qq` |
| `GET` | `/login/qq/callback` |

---

## 5. OAuth2 服务端 API（V1 实现）

**说明**：OAuth2 服务端 Access/Refresh Token 与用户 Login-Token 独立体系，不混淆。

### 5.1 授权码请求 —— GET /oauth2/authorize

**Query：** `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`

**响应：** HTTP 302 重定向到 `redirect_uri?code=xxx&state=xxx`

**错误时：** 重定向到 `redirect_uri?error=xxx&error_description=xxx&state=xxx`

**流程：**
1. 校验 `client_id` 和 `redirect_uri` 匹配
2. 用户未登录 → 302 到登录页，登录后回到此端点
3. 用户已登录 → 生成授权码（code），存入 Redis（TTL 10 分钟）
4. 302 重定向回 `redirect_uri`

---

### 5.2 换取 Token —— POST /oauth2/token

**Content-Type：** `application/x-www-form-urlencoded`
**Body：** `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `client_secret`

**响应：**
```json
{
  "Success": true,
  "Data": {
    "access_token": "xxx",
    "refresh_token": "xxx",
    "expires_in": 7200,
    "token_type": "Bearer"
  },
  "ErrCode": 200,
  "ErrMsg": ""
}
```

**Access Token：** JWT，2 小时过期，含 `uid`, `scope`
**Refresh Token：** 随机串，7 天过期，存 Redis

---

### 5.3 刷新 Token —— POST /oauth2/refresh

**Content-Type：** `application/x-www-form-urlencoded`
**Body：** `grant_type=refresh_token`, `refresh_token`, `client_id`, `client_secret`

**响应：** 新的 `access_token` + `refresh_token` 对（轮换机制）

---

### 5.4 注册客户端 —— POST /oauth2/create-client

**Auth：** Login-Token（仅管理员）
**Content-Type：** `application/json`
**Body：** `name`, `redirect_uris`（数组）, `scopes`（数组）

**响应：** `Data = { client_id, client_secret }`

---

### 5.5 撤销 Token —— POST /oauth2/revoke

**Content-Type：** `application/x-www-form-urlencoded`
**Body：** `token`, `token_type_hint`

---

### 5.6 获取用户信息 —— GET /oauth2/userinfo

**Auth：** Bearer `{access_token}`

**响应：**
```json
{
  "Success": true,
  "Data": {
    "sub": "user_id",
    "email": "xxx@njupt.edu.cn",
    "nickname": "xxx"
  },
  "ErrCode": 200,
  "ErrMsg": ""
}
```

---

## 6. 错误码体系

### 5.1 错误码定义表

**保留老后端全部 5 位错误码，不引入新码。**

| 错误码 | 含义 | 使用场景 |
|--------|------|----------|
| 10001 | 请求参数错误 | 参数缺失/格式错误 |
| 10002 | 用户名错误 | - |
| 10003 | 密码错误 | 密码格式不符 |
| 10004 | 密码为空 | - |
| 10005 | 登录失败 | 密码不匹配/登录失败 |
| 10007 | 重复注册 | 账号已存在 |
| 10010 | OAuth用户未注册或未绑定 | - |
| 10011 | 用户不存在 | - |
| 20002 | Token已超时 | - |
| 20003 | Token生成失败 | - |
| 20004 | Token错误 | Token 缺失/无效/解析失败 |
| 20006 | Token解析失败 | - |
| 20007 | Ticket不正确 | Ticket 无效/状态异常 |
| 20008 | Ticket不存在 | Ticket 已过期/未找到 |
| 30001 | 发送邮件失败 | - |
| 30002 | 验证码错误 | - |
| 30003 | 邮箱格式错误 | - |
| 40001 | 验证账户失败 | - |
| 40002 | 验证账户密码失败 | - |
| 50000 | 未知错误 | 内部错误 |
| 60001 | 客户端错误 | - |
| 60002 | access_token错误 | - |
| 60003 | refresh_token错误 | - |
| 70003 | 注册失败（阶段错误） | - |
| 70004 | 重置密码失败 | - |
| 80000 | 用户profile不存在 | - |
| 80001 | 组织填写错误 | org_id 不在 [-1, 26] |
| 80002 | 填写隐藏信息不合法 | hide 包含非允许值 |
| 90000 | 发送审核通知信息失败 | - |
| 90001 | 处理冻结图片失败 | - |
| 90002 | 图片URL地址错误 | - |

**成功响应：`ErrCode = 200`**

### 5.2 错误码分类规则

| 范围 | 类别 |
|------|------|
| `200` | 成功 |
| `1xxxx` | 用户/参数相关 |
| `2xxxx` | Token/Ticket 相关 |
| `3xxxx` | 邮件/验证码相关 |
| `4xxxx` | 验证相关 |
| `5xxxx` | 服务端/未知错误 |
| `6xxxx` | 客户端/OAuth Token |
| `7xxxx` | 注册/重置 |
| `8xxxx` | Profile/资料 |
| `9xxxx` | 图片/通知 |

---

## 6. 请求/响应 Schema

### 6.1 统一响应结构

```typescript
interface ApiResponse<T> {
  Success: boolean;
  Data: T | null;
  ErrCode: number;
  ErrMsg: string;
}
```

### 6.2 关键类型

```typescript
interface UserInfo {
  email: string;
  userId: string;
}

interface UserProfile {
  nickname: string;
  dep: string | null;
  org: string | null;
  email: string;
  avatar: string | null;
  bio: string | null;
  link: string[] | null;
  badge: Badge[] | null;
  hide: string[] | null;
}

interface Badge {
  title: string;
  description: string;
  created_at: string;  // Go/GORM 标准命名
}

// 前端期望 { filePath: string }（老后端返回纯字符串，V2 选对象兼容前端）
interface AvatarUploadResponse {
  filePath: string;
}
```

---

## 7. 附录

### 7.1 API 端点总览

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| `POST` | `/verify/account` | - | 验证账号，返回 Ticket |
| `POST` | `/sendEmail` | Ticket | 发送验证邮件 |
| `POST` | `/verify/captcha` | Ticket | 验证邮箱验证码 |
| `POST` | `/user/register` | Register-Ticket | 用户注册（SHA-512） |
| `POST` | `/user/login` | Login-Ticket | 用户登录（SHA-512） |
| `POST` | `/user/logout` | Login-Token | 用户登出 |
| `POST` | `/user/changePassword` | Login-Token | 修改密码（SHA-512） |
| `POST` | `/user/resetPassword` | ResetPwd-Ticket | 重置密码（SHA-512） |
| `GET` | `/user/info` | Login-Token | 获取用户信息 |
| `GET` | `/profile/getProfile` | Login-Token | 获取用户资料 |
| `POST` | `/profile/changeProfile` | Login-Token | 修改用户资料 |
| `POST` | `/profile/uploadAvatar` | Login-Token | 上传头像（Data 为 `{ filePath }` 对象） |
| `GET` | `/profile/bindStatus` | Login-Token | 获取 OAuth 绑定状态 |
| `GET` | `/login/lark` | - | 飞书登录入口 |
| `GET` | `/login/lark/callback` | - | 飞书回调 |
| `GET` | `/login/github` | - | GitHub 登录入口 |
| `GET` | `/login/github/callback` | - | GitHub 回调 |
| `GET` | `/login/microsoft` | - | 微软登录（预留） |
| `GET` | `/login/microsoft/callback` | - | 微软回调（预留） |
| `GET` | `/login/qq` | - | QQ 登录（预留） |
| `GET` | `/login/qq/callback` | - | QQ 回调（预留） |

### 7.2 限流策略

| 端点 | 限制 | 维度 |
|------|------|------|
| `/sendEmail` | 3 次/分钟 | 账号 |
| `/verify/captcha` | 5 次/分钟 | IP |
| `/user/login` | 5 次/分钟 | 账号 |
| `/user/register` | 3 次/小时 | IP |
| 全局 | 100 次/分钟 | IP |

### 7.3 前端兼容性说明

1. **错误码兼容**：使用老后端 5 位错误码体系，成功 ErrCode = 200
2. **Token 兼容**：单 Token 模式，有效期 7 天，与老后端一致
3. **字段名兼容**：前端期望 `loginToken` 字段
4. **Header 兼容**：前端使用 `Token` header
5. **uploadAvatar 兼容**：`Data` 为 `{ filePath: string }` 对象（兼容前端）
6. **badge 时间字段**：`created_at`（Go/GORM 标准命名，前端需同步调整）
7. **路径兼容**：所有端点路径与老后端完全一致

### 7.4 与老后端的兼容性修正

| 修正项 | 原错误设计 | 修正后 |
|--------|-----------|--------|
| 错误码 | 4 位码 | 5 位码（保留老后端全部） |
| 成功码 | ErrCode = 0 | ErrCode = 200 |
| Token | Access 15min + Refresh 7天 | 单 Token 7 天 |
| uploadAvatar | Data 为字符串 | `{ filePath: string }` 对象（兼容前端） |
| 密码 | bcrypt + SHA-512 双哈希 | 统一 SHA-512 |
| /refresh | 新增端点 | 删除（单 Token 不需要） |
| badge 时间 | `created_at` | `created_at`（标准命名） |

### 7.5 变更日志

| 版本 | 日期 | 变更内容 |
|------|------|---------|
| v1.0 | 2026-05-19 | 初始版本 |
| v1.2 | 2026-05-19 | 修正 badge 时间字段为 `create_at`、uploadAvatar 返回 `{ filePath }` 对象、补充 Content-Type |
| v1.3 | 2026-05-20 | badge 时间字段统一为 `created_at`（Go/GORM 标准），前端需同步调整 |

---

*文档结束。*
