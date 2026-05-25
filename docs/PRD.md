# SAST Link v2 PRD

## 1. 背景

### 1.1 定位

SAST Link 是南京邮电大学校大学生科学技术协会（SAST）的统一身份认证与人员管理系统

本项目（V2）基于一个初始项目 scaffold（Go + Gin + GORM + PostgreSQL）进行开发，直接在此基础上迭代重构，逐步实现全部功能。

### 1.2 目标

对 SAST Link 后端进行全面重构，引入 OAuth 2.1 标准作为认证授权体系，提升代码质量、可维护性和安全性。


## 2. 功能需求

同[SAST Oauth](https://njupt-sast.feishu.cn/wiki/PsalwqGZwiJyE9kjTQWcWuGknpc?from=from_copylink)

### 2.1 范围

- 账号注册/登录/登出/改密/重置密码
- 邮箱验证码
- 用户资料管理（查看/编辑/头像上传）
- GitHub / 飞书 OAuth 主动绑定/解绑 + 登录
- OAuth 首次登录注册补全教育邮箱
- 限流与防刷
- 操作日志 + 健康检查
- 头像内容审核（腾讯云 COS）
- OAuth2 授权服务端（Auth 2.1 标准）
- 管理后台
- 审计日志

### 2.2 非目标

以下功能/策略**不在 V2 范围内**：

- **API 契约**：不保证前端零改动，仅在性能或安全需求迫使时修改响应格式，需经技术评审
- **认证协议**：不限制为 JWT HS256，全面引入 OAuth 2.1 标准
- **管理后台**：第一版不实现细粒度 RBAC，仅基础成员管理
- **历史数据**：不迁移老用户历史操作日志，V2 从零开始记录
- **OAuth2 模式**：不限于授权码模式，按 OAuth 2.1 标准实现

## 3.技术架构

### 3.1技术栈

|层|技术|版本|
|---|---|---|
|语言|Go|1.26.3|
|Web 框架|Gin|v1.12.0|
|ORM|GORM|v1.31.1|
|数据库|PostgreSQL|16+（生产直连已有部署，开发用 Docker）|
|缓存|Redis|8+|
|对象存储|腾讯云 COS|—|
|邮件|SMTP|—|
|密码哈希|PBKDF2-HMAC-SHA512|—|
|认证授权|OAuth 2.1 + RS256|—|
|安全扫描|gosec + govulncheck|—|
|集成测试|testcontainers-go|—|

## 4. 功能详细说明

### 4.1 认证方式

```mermaid
flowchart TD
    A["客户端"] --> B{"应用类型"}
    B -->|"第一方"| C["PKCE-S256
无 client_secret"]
    B -->|"第三方"| D["client_id + client_secret
通过 /oauth2/register"]

    C --> E["请求认证"]
    D --> E

    E --> F{"已有 Token?"}
    F -->|"有 Access Token"| G["Authorization: Bearer
15min 有效期"]
    G --> H{"验证"}
    H -->|"有效"| I["放行"]
    H -->|"过期"| J["Refresh Token
Header 或 /token"]

    J --> K{"验证 7d"}
    K -->|"有效"| L["换发新 Token"]
    K -->|"过期"| M["重新认证"]

    F -->|"无 Token"| M

    M --> N{"认证方式"}
    N -->|"OAuth 登录"| O["/login/{provider}/callback
登录回调"]
    N -->|"OAuth 绑定"| P["/profile/bind/{provider}/callback
绑定回调"]
    N -->|"账号密码"| Q["Ticket 流程
*-TICKET Header
注册/登录/重置/绑定"]

    O --> R["GET /oauth2/authorize"]
    P --> R
    R -->|"参数错误/拒绝"| S["返回标准
error/error_description"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style F fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style H fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style K fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style N fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style I fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style L fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style S fill:#fef2f2,stroke:#ef4444,stroke-width:1px
```

### 4.2 注册流程

```mermaid
flowchart TD
    A["POST /verify/account
输入 @njupt.edu.cn 邮箱"] --> B{"校验邮箱格式 + 是否已注册"}
    B -->|"格式错误或已注册"| C["返回错误"]
    B -->|"校验通过"| D["生成 Register-Ticket"]
    D --> E["POST /sendEmail
发送验证码"]
    E --> F["用户收到验证码
S-XXXXX"]
    F --> G["POST /verify/captcha
校验验证码"]
    G -->|"验证码错误"| H["返回错误"]
    G -->|"校验通过"| I["POST /user/register
设置密码"]
    I --> J{"校验密码强度
6-64 位含字母+数字"}
    J -->|"强度不足"| K["返回错误"]
    J -->|"通过"| L["创建 user + profile"]
    L --> M["PBKDF2-HMAC-SHA512
哈希密码"]
    M --> N["生成 Access + Refresh Token"]
    N --> O["注册完成"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style J fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style C fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style H fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style K fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style O fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

### 4.3 登录流程

**分阶段登录**：先验证账号获取 Login-Ticket，再凭 Ticket 完成登录。

```mermaid
flowchart TD
    A["POST /verify/account
输入学号/邮箱"] --> B["查询 user.email
或 user_emails.email"]
    B -->|"账号不存在"| C["返回 10006"]
    B -->|"账号存在"| D["生成 Login-Ticket"]
    D --> E["返回 Login-Ticket
有效期 5 分钟"]
    E --> F["POST /user/login
输入密码 + Login-Ticket Header"]
    F --> G{"校验 Login-Ticket
有效"}
    G -->|"Ticket 无效"| H["返回 20007"]
    G -->|"Ticket 有效"| I["校验 PBKDF2-HMAC-SHA512
密码"]
    I -->|"密码错误"| J["返回 10005"]
    I -->|"密码正确"| K["检查 token_version
匹配"]
    K --> L["检查当前设备数"]
    L -->|"已达 5 设备"| M["淘汰最旧设备"]
    L -->|"未满 5 设备"| N["生成 Access + Refresh Token"]
    M --> N
    N --> O["Redis 记录 Token Family
DB 记录/更新 login_devices"]
    O --> P["返回双 Token"]

    style G fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style I fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style L fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style C fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style H fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style J fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style P fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

### 4.4 重置密码流程

```mermaid
flowchart TD
    A["POST /verify/account
输入邮箱"] --> B{"校验账号是否存在"}
    B -->|"账号不存在"| C["返回 10006"]
    B -->|"账号存在"| D["生成 ResetPwd-Ticket"]
    D --> E["POST /sendEmail
发送验证码"]
    E --> F["用户收到验证码"]
    F --> G["POST /verify/captcha
校验验证码"]
    G -->|"验证码错误"| H["返回 30002"]
    G -->|"校验通过"| I["POST /user/resetPassword
设置新密码"]
    I --> J{"校验密码强度"}
    J -->|"强度不足"| K["返回 10003"]
    J -->|"通过"| L["PBKDF2-HMAC-SHA512
哈希新密码"]
    L --> M["递增 token_version"]
    M --> N["使所有现有 Token 失效"]
    N --> O["重置成功"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style J fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style G fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style C fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style H fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style K fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style O fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

### 4.5 OAuth 注册补全流程

首次 OAuth 登录（GitHub/飞书）且未绑定任何账号时：

```mermaid
flowchart TD
    A["OAuth 回调"] --> B{"检查 provider_user_id
是否已绑定"}
    B -->|"已绑定"| C["生成 Access + Refresh Token"]
    C --> D["登录成功"]
    B -->|"未绑定"| E["返回 OAuth-Ticket
+ 临时用户信息"]
    E --> F["前端引导输入邮箱
发送验证码"]
    F --> G["POST /user/oauthRegister
Body: oauthTicket, email, captcha, password"]
    G --> H{"后端校验 email"}
    H -->|"已被注册"| I["返回错误
可选：换邮箱 或 走绑定已有账号"]
    I -->|"走绑定流程"| J["POST /user/oauthBindExisting
Body: oauthTicket, email, password"]
    J --> K{"校验 email + 密码
匹配已有账号"}
    K -->|"校验失败"| L["返回错误"]
    K -->|"校验通过"| M["绑定 OAuth 到已有账号"]
    M --> N["绑定成功"]
    H -->|"email 可用"| O["创建 user + profile 记录"]
    O --> P["绑定 OAuth"]
    P --> Q["生成 Token"]
    Q --> R["注册完成"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style H fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style K fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style D fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style N fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style R fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style L fill:#fef2f2,stroke:#ef4444,stroke-width:1px
```

**uid 生成规则**：所有用户注册时系统统一生成唯一 `uid`，格式 `u{8位随机字母数字}`（如 `u7a3k9p2`），不对外暴露学号。OAuth 注册用户 `student_id` 为 NULL。

### 4.6 邮箱绑定流程

已登录用户绑定第三方邮箱：

```mermaid
flowchart TD
    A["POST /profile/bindEmail"] --> B{"校验"}
    B -->|"邮箱格式无效"| C["返回错误"]
    B -->|"@njupt.edu.cn"| D["返回错误
教育邮箱不可绑定"]
    B -->|"已绑 2 个邮箱"| E["返回错误
已达上限"]
    B -->|"邮箱已被绑定"| F["返回错误"]
    B -->|"校验通过"| G["发送验证码邮件
生成 BindEmail-Ticket"]
    G --> H["用户收到验证码"]
    H --> I["POST /profile/verifyBindEmail
Body: email, captcha, bindEmailTicket"]
    I --> J{"校验 Ticket + 验证码"}
    J -->|"验证失败"| K["返回错误"]
    J -->|"验证通过"| L["创建 user_emails 记录"]
    L --> M["使 Ticket 失效"]
    M --> N["绑定成功"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style J fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style C fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style D fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style E fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style F fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style K fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style N fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

**解绑流程**：

```mermaid
flowchart TD
    A["POST /profile/unbindEmail
body: 要解绑的邮箱"] --> B["生成 UnbindEmail-Ticket
发送验证码到该邮箱"]
    B --> C["用户输入验证码"]
    C --> D["POST /profile/confirmUnbindEmail
email + captcha + unbindEmailTicket"]
    D --> E{校验 Ticket + 验证码}
    E -->|失败| F["返回错误"]
    E -->|通过| G["软删除 user_emails 记录"]
    G --> H["Redis 设置 unbind_cooldown:{email}
TTL 60s"]
    H --> I["解绑成功
冷却期内不可重新绑定"]

    style E fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style F fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style I fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

**登录适配**：

```mermaid
flowchart TD
    A["POST /user/login
输入邮箱"] --> B{"邮箱存在于哪个表?"}
    B -->|"user.email"| C["教育邮箱匹配"]
    B -->|"user_emails.email"| D["绑定邮箱匹配"]
    B -->|"都不存在"| E["返回 10006
账号不存在"]

    C --> F["PBKDF2 密码验证"]
    D --> F
    F -->|"密码错误"| G["返回 10005"]
    F -->|"密码正确"| H["检查 token_version
检查设备数"]
    H --> I["生成 Access + Refresh Token"]
    I --> J["记录 login_devices
Redis 记录 Token Family"]
    J --> K["返回双 Token"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style E fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style G fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style K fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

### 4.7 OAuth 2.1 端点

第一方应用使用 PKCE-S256，无需 client_secret。详细参数见 `docs/openapi.yaml`。

```mermaid
flowchart TD
    A["客户端"] -->|"① GET /oauth2/authorize
response_type=code + PKCE"| B{"用户已登录?"}
    B -->|"未登录"| C["302 重定向到登录页"]
    C -->|"登录完成后"| B
    B -->|"已登录"| D["用户授权确认"]
    D -->|"拒绝"| E["302 redirect_uri
error=access_denied"]
    D -->|"同意"| F["生成授权码 code
10min / 单次使用"]
    F -->|"302 redirect_uri
?code=xxx&state=xxx"| G["客户端收到授权码"]

    G -->|"② POST /oauth2/token
grant_type=authorization_code
code + code_verifier"| H{"验证 code + PKCE"}
    H -->|"失败"| I["返回 error"]
    H -->|"通过"| J["签发 access_token + refresh_token"]
    J --> K["返回 Token"]

    K -->|"③ POST /oauth2/revoke
token=xxx"| L["Token 失效"]
    K -->|"④ POST /oauth2/introspect
token=xxx"| M["查询 Token 状态"]

    style B fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style D fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style H fill:#eff6ff,stroke:#3b82f6,stroke-width:1px
    style E fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style I fill:#fef2f2,stroke:#ef4444,stroke-width:1px
    style F fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style J fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
    style K fill:#f0fdf4,stroke:#22c55e,stroke-width:1px
```

## 5. 实现顺序（Todo）

按以下顺序实现，打勾表示已完成：

* [x] 项目初始化、数据库设计、CI/CD
* [ ] 用户认证（注册 / 登录 / 验证码 / 改密 / 重置密码）
* [ ] 用户资料管理（查看 / 编辑 / 头像上传）
* [ ] OAuth 登录（GitHub / 飞书）
* [ ] OAuth 绑定 / 解绑 + 注册补全
* [ ] 限流与防刷
* [ ] 操作日志 + 健康检查
* [ ] 头像内容审核（腾讯云 COS）
* [ ] OAuth2 授权服务端（OAuth 2.1）
* [ ] OAuth2 客户端注册 API
* [ ] 管理后台
* [ ] 审计日志
* [ ] 测试、联调、上线
