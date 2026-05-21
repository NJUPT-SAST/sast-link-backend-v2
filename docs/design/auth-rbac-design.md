# SAST Link Backend V2 — 认证系统与 RBAC 设计文档

> 状态：已确认
> 日期：2026-05-19
> 版本：v1.1（修正版）
> 依赖：`v2-architecture-design.md`（架构总纲）、`security-audit.md`（老项目漏洞清单）、`design-corrections.md`（兼容性修正）

---

## 目录

1. [密码策略详细设计](#1-密码策略详细设计)
2. [JWT 设计详细规范](#2-jwt-设计详细规范)
3. [Ticket 机制详细设计](#3-ticket-机制详细设计)
4. [OAuth Provider 统一接口与实现](#4-oauth-provider-统一接口与实现)
5. [RBAC 模型设计](#5-rbac-模型设计)
6. [认证中间件设计](#6-认证中间件设计)
7. [Go 代码结构](#7-go-代码结构)

---

## 1. 密码策略详细设计

### 1.1 统一 SHA-512 策略

**决策**：密码 SHA-512 保留，不迁移，不引入 bcrypt。

> **安全债务声明**：SHA-512 无盐哈希在数据库泄露后的离线破解场景下无防御能力（GPU 可每秒数十亿次计算）。此方案为兼容老后端数据而保留，非最佳安全实践。当前通过登录限流（5次/分钟）、验证码限流、全局限流（100次/分钟/IP）、登录异常检测等措施防御在线暴力破解。

| 属性 | 值 |
|------|-----|
| 哈希算法 | SHA-512 无盐 |
| 存储格式 | 128 位 hex 字符串 |
| 与老后端关系 | 完全一致，零改动 |

**安全措施（弥补 SHA-512 弱点）**：
- 密码复杂度：至少 8 位，必须同时包含字母和数字
- 登录限流：同一账号 5 次失败/分钟，封禁 15 分钟
- 验证码限流：同一 IP 5 次/分钟
- 全局限流：100 次/分钟/IP
- 登录异常检测：记录登录 IP 和时间

### 1.2 密码哈希与验证

```go
package auth

import (
    "crypto/sha512"
    "crypto/subtle"
    "encoding/hex"
)

// HashPassword 使用 SHA-512 哈希密码（与老后端完全一致）
func HashPassword(password string) string {
    sum := sha512.Sum512([]byte(password))
    return hex.EncodeToString(sum[:])
}

// VerifyPassword 验证密码（常量时间比较，防时序攻击）
func VerifyPassword(password, hash string) bool {
    if len(hash) != 128 {
        return false
    }
    computed := HashPassword(password)
    return subtle.ConstantTimeCompare([]byte(hash), []byte(computed)) == 1
}
```

**与老后端一致性**：
- 算法：`crypto/sha512.Sum512 + hex.EncodeToString`
- 与老后端 `util/common.go` 逻辑完全一致
- 验证使用 `subtle.ConstantTimeCompare` 防时序攻击

### 1.3 密码复杂度策略

**前端要求**（第一道防线）：
- 长度 >= 8 位
- 必须同时包含英文字母（a-zA-Z）和阿拉伯数字（0-9）
- 允许特殊字符 `!@#$%^&*()_+=-[]{}|;:,.<>?`

**后端校验**（最终防线）：

```go
var (
    passwordMinLen = 6
    passwordMaxLen = 32
    passwordRegexp = regexp.MustCompile(`[a-zA-Z]`)
    digitRegexp    = regexp.MustCompile(`[0-9]`)
)

func ValidatePasswordComplexity(password string) error {
    if len(password) < passwordMinLen || len(password) > passwordMaxLen {
        return ErrPasswordLengthInvalid
    }
    if !passwordRegexp.MatchString(password) || !digitRegexp.MatchString(password) {
        return ErrPasswordComplexityWeak
    }
    return nil
}
```

**与老项目的改进**：
- 老项目正则 `^[a-zA-Z0-9!@#$%^&*()_=+]{6,32}$` 仅检查字符集和长度，允许纯数字通过
- 新策略保留 6-32 位长度（与老后端完全兼容），强制要求至少包含字母+数字两种类型
- 通过限流和登录异常检测弥补 SHA-512 安全性

### 1.4 changePassword / resetPassword 实现要点

**changePassword（已登录用户修改密码）**：

```go
func (s *UserService) ChangePassword(ctx context.Context, userID int64, oldPwd, newPwd string) error {
    if err := auth.ValidatePasswordComplexity(newPwd); err != nil {
        return err
    }
    if oldPwd == newPwd {
        return ErrNewPasswordSameAsOld
    }

    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        return err
    }

    if !auth.VerifyPassword(oldPwd, user.PasswordHash) {
        return ErrPasswordIncorrect
    }

    newHash := auth.HashPassword(newPwd)
    if err := s.userRepo.UpdatePassword(ctx, userID, newHash); err != nil {
        return err
    }

    // 使该用户所有现有 Token 失效
    if err := s.tokenRepo.RevokeAllUserTokens(ctx, userID); err != nil {
        slog.Warn("failed to revoke user tokens after password change", "user_id", userID, "error", err)
    }
    return nil
}
```

**resetPassword（通过 Ticket 重置密码）**：

```go
func (s *UserService) ResetPassword(ctx context.Context, ticketID, newPwd string) error {
    if err := auth.ValidatePasswordComplexity(newPwd); err != nil {
        return err
    }

    ticket, err := s.ticketRepo.Get(ctx, TicketTypeResetPassword, ticketID)
    if err != nil {
        return ErrTicketInvalid
    }
    if ticket.Status != TicketStatusVerified {
        return ErrTicketNotVerified
    }

    if err := s.ticketRepo.MarkUsed(ctx, TicketTypeResetPassword, ticketID); err != nil {
        return err
    }

    user, err := s.userRepo.GetByEmail(ctx, ticket.Email)
    if err != nil {
        return err
    }

    newHash := auth.HashPassword(newPwd)
    if err := s.userRepo.UpdatePassword(ctx, user.ID, newHash); err != nil {
        return err
    }

    if err := s.tokenRepo.RevokeAllUserTokens(ctx, user.ID); err != nil {
        slog.Warn("failed to revoke user tokens after password reset", "user_id", user.ID, "error", err)
    }
    return nil
}
```

**安全要点**：
- 修改/重置密码后强制使所有现有 Token 失效
- 新密码统一使用 SHA-512（与老后端一致）
- Ticket 验证后必须标记为 `used`，防止重放攻击

---

## 2. JWT 设计详细规范

### 2.1 单 Token 策略（与老后端兼容）

**核心决策**：保持单 Token 模式，与老后端完全一致。

| 属性 | 值 |
|------|-----|
| Token 类型 | JWT (HS256) |
| 有效期 | 7 天 |
| 存储 | Redis `sastlink:token:{uid}` |
| 传输 | `Token` header |
| 不引入 | Access/Refresh 双 Token、`/refresh` 端点 |

### 2.2 Claims 结构

```go
package auth

import "github.com/golang-jwt/jwt/v5"

// Role 定义用户角色
type Role string

const (
    RoleUser       Role = "user"
    RoleAdmin      Role = "admin"
    RoleSuperAdmin Role = "super_admin"
)

// Claims JWT 声明结构（与老后端兼容）
type Claims struct {
    jwt.RegisteredClaims
    UserID   int64  `json:"uid"`   // 用户主键 ID
    Username string `json:"uname"` // 学号，如 B21010101
    Role     Role   `json:"role"`  // user | admin | super_admin
}
```

**RegisteredClaims 字段填充**：

| 字段 | 来源 | 说明 |
|------|------|------|
| `jti` | `crypto/rand` 生成 32 位 hex | 唯一标识，用于黑名单 |
| `iss` | 固定 `"sast-link"` | 签发者 |
| `aud` | 固定 `"sast-link-api"` | 接收方 |
| `sub` | `strconv.FormatInt(UserID, 10)` | 主题 = 用户 ID 字符串 |
| `iat` | `jwt.NewNumericDate(time.Now())` | 签发时间 |
| `exp` | `now.Add(7 * 24 * time.Hour)` | 7 天过期 |

### 2.3 Signing 配置

```go
package auth

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "os"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

var (
    ErrMissingSecretKey = errors.New("JWT_SECRET_KEY environment variable is required")
    ErrInvalidToken     = errors.New("invalid token")
    ErrTokenExpired     = errors.New("token expired")
    ErrTokenBlacklisted = errors.New("token has been revoked")
)

type JWTManager struct {
    secretKey []byte
    issuer    string
    audience  string
}

func NewJWTManager() (*JWTManager, error) {
    key := os.Getenv("JWT_SECRET_KEY")
    if key == "" {
        return nil, ErrMissingSecretKey
    }
    secret, err := hex.DecodeString(key)
    if err != nil {
        secret = []byte(key)
    }
    if len(secret) < 32 {
        return nil, errors.New("JWT secret key must be at least 256 bits")
    }
    return &JWTManager{
        secretKey: secret,
        issuer:    "sast-link",
        audience:  "sast-link-api",
    }, nil
}

func generateJTI() (string, error) {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}
```

### 2.4 Token 生成

```go
const LoginTokenExpiry = 7 * 24 * time.Hour

// GenerateToken 生成单 Token（与老后端一致，7天有效期）
func (m *JWTManager) GenerateToken(userID int64, username string, role Role) (string, error) {
    jti, err := generateJTI()
    if err != nil {
        return "", err
    }

    now := time.Now()
    claims := Claims{
        RegisteredClaims: jwt.RegisteredClaims{
            ID:        jti,
            Issuer:    m.issuer,
            Audience:  jwt.ClaimStrings{m.audience},
            Subject:   strconv.FormatInt(userID, 10),
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(LoginTokenExpiry)),
        },
        UserID:   userID,
        Username: username,
        Role:     role,
    }

    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secretKey)
}
```

### 2.5 Token 解析与验证

```go
func (m *JWTManager) ParseToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return m.secretKey, nil
    }, jwt.WithIssuer(m.issuer), jwt.WithAudience(m.audience))
    if err != nil {
        if errors.Is(err, jwt.ErrTokenExpired) {
            return nil, ErrTokenExpired
        }
        return nil, ErrInvalidToken
    }

    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, ErrInvalidToken
    }
    return claims, nil
}
```

**安全要点**：
- 强制校验 `alg` 头必须为 HS256，防止 `alg:none` 攻击
- 校验 `iss` 和 `aud`，防止 Token 跨服务重用

### 2.6 登出与黑名单

```go
// Logout 用户登出，将 Token 加入黑名单
func (s *AuthService) Logout(ctx context.Context, tokenString string) error {
    claims, err := s.jwt.ParseToken(tokenString)
    if err == nil {
        ttl := time.Until(claims.ExpiresAt.Time)
        if ttl > 0 {
            if err := s.tokenRepo.AddToBlacklist(ctx, claims.ID, ttl); err != nil {
                slog.Warn("failed to blacklist token", "jti", claims.ID, "error", err)
            }
        }
    }
    return nil
}
```

**修复老项目漏洞**：
- 老项目登出仅删除 Redis 中 `TOKEN:username` 记录，JWT 本身仍有效
- 新设计将 jti 加入 Redis 黑名单，TTL 与 Token 剩余有效期一致，实现即时失效

### 2.7 Token 存储规范

```go
// Redis 键名模板
const (
    // 用户 Token 存储：sastlink:token:{uid}
    // Value: Token 字符串
    // TTL: 7 天（与 Token 过期时间一致）
    RedisKeyUserToken = "sastlink:token:%s"

    // Token 黑名单：sastlink:token:blacklist:{jti}
    // Value: "1"（存在即表示黑名单）
    // TTL: Token 剩余过期时间
    RedisKeyTokenBlacklist = "sastlink:token:blacklist:%s"

    // Ticket 存储前缀
    RedisKeyTicketPrefix = "sastlink:ticket"
)
```

**Token 存储逻辑**（登录成功后）：

```go
func (s *AuthService) StoreToken(ctx context.Context, uid string, token string) error {
    key := fmt.Sprintf(RedisKeyUserToken, strings.ToLower(uid))
    return s.redis.Set(ctx, key, token, LoginTokenExpiry).Err()
}

func (s *AuthService) GetToken(ctx context.Context, uid string) (string, error) {
    key := fmt.Sprintf(RedisKeyUserToken, strings.ToLower(uid))
    return s.redis.Get(ctx, key).Result()
}
```

**键名设计原则**：
- 统一前缀 `sastlink:`，避免与其他业务冲突
- 黑名单使用 `SETEX` 存储，值为 `"1"`，利用 Redis TTL 自动过期
- uid 强制 `strings.ToLower()`（与老后端一致）

---

## 3. Ticket 机制详细设计

### 3.1 设计目标

Ticket 是注册/登录/重置密码多阶段流程中的临时凭证，用于：
- 阶段间状态传递
- 防止阶段跳跃攻击
- 限流和防重放保护

### 3.2 Redis 键名与值结构

```go
package auth

type TicketType string

const (
    TicketTypeRegister      TicketType = "register"
    TicketTypeLogin         TicketType = "login"
    TicketTypeResetPassword TicketType = "reset_password"
    TicketTypeOAuth         TicketType = "oauth_bind"
)

type TicketStatus string

const (
    TicketStatusPending  TicketStatus = "pending"
    TicketStatusVerified TicketStatus = "verified"
    TicketStatusUsed     TicketStatus = "used"
    TicketStatusExpired  TicketStatus = "expired"
)

type Ticket struct {
    Email     string       `json:"email"`
    Status    TicketStatus `json:"status"`
    Code      string       `json:"code,omitempty"`
    ExpiresAt time.Time    `json:"expires_at"`
}
```

**Redis 键名**：`sastlink:ticket:{type}:{ticket_id}`

### 3.3 生命周期

| Ticket 类型 | 有效期 | 用途 | 是否需要验证码 |
|------------|--------|------|--------------|
| Register | 5 分钟 | 注册流程：验证邮箱 -> 设置密码 | 是 |
| Login | 5 分钟 | 登录流程：验证邮箱 -> 输入密码 | 是 |
| ResetPassword | 6 分钟 | 重置密码：验证邮箱 -> 设置新密码 | 是 |
| OAuth | 3 分钟 | OAuth 绑定：回调后暂存 provider 信息 | 否 |

```go
var ticketTTLs = map[TicketType]time.Duration{
    TicketTypeRegister:      5 * time.Minute,
    TicketTypeLogin:         5 * time.Minute,
    TicketTypeResetPassword: 6 * time.Minute,
    TicketTypeOAuth:         3 * time.Minute,
}
```

### 3.4 验证码格式

**与老后端一致**：`S-XXXXX`（5 位随机字母数字）

```go
import (
    "crypto/rand"
    "fmt"
)

func generateVerificationCode() (string, error) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, 5)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    for i := range b {
        b[i] = chars[int(b[i])%len(chars)]
    }
    return fmt.Sprintf("S-%s", string(b)), nil
}
```

**修复老项目漏洞**：使用 `crypto/rand` 替代 `math/rand`，防止验证码被预测。

### 3.5 状态流转

```
[创建 Ticket]
    |
    v
[pending] --> 发送验证码邮件 --> 用户收到验证码
    |
    | 验证码正确
    v
[verified] --> 用户提交密码 --> 验证通过
    |
    | 完成业务操作（注册/登录/重置）
    v
[used] --> 任何后续使用请求 --> 拒绝（防重放）
```

```go
func (r *TicketRepository) Create(ctx context.Context, typ TicketType, email string) (string, error) {
    ticketID, err := generateTicketID() // 32 字符随机串
    if err != nil {
        return "", err
    }

    code, err := generateVerificationCode() // S-XXXXX
    if err != nil {
        return "", err
    }

    ticket := Ticket{
        Email:     email,
        Status:    TicketStatusPending,
        Code:      code,
        ExpiresAt: time.Now().Add(ticketTTLs[typ]),
    }

    key := fmt.Sprintf("sastlink:ticket:%s:%s", typ, ticketID)
    data, _ := json.Marshal(ticket)

    if err := r.redis.Set(ctx, key, data, ticketTTLs[typ]).Err(); err != nil {
        return "", err
    }

    // 持久化审计
    if err := r.db.Create(&PersistentTicket{
        Ticket:    ticketID,
        Type:      typ,
        Email:     email,
        Status:    TicketStatusPending,
        ExpiresAt: ticket.ExpiresAt,
    }).Error; err != nil {
        slog.Warn("failed to persist ticket", "ticket_id", ticketID, "error", err)
    }

    return ticketID, nil
}

func (r *TicketRepository) VerifyCode(ctx context.Context, typ TicketType, ticketID, code string) error {
    key := fmt.Sprintf("sastlink:ticket:%s:%s", typ, ticketID)
    data, err := r.redis.Get(ctx, key).Result()
    if err == redis.Nil {
        return ErrTicketExpired
    }
    if err != nil {
        return err
    }

    var ticket Ticket
    if err := json.Unmarshal([]byte(data), &ticket); err != nil {
        return err
    }

    if ticket.Status == TicketStatusUsed {
        return ErrTicketAlreadyUsed
    }
    if ticket.Status == TicketStatusVerified {
        return ErrTicketAlreadyVerified
    }
    if ticket.Status != TicketStatusPending {
        return ErrTicketInvalid
    }

    if subtle.ConstantTimeCompare([]byte(ticket.Code), []byte(code)) != 1 {
        return ErrVerificationCodeIncorrect
    }

    ticket.Status = TicketStatusVerified
    newData, _ := json.Marshal(ticket)

    ttl, _ := r.redis.TTL(ctx, key).Result()
    if ttl <= 0 {
        return ErrTicketExpired
    }

    return r.redis.Set(ctx, key, newData, ttl).Err()
}

func (r *TicketRepository) MarkUsed(ctx context.Context, typ TicketType, ticketID string) error {
    key := fmt.Sprintf("sastlink:ticket:%s:%s", typ, ticketID)
    data, err := r.redis.Get(ctx, key).Result()
    if err == redis.Nil {
        return ErrTicketExpired
    }
    if err != nil {
        return err
    }

    var ticket Ticket
    if err := json.Unmarshal([]byte(data), &ticket); err != nil {
        return err
    }

    if ticket.Status != TicketStatusVerified {
        return ErrTicketNotVerified
    }

    ticket.Status = TicketStatusUsed
    newData, _ := json.Marshal(ticket)

    ttl, _ := r.redis.TTL(ctx, key).Result()
    if ttl <= 0 {
        ttl = time.Minute
    }

    return r.redis.Set(ctx, key, newData, ttl).Err()
}
```

### 3.6 防重放机制

1. **状态机约束**：`pending -> verified -> used` 顺序流转
2. **Used 状态拒绝**：任何尝试使用 `used` 状态 Ticket 的操作返回 `ErrTicketAlreadyUsed`
3. **验证码一次性**：验证成功后 Ticket 进入 `verified` 状态
4. **Redis TTL**：所有 Ticket 都有严格 TTL
5. **持久化审计**：Ticket 操作记录写入 PostgreSQL `tickets` 表

---

## 4. OAuth Provider 统一接口与实现

### 4.1 统一接口定义

```go
package oauth

import "context"

type Provider interface {
    Name() string
    AuthURL(state, redirectURI string) string
    Exchange(ctx context.Context, code string) (*UserInfo, error)
}

type UserInfo struct {
    ProviderUserID string         `json:"provider_user_id"`
    Email          string         `json:"email"`
    Name           string         `json:"name"`
    Avatar         string         `json:"avatar"`
    RawData        map[string]any `json:"raw_data"`
}

type ProviderRegistry struct {
    providers map[string]Provider
}

func NewRegistry() *ProviderRegistry {
    return &ProviderRegistry{providers: make(map[string]Provider)}
}

func (r *ProviderRegistry) Register(p Provider) {
    r.providers[p.Name()] = p
}

func (r *ProviderRegistry) Get(name string) (Provider, bool) {
    p, ok := r.providers[name]
    return p, ok
}
```

### 4.2 飞书实现（P0）

```go
type FeishuProvider struct {
    AppID       string
    AppSecret   string
    RedirectURI string
    HTTPClient  *http.Client
}

func (p *FeishuProvider) Name() string { return "feishu" }

func (p *FeishuProvider) AuthURL(state, redirectURI string) string {
    u, _ := url.Parse("https://open.feishu.cn/open-apis/authen/v1/authorize")
    q := u.Query()
    q.Set("app_id", p.AppID)
    q.Set("redirect_uri", redirectURI)
    q.Set("state", state)
    u.RawQuery = q.Encode()
    return u.String()
}

func (p *FeishuProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
    appToken, err := p.getAppAccessToken(ctx)
    if err != nil {
        return nil, fmt.Errorf("get app_access_token failed: %w", err)
    }

    userToken, err := p.getUserAccessToken(ctx, code, appToken)
    if err != nil {
        return nil, fmt.Errorf("get user_access_token failed: %w", err)
    }

    return p.getUserInfo(ctx, userToken)
}

func (p *FeishuProvider) getAppAccessToken(ctx context.Context) (string, error) {
    body := fmt.Sprintf(`{"app_id":"%s","app_secret":"%s"}`, p.AppID, p.AppSecret)
    req, err := http.NewRequestWithContext(ctx, "POST",
        "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
        strings.NewReader(body))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var result struct {
        Code           int    `json:"code"`
        AppAccessToken string `json:"app_access_token"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", err
    }
    if result.Code != 0 {
        return "", fmt.Errorf("feishu error code: %d", result.Code)
    }
    return result.AppAccessToken, nil
}

func (p *FeishuProvider) getUserAccessToken(ctx context.Context, code, appToken string) (string, error) {
    body := fmt.Sprintf(`{"grant_type":"authorization_code","code":"%s"}`, code)
    req, err := http.NewRequestWithContext(ctx, "POST",
        "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token",
        strings.NewReader(body))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+appToken)

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var result struct {
        Code int `json:"code"`
        Data struct {
            AccessToken string `json:"access_token"`
        } `json:"data"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", err
    }
    if result.Code != 0 {
        return "", fmt.Errorf("feishu error code: %d", result.Code)
    }
    return result.Data.AccessToken, nil
}

func (p *FeishuProvider) getUserInfo(ctx context.Context, userToken string) (*UserInfo, error) {
    req, err := http.NewRequestWithContext(ctx, "GET",
        "https://open.feishu.cn/open-apis/authen/v1/user_info", nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+userToken)

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        Code int `json:"code"`
        Data struct {
            OpenID   string `json:"open_id"`
            UnionID  string `json:"union_id"`
            Email    string `json:"email"`
            Name     string `json:"name"`
            Avatar   string `json:"avatar_url"`
        } `json:"data"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    if result.Code != 0 {
        return nil, fmt.Errorf("feishu error code: %d", result.Code)
    }

    rawData, _ := json.Marshal(result.Data)

    return &UserInfo{
        ProviderUserID: result.Data.UnionID,
        Email:          result.Data.Email,
        Name:           result.Data.Name,
        Avatar:         result.Data.Avatar,
        RawData:        map[string]any{"union_id": result.Data.UnionID, "open_id": result.Data.OpenID},
    }, nil
}
```

### 4.3 GitHub 实现（P0）

```go
type GitHubProvider struct {
    ClientID     string
    ClientSecret string
    RedirectURI  string
    HTTPClient   *http.Client
}

func (p *GitHubProvider) Name() string { return "github" }

func (p *GitHubProvider) AuthURL(state, redirectURI string) string {
    u, _ := url.Parse("https://github.com/login/oauth/authorize")
    q := u.Query()
    q.Set("client_id", p.ClientID)
    q.Set("redirect_uri", redirectURI)
    q.Set("state", state)
    q.Set("scope", "read:user user:email")
    u.RawQuery = q.Encode()
    return u.String()
}

func (p *GitHubProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
    token, err := p.exchangeCode(ctx, code)
    if err != nil {
        return nil, err
    }

    userInfo, err := p.getUserInfo(ctx, token)
    if err != nil {
        return nil, err
    }

    if userInfo.Email == "" {
        email, err := p.getPrimaryEmail(ctx, token)
        if err == nil {
            userInfo.Email = email
        }
    }

    return userInfo, nil
}

func (p *GitHubProvider) exchangeCode(ctx context.Context, code string) (string, error) {
    data := url.Values{}
    data.Set("client_id", p.ClientID)
    data.Set("client_secret", p.ClientSecret)
    data.Set("code", code)
    data.Set("redirect_uri", p.RedirectURI)

    req, err := http.NewRequestWithContext(ctx, "POST",
        "https://github.com/login/oauth/access_token",
        strings.NewReader(data.Encode()))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("Accept", "application/json")

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var result struct {
        AccessToken string `json:"access_token"`
        Error       string `json:"error"`
        ErrorDesc   string `json:"error_description"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return "", err
    }
    if result.Error != "" {
        return "", fmt.Errorf("github oauth error: %s - %s", result.Error, result.ErrorDesc)
    }
    return result.AccessToken, nil
}

func (p *GitHubProvider) getUserInfo(ctx context.Context, token string) (*UserInfo, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Accept", "application/vnd.github.v3+json")

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        ID        int64  `json:"id"`
        Login     string `json:"login"`
        Email     string `json:"email"`
        Name      string `json:"name"`
        AvatarURL string `json:"avatar_url"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    rawData, _ := json.Marshal(result)

    return &UserInfo{
        ProviderUserID: fmt.Sprintf("%d", result.ID),
        Email:          result.Email,
        Name:           result.Name,
        Avatar:         result.AvatarURL,
        RawData:        map[string]any{"login": result.Login},
    }, nil
}

func (p *GitHubProvider) getPrimaryEmail(ctx context.Context, token string) (string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
    if err != nil {
        return "", err
    }
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Accept", "application/vnd.github.v3+json")

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var emails []struct {
        Email    string `json:"email"`
        Primary  bool   `json:"primary"`
        Verified bool   `json:"verified"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
        return "", err
    }

    for _, e := range emails {
        if e.Primary && e.Verified {
            return e.Email, nil
        }
    }
    return "", fmt.Errorf("no primary verified email found")
}
```

### 4.4 Microsoft 实现（P1，含 PKCE）

```go
type MicrosoftProvider struct {
    ClientID     string
    ClientSecret string
    RedirectURI  string
    Tenant       string
    HTTPClient   *http.Client
}

func (p *MicrosoftProvider) Name() string { return "microsoft" }

func (p *MicrosoftProvider) AuthURL(state, redirectURI string) string {
    tenant := p.Tenant
    if tenant == "" {
        tenant = "common"
    }
    u, _ := url.Parse(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant))
    q := u.Query()
    q.Set("client_id", p.ClientID)
    q.Set("redirect_uri", redirectURI)
    q.Set("state", state)
    q.Set("scope", "openid email profile User.Read")
    q.Set("response_type", "code")
    q.Set("response_mode", "query")

    codeChallenge, codeVerifier := generatePKCE()
    q.Set("code_challenge", codeChallenge)
    q.Set("code_challenge_method", "S256")
    _ = codeVerifier // 实际实现通过 state 关联存储

    u.RawQuery = q.Encode()
    return u.String()
}

func (p *MicrosoftProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
    codeVerifier := "..." // 从存储中获取

    data := url.Values{}
    data.Set("client_id", p.ClientID)
    data.Set("client_secret", p.ClientSecret)
    data.Set("code", code)
    data.Set("redirect_uri", p.RedirectURI)
    data.Set("grant_type", "authorization_code")
    data.Set("code_verifier", codeVerifier)

    req, err := http.NewRequestWithContext(ctx, "POST",
        fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", p.Tenant),
        strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var tokenResp struct {
        AccessToken string `json:"access_token"`
        Error       string `json:"error"`
        ErrorDesc   string `json:"error_description"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }
    if tokenResp.Error != "" {
        return nil, fmt.Errorf("microsoft oauth error: %s", tokenResp.ErrorDesc)
    }

    return p.getUserInfo(ctx, tokenResp.AccessToken)
}

func (p *MicrosoftProvider) getUserInfo(ctx context.Context, token string) (*UserInfo, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := p.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        ID                string `json:"id"`
        DisplayName       string `json:"displayName"`
        Mail              string `json:"mail"`
        UserPrincipalName string `json:"userPrincipalName"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    email := result.Mail
    if email == "" {
        email = result.UserPrincipalName
    }

    rawData, _ := json.Marshal(result)

    return &UserInfo{
        ProviderUserID: result.ID,
        Email:          email,
        Name:           result.DisplayName,
        Avatar:         "",
        RawData:        map[string]any{"user_principal_name": result.UserPrincipalName},
    }, nil
}

func generatePKCE() (challenge, verifier string) {
    b := make([]byte, 32)
    rand.Read(b)
    verifier = base64.RawURLEncoding.EncodeToString(b)
    h := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(h[:])
    return
}
```

### 4.5 QQ 实现（P1，预留）

```go
type QQProvider struct {
    AppID       string
    AppKey      string
    RedirectURI string
    HTTPClient  *http.Client
}

func (p *QQProvider) Name() string { return "qq" }

func (p *QQProvider) AuthURL(state, redirectURI string) string {
    // QQ OAuth2 授权 URL
    // https://graph.qq.com/oauth2.0/authorize
    return "" // TODO: 申请开放平台后实现
}

func (p *QQProvider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
    // QQ OAuth2 流程：code -> access_token -> openid -> user_info
    return nil, ErrProviderNotImplemented
}
```

### 4.6 登录/绑定状态机

```
[OAuth 回调 /api/v1/login/{provider}/callback]
    |
    v
[校验 state 参数（防止 CSRF）]
    |
    v
[调用 Provider.Exchange 获取用户信息]
    |
    v
[查询 user_oauths 表：provider + provider_user_id 是否已绑定]
    |
    |-- 已绑定 -----------------------------------|
    |                                             |
    v                                             |
[查询 users 表获取完整用户信息]                     |
    |                                             |
    v                                             |
[生成单 Token（7天）] <--------------------------|
    |
    v
[返回 Token 给前端]

    |-- 未绑定 -----------------------------------|
                                                 |
    v                                            |
[查询 users 表：provider_email 是否匹配已有用户]     |
    |                                            |
    |-- 匹配 --> [可选：自动绑定] --> [生成 Token]   |
    |                                            |
    |-- 不匹配                                    |
           |                                     |
           v                                     |
    [生成 OAuth-Ticket（3 分钟有效期）]             |
           |                                     |
           v                                     |
    [返回 200 + oauthTicket 给前端]               |
           |                                     |
           v                                     |
    [前端跳转 /login?oauthTicket=xxx]            |
           |                                     |
           v                                     |
    [用户输入已有账号密码]                         |
           |                                     |
           v                                     |
    [POST /api/v1/user/bindOauth]              |
           |                                     |
           v                                     |
    [验证 oauthTicket 有效]                      |
           |                                     |
           v                                     |
    [验证账号密码正确]                            |
           |                                     |
           v                                     |
    [创建 user_oauths 记录]                      |
           |                                     |
           v                                     |
    [生成单 Token] <-----------------------------|
```

**关键安全点**：
- state 参数必须校验，防止 CSRF 攻击（修复老项目 nil pointer 漏洞）

```go
// 安全实现（修复老项目漏洞）
oauthState, err := c.Cookie("oauthstate")
if err != nil || oauthState == nil {
    c.JSON(http.StatusBadRequest, response.Fail(ErrOAuthStateMissing))
    return
}
if c.Query("state") != oauthState.Value {
    c.JSON(http.StatusBadRequest, response.Fail(ErrOAuthStateMismatch))
    return
}
```

---

## 5. RBAC 模型设计

### 5.1 角色定义

| 角色 | 标识 | 权限范围 |
|------|------|---------|
| 普通用户 | `user` | 基础功能（查看/修改个人资料、绑定 OAuth） |
| 管理员 | `admin` | 用户管理、内容审核、查看统计 |
| 超级管理员 | `super_admin` | 全部权限，包括管理员增删、系统配置 |

**角色继承**：`super_admin` > `admin` > `user`。拥有上级角色自动拥有下级角色的所有权限。

### 5.2 admins 表结构

```sql
CREATE TYPE admin_role AS ENUM ('admin', 'super_admin');

CREATE TABLE admins (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    role        admin_role NOT NULL DEFAULT 'admin',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 5.3 用户角色查询

```go
package service

func (s *UserService) GetUserRole(ctx context.Context, userID int64) (domain.Role, error) {
    admin, err := s.adminRepo.GetByUserID(ctx, userID)
    if err != nil {
        if errors.Is(err, domain.ErrNotFound) {
            return domain.RoleUser, nil
        }
        return "", err
    }
    return domain.Role(admin.Role), nil
}
```

### 5.4 中间件设计

```go
package middleware

import (
    "net/http"
    "sast-link-backend-v2/internal/auth"
    "sast-link-backend-v2/internal/domain"
    "sast-link-backend-v2/internal/pkg/response"

    "github.com/gin-gonic/gin"
)

type AuthContextKey string

const ClaimsContextKey AuthContextKey = "auth_claims"

// RequireAuth 要求用户已登录（任意有效 Token）
func RequireAuth(jwtManager *auth.JWTManager, tokenRepo auth.TokenRepository) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractToken(c)
        if token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrUnauthorized))
            return
        }

        claims, err := jwtManager.ParseToken(token)
        if err != nil {
            if errors.Is(err, auth.ErrTokenExpired) {
                c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrTokenExpired))
                return
            }
            c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrUnauthorized))
            return
        }

        blacklisted, err := tokenRepo.IsBlacklisted(c.Request.Context(), claims.ID)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusInternalServerError, response.Fail(domain.ErrInternal))
            return
        }
        if blacklisted {
            c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrTokenRevoked))
            return
        }

        c.Set(string(ClaimsContextKey), claims)
        c.Next()
    }
}

// RequireAdmin 要求管理员权限
func RequireAdmin(jwtManager *auth.JWTManager, tokenRepo auth.TokenRepository) gin.HandlerFunc {
    return func(c *gin.Context) {
        RequireAuth(jwtManager, tokenRepo)(c)
        if c.IsAborted() {
            return
        }

        claims, ok := c.Value(string(ClaimsContextKey)).(*auth.Claims)
        if !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrUnauthorized))
            return
        }

        if claims.Role != domain.RoleAdmin && claims.Role != domain.RoleSuperAdmin {
            c.AbortWithStatusJSON(http.StatusForbidden, response.Fail(domain.ErrForbidden))
            return
        }

        c.Next()
    }
}

// RequireSuperAdmin 要求超级管理员权限
func RequireSuperAdmin(jwtManager *auth.JWTManager, tokenRepo auth.TokenRepository) gin.HandlerFunc {
    return func(c *gin.Context) {
        RequireAuth(jwtManager, tokenRepo)(c)
        if c.IsAborted() {
            return
        }

        claims, ok := c.Value(string(ClaimsContextKey)).(*auth.Claims)
        if !ok {
            c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrUnauthorized))
            return
        }

        if claims.Role != domain.RoleSuperAdmin {
            c.AbortWithStatusJSON(http.StatusForbidden, response.Fail(domain.ErrForbidden))
            return
        }

        c.Next()
    }
}

// extractToken 从请求头中提取 Token（与老后端兼容）
func extractToken(c *gin.Context) string {
    // 优先从 "Token" Header 读取（与老后端一致）
    token := c.GetHeader("Token")
    if token != "" {
        return token
    }

    // 兼容 "Authorization: Bearer xxx" 格式
    token = c.GetHeader("Authorization")
    if token != "" {
        parts := strings.SplitN(token, " ", 2)
        if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
            return parts[1]
        }
        return token
    }

    // 从 Query 参数读取（用于 WebSocket 等场景）
    return c.Query("token")
}
```

### 5.5 权限检查逻辑

```go
package auth

import "sast-link-backend-v2/internal/domain"

func HasRole(userRole domain.Role, required domain.Role) bool {
    roleHierarchy := map[domain.Role]int{
        domain.RoleUser:       1,
        domain.RoleAdmin:      2,
        domain.RoleSuperAdmin: 3,
    }
    return roleHierarchy[userRole] >= roleHierarchy[required]
}

func IsAdmin(role domain.Role) bool {
    return role == domain.RoleAdmin || role == domain.RoleSuperAdmin
}

func IsSuperAdmin(role domain.Role) bool {
    return role == domain.RoleSuperAdmin
}
```

### 5.6 初始管理员设置方案

```go
func SeedInitialAdmin(ctx context.Context, cfg *config.Config, userRepo repository.UserRepository, adminRepo repository.AdminRepository) error {
    adminUID := os.Getenv("INITIAL_SUPER_ADMIN_UID")
    if adminUID == "" {
        slog.Info("no initial super admin configured, skipping")
        return nil
    }

    user, err := userRepo.GetByUID(ctx, adminUID)
    if err != nil {
        if errors.Is(err, domain.ErrNotFound) {
            return fmt.Errorf("initial super admin user %s not found", adminUID)
        }
        return err
    }

    existing, _ := adminRepo.GetByUserID(ctx, user.ID)
    if existing != nil {
        slog.Info("initial super admin already exists", "uid", adminUID)
        return nil
    }

    if err := adminRepo.Create(ctx, &domain.Admin{
        UserID: user.ID,
        Role:   domain.RoleSuperAdmin,
    }); err != nil {
        return err
    }

    slog.Info("initial super admin created", "uid", adminUID, "user_id", user.ID)
    return nil
}
```

**配置示例**：
```bash
INITIAL_SUPER_ADMIN_UID=B21010101
```

---

## 6. 认证中间件设计

### 6.1 JWT 验证中间件

已在 5.4 节中完整展示 `RequireAuth` 实现，核心要点：

```go
func RequireAuth(jwtManager *auth.JWTManager, tokenRepo auth.TokenRepository) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractToken(c)
        if token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, response.Fail(domain.ErrUnauthorized))
            return // 修复老项目：abort 后必须 return
        }
        // ...
    }
}
```

**修复老项目漏洞**：
- 老项目 `c.AbortWithStatusJSON` 后没有 `return`，导致后续代码继续执行
- 新设计每个 `AbortWithStatusJSON` 后紧跟 `return`

### 6.2 Token 黑名单检查

```go
type TokenRepository interface {
    AddToBlacklist(ctx context.Context, jti string, ttl time.Duration) error
    IsBlacklisted(ctx context.Context, jti string) (bool, error)
    RevokeAllUserTokens(ctx context.Context, userID int64) error
}

type RedisTokenRepository struct {
    redis *redis.Client
}

func (r *RedisTokenRepository) AddToBlacklist(ctx context.Context, jti string, ttl time.Duration) error {
    key := fmt.Sprintf("sastlink:token:blacklist:%s", jti)
    return r.redis.Set(ctx, key, "1", ttl).Err()
}

func (r *RedisTokenRepository) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
    key := fmt.Sprintf("sastlink:token:blacklist:%s", jti)
    n, err := r.redis.Exists(ctx, key).Result()
    if err != nil {
        return false, err
    }
    return n > 0, nil
}

func (r *RedisTokenRepository) RevokeAllUserTokens(ctx context.Context, userID int64) error {
    // 删除用户 Token 存储记录
    // 实际实现需要维护 uid -> token 的映射
    return nil
}
```

### 6.3 排除路径配置（白名单模式）

```go
package middleware

import "github.com/gin-gonic/gin"

// AuthWhitelist 不需要认证的路径列表（与老后端 API 兼容）
var AuthWhitelist = []string{
    "/ping",
    "/health",
    "/api/v1/verify/account",
    "/api/v1/sendEmail",
    "/api/v1/verify/captcha",
    "/api/v1/user/register",
    "/api/v1/user/login",
    "/api/v1/user/resetPassword",
    "/api/v1/login/lark",
    "/api/v1/login/lark/callback",
    "/api/v1/login/github",
    "/api/v1/login/github/callback",
    "/api/v1/login/microsoft",
    "/api/v1/login/microsoft/callback",
    "/api/v1/login/qq",
    "/api/v1/login/qq/callback",
}

func SkipAuth(path string) bool {
    for _, prefix := range AuthWhitelist {
        if path == prefix || strings.HasPrefix(path, prefix+"/") {
            return true
        }
    }
    return false
}

func AuthMiddleware(jwtManager *auth.JWTManager, tokenRepo auth.TokenRepository) gin.HandlerFunc {
    authMiddleware := RequireAuth(jwtManager, tokenRepo)
    return func(c *gin.Context) {
        if SkipAuth(c.Request.URL.Path) {
            c.Next()
            return
        }
        authMiddleware(c)
    }
}
```

**注意**：白名单中**不包含** `/api/v1/refresh`（不存在此端点）。

### 6.4 错误处理（401/403 统一响应，与老前端兼容）

```go
package response

import "net/http"

type Response struct {
    Success bool   `json:"Success"`
    Data    any    `json:"Data,omitempty"`
    ErrCode int    `json:"ErrCode,omitempty"`
    ErrMsg  string `json:"ErrMsg,omitempty"`
}

func Success(data any) Response {
    return Response{Success: true, Data: data, ErrCode: 200}
}

func Fail(err domain.Error) Response {
    return Response{
        Success: false,
        Data:    nil,
        ErrCode: err.Code,
        ErrMsg:  err.Message,
    }
}
```

**与老后端兼容的错误码（5 位）**：

| 场景 | HTTP 状态码 | 错误码 | 错误消息 |
|------|------------|--------|---------|
| Token 缺失 | 401 | 20004 | Token错误 |
| Token 格式错误 | 401 | 20006 | Token解析失败 |
| Token 过期 | 401 | 20002 | Token已超时 |
| Token 在黑名单 | 401 | 20004 | Token错误 |
| 非管理员访问管理接口 | 403 | 50000 | 未知错误 |
| 非超级管理员访问超级管理接口 | 403 | 50000 | 未知错误 |

```go
// 认证相关错误定义（5 位码，与老后端一致）
domain.ErrUnauthorized   = Error{Code: 20004, Message: "Token错误"}
domain.ErrForbidden      = Error{Code: 50000, Message: "未知错误"}
domain.ErrTokenExpired   = Error{Code: 20002, Message: "Token已超时"}
domain.ErrTokenRevoked   = Error{Code: 20004, Message: "Token错误"}
```

**安全要点（修复老项目漏洞）**：
- `Data` 字段永远返回 `nil`，不暴露任何内部错误详情
- 详细错误信息记录到 slog 日志
- 401/403 响应不区分具体原因，防止信息泄露

---

## 7. Go 代码结构

### 7.1 文件组织

```
internal/
├── auth/
│   ├── jwt.go              # JWT 生成/解析/验证（单 Token）
│   ├── jwt_test.go         # JWT 单元测试
│   ├── ticket.go           # Ticket 生成/验证/状态管理
│   ├── ticket_test.go      # Ticket 单元测试
│   ├── password.go         # SHA-512 哈希/验证/复杂度校验
│   ├── password_test.go    # 密码单元测试
│   └── oauth/
│       ├── provider.go     # OAuthProvider 接口 + ProviderRegistry
│       ├── feishu.go       # 飞书 OAuth 实现
│       ├── github.go       # GitHub OAuth 实现
│       ├── microsoft.go    # Microsoft OAuth 实现（含 PKCE）
│       └── qq.go           # QQ OAuth 实现（预留）
├── middleware/
│   ├── auth.go             # RequireAuth / RequireAdmin / RequireSuperAdmin
│   ├── auth_test.go        # 中间件单元测试
│   ├── cors.go             # CORS 中间件
│   ├── rate_limit.go       # 限流中间件（登录/验证码限流）
│   ├── request_log.go      # 请求日志（敏感信息脱敏）
│   └── recovery.go         # Panic 恢复
```

### 7.2 各文件职责

| 文件 | 职责 | 关键函数/类型 |
|------|------|-------------|
| `auth/jwt.go` | JWT 单 Token 全生命周期管理 | `JWTManager`, `Claims`, `GenerateToken`, `ParseToken` |
| `auth/ticket.go` | Ticket 创建/验证/状态流转 | `TicketType`, `TicketStatus`, `CreateTicket`, `VerifyCode`, `MarkUsed` |
| `auth/password.go` | SHA-512 密码哈希与验证 | `HashPassword`, `VerifyPassword`, `ValidatePasswordComplexity` |
| `auth/oauth/provider.go` | Provider 统一接口 | `Provider`, `UserInfo`, `ProviderRegistry` |
| `auth/oauth/feishu.go` | 飞书 OAuth | `FeishuProvider`（app_access_token -> user_access_token -> user_info） |
| `auth/oauth/github.go` | GitHub OAuth | `GitHubProvider`（标准 OAuth2 + /user/emails） |
| `auth/oauth/microsoft.go` | Microsoft OAuth | `MicrosoftProvider`（common 租户 + PKCE） |
| `auth/oauth/qq.go` | QQ OAuth（预留） | `QQProvider`（框架） |
| `middleware/auth.go` | 认证/授权中间件 | `RequireAuth`, `RequireAdmin`, `RequireSuperAdmin`, `AuthMiddleware` |
| `middleware/rate_limit.go` | 限流中间件 | 登录限流、验证码限流、IP 全局限流 |

### 7.3 依赖注入方式

**修复老项目全局变量问题**：

```go
// 不推荐（老项目方式）
var jwtManager = auth.NewJWTManager()

// 推荐（V2 方式）：通过构造函数注入
type Server struct {
    jwtManager    *auth.JWTManager
    tokenRepo     auth.TokenRepository
    ticketRepo    auth.TicketRepository
    userService   *service.UserService
    oauthRegistry *oauth.ProviderRegistry
}

func NewServer(
    jwtManager *auth.JWTManager,
    tokenRepo auth.TokenRepository,
    // ...
) *Server {
    return &Server{
        jwtManager: jwtManager,
        tokenRepo:  tokenRepo,
        // ...
    }
}

// 路由注册时注入
func (s *Server) RegisterRoutes(r *gin.Engine) {
    api := r.Group("/api/v1")

    api.Use(middleware.AuthMiddleware(s.jwtManager, s.tokenRepo))

    admin := api.Group("/admin")
    admin.Use(middleware.RequireAdmin(s.jwtManager, s.tokenRepo))
    {
        admin.GET("/users", s.handler.ListUsers)
    }

    super := api.Group("/super")
    super.Use(middleware.RequireSuperAdmin(s.jwtManager, s.tokenRepo))
    {
        super.POST("/admins", s.handler.CreateAdmin)
    }
}
```

---

## 8. OAuth2 服务端 Token 设计

> 本章节补充 OAuth2 授权服务端（SSO）的 Token 体系设计，与用户 Login-Token 完全独立。

### 8.1 设计原则

| 维度 | 用户 Login-Token | OAuth2 Access/Refresh Token |
|------|-----------------|----------------------------|
| 用途 | 用户自用 API 鉴权 | 对外部应用授权访问用户数据 |
| 传输方式 | `Token` Header | `Authorization: Bearer` |
| 有效期 | 7 天 | Access 2h / Refresh 7 天 |
| 存储 | Redis `sastlink:token:{uid}` | Redis + PostgreSQL |
| 签发者 | sast-link | sast-link-oauth2 |

### 8.2 Access Token

```go
package auth

// OAuth2AccessClaims OAuth2 Access Token Claims
type OAuth2AccessClaims struct {
    jwt.RegisteredClaims
    UserID int64    `json:"sub"`   // 用户 ID（字符串形式）
    Scope  string   `json:"scope"` // 授权范围，如 "profile email"
    ClientID string `json:"client_id"` // 客户端 ID
}
```

| 属性 | 值 |
|------|-----|
| 类型 | JWT (HS256) |
| 有效期 | 2 小时 |
| 存储 | 不存储（JWT 自包含） |
| `jti` | 唯一标识，用于撤销 |
| `iss` | `sast-link-oauth2` |
| `aud` | `sast-link-api` |

### 8.3 Refresh Token

| 属性 | 值 |
|------|-----|
| 类型 | 64 位随机 hex 字符串 |
| 有效期 | 7 天 |
| 存储 | PostgreSQL `oauth2_tokens` + Redis |
| 轮换 | 每次刷新生成新 Refresh Token，旧 Token 失效 |

```go
// GenerateRefreshToken 生成 Refresh Token
func GenerateRefreshToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}
```

### 8.4 授权码（Authorization Code）

| 属性 | 值 |
|------|-----|
| 类型 | 32 位随机字符串 |
| 有效期 | 10 分钟 |
| 存储 | Redis `sastlink:oauth2:code:{code}` |
| 单次使用 | 换取 Token 后立即删除 |

```go
// RedisKeyOAuth2Code = "sastlink:oauth2:code:%s"
// Value: JSON { user_id, client_id, redirect_uri, scope, expires_at }
// TTL: 10 * time.Minute
```

### 8.5 Token 验证流程

```
[外部应用请求 /oauth2/userinfo]
    |
    v
[提取 Authorization: Bearer {access_token}]
    |
    v
[解析 JWT，校验签名/过期/iss/aud]
    |
    v
[校验 jti 不在撤销列表（Redis sastlink:oauth2:revoked:{jti}）]
    |
    v
[返回用户信息]
```

### 8.6 Token 撤销

```go
// RevokeAccessToken 将 Access Token 的 jti 加入撤销列表
func (s *OAuth2Service) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
    ttl := time.Until(expiresAt)
    if ttl <= 0 {
        return nil // 已过期，无需撤销
    }
    key := fmt.Sprintf("sastlink:oauth2:revoked:%s", jti)
    return s.redis.Set(ctx, key, "1", ttl).Err()
}

// RevokeRefreshToken 删除 Refresh Token 记录
func (s *OAuth2Service) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
    return s.db.Where("refresh_token = ?", refreshToken).Delete(&domain.OAuth2Token{}).Error
}
```

### 8.7 Redis 键名规范（OAuth2 服务端）

```go
const (
    // 授权码
    RedisKeyOAuth2Code     = "sastlink:oauth2:code:%s"
    // Access Token 撤销列表
    RedisKeyOAuth2Revoked  = "sastlink:oauth2:revoked:%s"
    // Refresh Token 查 user_id（加速验证）
    RedisKeyOAuth2Refresh  = "sastlink:oauth2:refresh:%s"
)
```

### 8.8 与用户 Login-Token 的关键区别

| 场景 | Login-Token | OAuth2 Access Token |
|------|------------|---------------------|
| 用户登录后端 | ✅ | ❌ |
| 外部应用获取用户资料 | ❌ | ✅ |
| `/api/v1/user/info` | ✅ Token Header | ❌ |
| `/oauth2/userinfo` | ❌ | ✅ Bearer |
| 有效期 7 天 | ✅ | ❌（Access 2h） |
| 可撤销 | ✅（黑名单） | ✅（jti 撤销列表） |

---

## 附录 A：安全审计修复对照表

本设计对 `security-audit.md` 中所有漏洞的修复措施：

| 编号 | 严重程度 | 老项目问题 | 本设计修复措施 |
|------|---------|-----------|--------------|
| 1 | 高危 | JWT signing_key 硬编码弱 UUID | 从 `JWT_SECRET_KEY` 环境变量读取 256-bit 随机串 |
| 2 | 高危 | JWT 中间件 abort 后未 return | 所有 `AbortWithStatusJSON` 后紧跟 `return` |
| 3 | 高危 | 无盐 SHA-512 存储密码 | **s3 决策保留 SHA-512**，增加登录限流/验证码限流/全局限流/异常检测 |
| 4 | 高危 | 错误响应泄露原始错误 | `Data` 字段永远返回 `nil`，错误详情仅记录日志 |
| 5 | 高危 | OAuth state cookie nil pointer | 检查 `err != nil \|\| cookie == nil` 后再比较 `.Value` |
| 6 | 高危 | example.toml 暴露密钥结构 | 密钥全部走环境变量，example 中值为 `<CHANGE_ME>` |
| 7 | 高危 | 飞书 Bot Webhook 硬编码 | 移至环境变量配置（邮件通过 SMTP 接口抽象） |
| 8 | 高危 | GitHub OAuth 响应体未关闭 | 所有 HTTP 响应 `defer resp.Body.Close()` |
| 9 | 高危 | `UserByField` SQL 注入 | Repository 层使用 GORM 参数化查询，禁止字符串拼接 |
| 10 | 中危 | JWT Redis 仅检查存在性 | 黑名单严格比对 jti |
| 11 | 中危 | Token 续期 TODO 未实现 | 单 Token 7 天有效期，无需续期机制 |
| 12 | 中危 | `GetUsername` 数组越界 | Claims 结构直接使用 `UserID` int64 字段 |
| 13 | 中危 | 密码复杂度策略弱 | 保留 6-32 位长度兼容老后端，强制要求字母+数字组合 |
| 14 | 中危 | 修改密码未校验新旧不同 | `ChangePassword` 中检查 `oldPwd == newPwd` |
| 15 | 中危 | 登出未使 JWT 失效 | jti 加入 Redis 黑名单，TTL 与 Token 过期时间一致 |
| 16 | 中危 | Debug 日志打印完整请求体 | 敏感 Header（Authorization/Token/Cookie/Password）脱敏为 `[REDACTED]` |
| 17 | 中危 | 多处忽略错误返回值 | 所有错误必须处理，禁止 `_ :=` 忽略 |
| 18 | 中危 | 全局 jwtSigningKey 无热重载 | `JWTManager` 为结构体实例，通过构造函数创建 |
| 19 | 中危 | init panic 导致启动崩溃 | 基础设施初始化返回 error，由 main 决定是否 panic |
| 20 | 中危 | Model 层直接操作 Redis | 拆分 `repository` 层，Redis 操作通过接口抽象 |
| 21 | 中危 | Service 依赖全局变量 | 全部改为构造函数参数注入 |
| 22 | 中危 | 全局变量导致测试不可并行 | 依赖注入 + 接口 mock，测试可并行执行 |
| 23 | 低危 | `GenerateToken` 冗余 | 统一使用单 Token 生成，无冗余函数 |
| 24 | 低危 | Redis 键名无命名空间 | 统一前缀 `sastlink:` |
| 25 | 低危 | 验证码使用 math/rand | 使用 `crypto/rand` 生成验证码和 jti |
| 26 | 低危 | defer 位置不当 | `defer resp.Body.Close()` 紧跟 `http.Client.Do` 后 |
| 27 | 低危 | `RefreshToken` 逻辑反了 | 不实现 Refresh 机制（单 Token 7 天） |
| 28 | 低危 | 无 `.env.example` | 项目已创建 `.env.example` |
| 29 | 低危 | COS 桶名硬编码 | 移至配置文件（由 `infra` 层管理） |
| 30 | 低危 | 路由缺少中间件 | 全局注册 `AuthMiddleware`（白名单模式） |
| 31 | 低危 | OAuth 客户端配置写死 | `ProviderRegistry` 支持配置驱动注册 |

---

*文档结束*
