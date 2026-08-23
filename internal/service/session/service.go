package session

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/mailer"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/objectstore"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

const (
	defaultAccessTTL  = time.Hour
	defaultRefreshTTL = 30 * 24 * time.Hour
	// verificationTTL bounds email verification codes and the tickets derived
	// from them (Register-Ticket / Bind-Ticket), per the API contract's 5-minute
	// one-time semantics.
	verificationTTL = 5 * time.Minute
	// maxOtherMailBindings is the per-user cap on other_mail identities.
	maxOtherMailBindings = 2
	// auditTimeout bounds a detached audit write so a completed action's row
	// still lands after the caller disconnects, without hanging the worker.
	auditTimeout = 5 * time.Second
)

var sessionScopes = scope.InternalSessionScopes

type Service struct {
	Users            UserRepository
	Clients          ClientRepository
	Tokens           TokenRepository
	Audit            AuditRepository
	Identities       IdentityRepository
	Limiter          EndpointLimiter
	EmailLimiter     EndpointLimiter
	EmailIPLimiter   EndpointLimiter
	Failures         LoginFailureStore
	Blacklist        TokenBlacklist
	Mailer           Mailer
	VerificationCode VerificationCodeStore
	RegisterTicket   RegisterTicketStore
	BindTicket       BindTicketStore
	// OAuthRegistration reads the identity parked by an OAuth callback. A nil
	// value disables OAuth-completed registration, which is what a deployment
	// with no third-party providers configured wants.
	OAuthRegistration OAuthRegistrationStore
	// UnbindLimiter is separate from Limiter because checkEndpointLimit reads the
	// quota off the instance, not the endpoint name — sharing one would give unbind
	// the login budget.
	UnbindLimiter EndpointLimiter
	// RegisterLimiter throttles POST /auth/register per caller IP. A valid
	// Register-Ticket is required to reach the write, so this bounds cost rather
	// than guessing: every accepted call runs an argon2id derivation.
	RegisterLimiter EndpointLimiter
	// CardLimiter throttles the unauthenticated GET /card/:id per caller IP. The
	// path parameter is a sequential user ID, so an uncapped endpoint is a scrape
	// of every public card.
	CardLimiter EndpointLimiter
	// RefreshLimiter throttles POST /auth/refresh per caller IP. The endpoint is
	// unauthenticated and each call runs several DB statements, so without a cap a
	// single source can amplify DB work for free (see config.RateLimitRefreshRPM).
	RefreshLimiter   EndpointLimiter
	ForgotPasswords  ForgotPasswordDispatcher
	InternalClientID string
	JWT              *auth.JWTManager
	RefreshTokens    *auth.RefreshTokenManager
	Passwords        auth.PasswordHasher
	Clock            Clock
	AccessTTL        time.Duration
	RefreshTTL       time.Duration

	// AvatarStore persists avatar objects; AvatarAuditor reviews them. Both are
	// optional: a nil store means object storage is not configured and avatar
	// upload answers 50002, keeping every other endpoint alive on a deployment
	// without storage.
	AvatarStore   objectstore.ObjectStore
	AvatarAuditor objectstore.AvatarAuditor
	// AvatarLimiter throttles PUT /user/avatar per caller. Separate from
	// Limiter because checkEndpointLimit reads the quota off the instance, not
	// the endpoint name.
	AvatarLimiter EndpointLimiter

	// Devices persists per-user device records in Redis (PRD §6.1). Device
	// records are operational state, so every session-flow write through this
	// port is fail-open: a hiccup must not fail a login, refresh, logout or
	// password change. DeviceOwnedBy is the exception and fails closed, gating
	// "logout a specific device" against cross-user family revokes.
	Devices DeviceStore
	// DeviceLimiter throttles DELETE /user/devices/:id per user, like the unbind
	// limiter — the subject is the user, not the IP, because the device list
	// belongs to an authenticated account.
	DeviceLimiter EndpointLimiter
}

func (s Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	identifier := normalizeIdentifier(input.Identifier)
	if identifier == "" || input.Password == "" {
		return nil, newError(ErrInvalidInput, "登录参数无效", nil)
	}
	if err := s.checkEndpointLimit(ctx, s.Limiter, "login", loginLimitSubject(input, identifier)); err != nil {
		return nil, err
	}
	// Lean lookup: the login response serializes only scalar user fields, so the
	// Profile/Identities preloads would be two dead SQL statements per login.
	user, err := s.Users.FindAuthUserByLoginIdentifier(ctx, identifier)
	if errors.Is(err, repository.ErrNotFound) {
		failureKey := loginFailureKey(nil, identifier)
		if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
			return nil, lockErr
		}
		return nil, s.failLogin(ctx, nil, input, failureKey, ErrUnknownIdentifier, "登录标识不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询登录用户失败", err)
	}
	failureKey := loginFailureKey(user, identifier)
	if lockErr := s.checkLoginLock(ctx, failureKey); lockErr != nil {
		return nil, lockErr
	}
	if user.State == model.UserStateDeleted {
		if auditErr := s.audit(ctx, &user.ID, "login", "session", nil, nil, false, errcode.CodeAccountDeleted, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)}); auditErr != nil {
			slog.Error("audit deleted login failure", "user_id", user.ID, "error", auditErr)
		}
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}
	if passwordErr := s.Passwords.VerifyPassword(ctx, input.Password, user.PasswordHash); passwordErr != nil {
		// A cancelled or timed-out caller never proved anything about the password,
		// so it must not be recorded as a failed attempt: doing so would let a
		// client that disconnects mid-login drive its own account into the lockout
		// window.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, newError(ErrDependencyUnavailable, "密码校验被中断", passwordErr)
		}
		return nil, s.failLogin(ctx, user, input, failureKey, ErrPasswordInvalid, "密码错误", passwordErr)
	}
	// Rehash a stale hash in place once the password is proven, so a KDF parameter
	// change (scheme, work factor) reaches existing accounts on their next login
	// instead of verifying at the old cost forever. This is an optimization, not an
	// auth gate: a failed write keeps the old hash and the login still succeeds.
	if s.Passwords.ShouldRehash(user.PasswordHash) {
		newHash, hashErr := s.Passwords.HashPassword(ctx, input.Password)
		if hashErr != nil {
			slog.WarnContext(ctx, "rehash password on login failed", "user_id", user.ID, "error", hashErr)
		} else if updateErr := s.Users.UpdatePasswordHash(ctx, user.ID, user.PasswordHash, newHash); updateErr != nil {
			// The rehash is guarded on the hash this login verified: a concurrent
			// password change/reset that landed in between wins, and the skipped
			// rehash must not surface as a failure.
			if !errors.Is(updateErr, repository.ErrRehashSkipped) {
				slog.WarnContext(ctx, "persist rehashed password failed", "user_id", user.ID, "error", updateErr)
			}
		}
	}
	// The built-in client is resolved only after the password verifies: a wrong
	// password is exactly the pattern an endpoint is hammered with, and probing
	// it must not make every attempt hit oauth_clients as well.
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	pair, err := s.issuePair(user, client, 0, "", sessionScopes)
	if err != nil {
		return nil, err
	}
	// Build the audit row before the token transaction so a marshal error fails
	// before any write; the row then rides the same commit as the token pair, so
	// the session and its audit are atomic at the cost of a single fsync, and no
	// compensate-on-audit branch is needed.
	var audit *model.AuditLog
	if s.Audit != nil {
		audit, err = s.buildAuditEntry(&user.ID, "login", "session", nil, nil, true, 0,
			input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, identifier)})
		if err != nil {
			return nil, newError(ErrInternal, "构造审计记录失败", err)
		}
	}
	if err := s.Tokens.CreatePairWithAudit(ctx, pair.access, pair.refresh, audit); err != nil {
		return nil, newError(ErrInternal, "创建 Token Pair 失败", err)
	}
	if s.Failures != nil {
		if resetErr := s.Failures.Reset(ctx, failureKey); resetErr != nil {
			// A stale counter can lock this identifier until its 15min window
			// expires, which is strictly better than revoking a valid session
			// and refusing every login for as long as Redis is unavailable.
			slog.WarnContext(ctx, "reset login failures unavailable", "error", resetErr)
		}
	}
	// Device registration happens after every compensable step: the family is
	// committed and audited by this point, so a failed record write only costs a
	// WARN and the device shows up on the next login. Registering before the
	// audit would leave an orphan record for every session the compensate path
	// revokes.
	if s.Devices != nil {
		evicted, err := s.Devices.RegisterDevice(ctx, user.ID, pair.familyID, input.UserAgent, input.ClientIP, s.now())
		if err != nil {
			slog.WarnContext(ctx, "register device failed", "user_id", user.ID, "error", err)
		}
		// Eviction revokes the displaced family even when the record write
		// partially failed: the set already made room, and leaving the old
		// session live would create an invisible, unmanageable ghost session.
		s.revokeEvictedDevice(ctx, user.ID, evicted, s.now(), input.ClientIP, input.UserAgent)
	}
	return &LoginResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
		Profile:          profileDTO(user),
	}, nil
}

func (s Service) Refresh(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	if strings.TrimSpace(input.RefreshToken) == "" {
		return nil, newError(ErrInvalidInput, "刷新参数无效", nil)
	}
	// Unauthenticated and DB-heavy, so it is throttled before any lookup — the
	// limiter must bound the amplification, not sit behind the work it exists to cap.
	if err := s.checkEndpointLimit(ctx, s.RefreshLimiter, "refresh", strings.TrimSpace(input.ClientIP)); err != nil {
		return nil, err
	}
	tokenHash, err := s.RefreshTokens.HashRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, newError(ErrInvalidToken, "Refresh Token 无效", err)
	}
	current, err := s.Tokens.FindRefreshToken(ctx, tokenHash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "Refresh Token 无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 Refresh Token 失败", err)
	}
	if current.RevokedAt != nil {
		// Within the grace window this is a benign concurrent refresh (the winning
		// rotation preserved the family) and must not be cut, or the winning tab
		// would be logged out. Beyond the window it is a true replay of a
		// long-dead token: cut the family, which also invalidates the cached
		// auth-state entries for every sibling token.
		if !repository.IsWithinRefreshGrace(*current.RevokedAt, s.now()) {
			entries, revokeErr := s.Tokens.RevokeFamily(ctx, current.FamilyID, s.now())
			if revokeErr != nil {
				return nil, newError(ErrInternal, "撤销被重放的 Refresh Token 家族失败", revokeErr)
			}
			s.deliverBlacklist(ctx, entries, s.now())
			// Replay kills the whole family, and the family is the device record:
			// without the cleanup the device list keeps showing a session that can
			// no longer authenticate. Fail-open — the revoke already committed.
			if s.Devices != nil {
				if removeErr := s.Devices.RemoveDevice(ctx, current.UserID, current.FamilyID); removeErr != nil {
					slog.WarnContext(ctx, "remove device on replay revoke failed", "user_id", current.UserID, "device_id", current.FamilyID, "error", removeErr)
				}
			}
			s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, refreshOutcomeReplayed, input)
			return nil, newError(ErrInvalidToken, "Refresh Token 无效", nil)
		}
		// Benign concurrent refresh within the grace window: the family (and the
		// winning tab's session) is preserved. Return a distinct outcome so the
		// handler does not clear the cookie, which now holds the winner's token.
		s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, refreshOutcomeConcurrent, input)
		return nil, newError(ErrConcurrentRefresh, "刷新请求冲突，请重试", nil)
	}
	if !current.ExpiresAt.After(s.now()) {
		// The session is over: the refresh anchor is dead, so the device record
		// must not keep showing a live login. Fail-open — the expiration itself
		// is authoritative in the DB.
		if s.Devices != nil {
			if removeErr := s.Devices.RemoveDevice(ctx, current.UserID, current.FamilyID); removeErr != nil {
				slog.WarnContext(ctx, "remove device on expired refresh failed", "user_id", current.UserID, "device_id", current.FamilyID, "error", removeErr)
			}
		}
		s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, refreshOutcomeExpired, input)
		return nil, newError(ErrInvalidToken, "Refresh Token 无效", nil)
	}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	if current.ClientID != client.ID {
		s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, refreshOutcomeClientMismatch, input)
		return nil, newError(ErrInvalidToken, "Refresh Token 与客户端不匹配", nil)
	}
	user, err := s.Users.FindAuthUserByID(ctx, current.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "Refresh Token 所属用户无效", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 Refresh Token 所属用户失败", err)
	}

	pair, err := s.issuePair(user, client, current.Sequence+1, current.FamilyID, []string(current.Scopes))
	if err != nil {
		return nil, err
	}
	// The refresh proves the device is alive; update last_seen without extending
	// the device TTL, so an abandoned device ages out instead of being kept
	// alive by refreshes. A refresh of an already-expired record resurrects it
	// (it is clearly still in use), which re-enters the per-user cap: the
	// displaced family is revoked exactly like login eviction. Fail-open: the
	// rotated pair is already committed.
	//
	// The touch runs BEFORE the rotation commit: a terminating path (logout of
	// the device, replay revoke, password change) that interleaves with this
	// refresh always removes the record after the touch, so it can never be
	// resurrected with a fresh TTL by a refresh whose family was just revoked.
	// Running it after the commit would open exactly that window — the
	// resurrect branch re-registers the record and the terminated session stays
	// visible (and occupying a cap slot) until a manual delete or the TTL.
	//
	// The touch's eviction side-effect is deferred until AFTER the rotation
	// commits, though: revoking the displaced family is the "最多 5 台" cap
	// enforcement, and it must only fire for a refresh that actually landed. A
	// refresh whose family was revoked between the pre-checks above and the
	// rotate (a concurrent logout or eviction) still resurrects and evicts
	// through the touch — the resurrect branch cannot know the family is doomed —
	// but revoking a different, healthy device's family as collateral for a
	// rotation that then fails would log the user out of a session they never
	// touched. Deferring the revoke makes a doomed refresh non-destructive.
	//
	// The residual cost of deferral: the touch already removed the displaced
	// device's record from the set, and skipping the family revoke leaves that
	// device briefly invisible in the list while its session stays live — a
	// ghost that reappears on its own next refresh (the resurrect branch
	// re-registers it). Acceptable: strictly better than logging the user out
	// of a device they never touched, and it self-heals.
	var evicted string
	if s.Devices != nil {
		evicted, err = s.Devices.TouchDevice(ctx, current.UserID, current.FamilyID, input.UserAgent, input.ClientIP, s.now())
		if err != nil {
			slog.WarnContext(ctx, "touch device failed", "user_id", current.UserID, "device_id", current.FamilyID, "error", err)
		}
	}
	// The success audit rides the rotation transaction, so the refresh waits on
	// one fsync instead of two. A build failure (practically unreachable — the
	// detail map is constant) logs and drops the success row; there is no
	// synchronous fallback.
	var audit *model.AuditLog
	if s.Audit != nil {
		audit, err = s.buildAuditEntry(&current.UserID, "refresh", "session", &current.FamilyID, nil, true, 0,
			input.ClientIP, input.UserAgent, map[string]any{"outcome": refreshOutcomeRotated})
		if err != nil {
			slog.WarnContext(ctx, "build refresh audit entry", "error", err)
			audit = nil
		}
	}
	if _, rotateErr := s.Tokens.RotateRefreshTokenWithAudit(ctx, current.FamilyID, tokenHash, pair.access, pair.refresh, audit); rotateErr != nil {
		if errors.Is(rotateErr, repository.ErrTokenReplayWithinGrace) {
			// A benign concurrent refresh: another request in this family already
			// rotated, and the repository preserved the family. The presented token
			// is dead, but the device record belongs to the still-live family and
			// must not be dropped — removing it would leave the winning session
			// invisible in the device list and free its cap slot.
			s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, refreshOutcomeConcurrent, input)
			return nil, newError(ErrConcurrentRefresh, "刷新请求冲突，请重试", rotateErr)
		}
		if errors.Is(rotateErr, repository.ErrTokenReplay) || errors.Is(rotateErr, repository.ErrTokenExpired) || errors.Is(rotateErr, repository.ErrTokenFamilyRevoked) || errors.Is(rotateErr, repository.ErrNotFound) {
			// RotateRefreshToken already cut the family in its own transaction and
			// enqueued the blacklist outbox rows. A second RevokeFamily here would
			// find no live token (the refresh token outlives every access token, so
			// an expired one means the whole family is dead) and deliver nothing.
			// ErrNotFound is the same shape — the presented row vanished between the
			// pre-read and the rotation (a concurrent deletion) — and mapping it to
			// 500 would tell the caller nothing actionable about a session that is
			// simply gone.
			// The repository cut the family; drop the device record so the list
			// stops showing a session that can no longer authenticate.
			if s.Devices != nil {
				if removeErr := s.Devices.RemoveDevice(ctx, current.UserID, current.FamilyID); removeErr != nil {
					slog.WarnContext(ctx, "remove device on rotation failure failed", "user_id", current.UserID, "device_id", current.FamilyID, "error", removeErr)
				}
			}
			s.auditRefresh(ctx, current.UserID, &current.FamilyID, false, refreshOutcomeReplayed, input)
			return nil, newError(ErrInvalidToken, "Refresh Token 无效", rotateErr)
		}
		return nil, newError(ErrInternal, "轮换 Refresh Token 失败", rotateErr)
	}
	// The rotation committed: the refresh is real, so the touch's displaced
	// device (if any) must be evicted exactly like a login eviction. revokeEvictedDevice
	// no-ops on an empty ID (a live-record touch that evicted nothing).
	s.revokeEvictedDevice(ctx, current.UserID, evicted, s.now(), input.ClientIP, input.UserAgent)
	return &RefreshResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
	}, nil
}

func (s Service) Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error) {
	principalJTI := strings.TrimSpace(input.PrincipalJTI)
	if principalJTI == "" || input.PrincipalUserID <= 0 {
		return nil, newError(ErrInvalidInput, "登出参数无效", nil)
	}
	access, err := s.Tokens.FindAccessTokenByJTI(ctx, principalJTI)
	if errors.Is(err, repository.ErrNotFound) {
		// The access token is gone — the session being logged out is already
		// dead. Idempotent: the handler clears the cookie and reports success so
		// a user with a revoked session is never stuck unable to log out.
		return nil, newError(ErrInvalidToken, "会话已不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询 Access Token 失败", err)
	}
	now := s.now()
	// A revoked access token is a dead session — the handler maps this to an
	// idempotent success. An *expired* one is not dead in the family sense: it
	// still names a live refresh family, and logout is family-wide revocation, so
	// a stale tab whose 1h access token ran out must still revoke the family its
	// refresh tokens outlive. This mirrors oauth.familyByAccessJTI, which likewise
	// revokes an expired access token's family rather than treating expiry as
	// "nothing to revoke".
	if access.RevokedAt != nil {
		return nil, newError(ErrInvalidToken, "会话已失效", nil)
	}
	// The family to revoke is the authenticated session's own — the access
	// token's family. The body/cookie refresh token is deliberately not required
	// to match: in the stale-tab case (the cookie carries a newer login's
	// family) requiring a match made logout report "已登出" without revoking
	// anything.
	if access.FamilyID == nil {
		// An internal session always carries a family; a missing one is a server
		// anomaly, not a successful logout — surface it rather than lie.
		return nil, newError(ErrInternal, "Access Token 无会话家族", nil)
	}
	familyID := *access.FamilyID
	entries, revokeErr := s.Tokens.RevokeFamily(ctx, familyID, now)
	if revokeErr != nil {
		return nil, newError(ErrInternal, "撤销 Token 家族失败", revokeErr)
	}
	s.deliverBlacklist(ctx, entries, now)
	// The family is revoked; drop its device record so the device list reflects
	// what can actually authenticate. Fail-open: the session is already dead and
	// a leftover record expires on its own.
	if s.Devices != nil {
		if err := s.Devices.RemoveDevice(ctx, input.PrincipalUserID, familyID); err != nil {
			slog.WarnContext(ctx, "remove device on logout failed", "user_id", input.PrincipalUserID, "device_id", familyID, "error", err)
		}
	}
	if auditErr := s.audit(ctx, &input.PrincipalUserID, "logout", "session", &familyID, nullableString(s.actorClientID(input.ActorClientID)), true, 0, input.ClientIP, input.UserAgent, map[string]any{}); auditErr != nil {
		slog.Error("audit logout", "family_id", familyID, "error", auditErr)
	}
	return &LogoutResult{BlacklistedJTI: principalJTI, FamilyID: familyID}, nil
}

func (s Service) Profile(ctx context.Context, input ProfileInput) (*ProfileResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidInput, "用户资料参数无效", nil)
	}
	// Two-query profile load (user+profile JOIN + lean identities) instead of
	// FindByID's three.
	user, err := s.Users.FindProfileByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "用户资料身份主体无效", nil)
	}
	if err == nil && user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询用户资料失败", err)
	}
	return &ProfileResult{Profile: profileDTO(user)}, nil
}

func (s Service) SendRegisterCode(ctx context.Context, input SendRegisterCodeInput) (*SendRegisterCodeResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" {
		return nil, newError(ErrInvalidInput, "邮箱不能为空", nil)
	}
	if !validate.EmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if !validate.IsLoginEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	code, err := GenerateVerificationCode()
	if err != nil {
		return nil, newError(ErrInternal, "生成验证码失败", err)
	}
	if err := s.VerificationCode.SaveVerificationCode(ctx, string(mailer.VerificationPurposeRegister), email, code, verificationTTL); err != nil {
		return nil, newError(ErrDependencyUnavailable, "保存验证码失败", err)
	}
	if err := s.Mailer.SendVerificationCode(ctx, email, code, mailer.VerificationPurposeRegister); err != nil {
		slog.Error("send register verification email", "email", email, "error", err)
		return nil, newError(ErrEmailFailed, "邮件发送失败，请稍后重试", err)
	}
	if auditErr := s.audit(ctx, nil, "register_send_code", "verification_code", nil, nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit register send code", "email", email, "error", auditErr)
	}
	return &SendRegisterCodeResult{Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) VerifyRegisterCode(ctx context.Context, input VerifyRegisterCodeInput) (*VerifyRegisterCodeResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" || input.Code == "" {
		return nil, newError(ErrInvalidInput, "邮箱与验证码不能为空", nil)
	}
	if !validate.EmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if !validate.IsLoginEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}
	purpose := string(mailer.VerificationPurposeRegister)
	if err := s.verifyCode(ctx, purpose, email, input.Code); err != nil {
		return nil, err
	}
	ticket, err := generateRegisterTicket()
	if err != nil {
		return nil, newError(ErrInternal, "生成 Register-Ticket 失败", err)
	}
	if err := s.RegisterTicket.SaveRegisterTicket(ctx, ticket, email, verificationTTL); err != nil {
		// The code already matched and was consumed; without a ticket the user has
		// to restart, so make sure the spent code cannot be reused either.
		s.discardCode(ctx, purpose, email)
		return nil, newError(ErrDependencyUnavailable, "保存 Register-Ticket 失败", err)
	}
	if auditErr := s.audit(ctx, nil, "register_verify_code", "verification_code", nil, nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit register verify code", "email", email, "error", auditErr)
	}
	return &VerifyRegisterCodeResult{RegisterTicket: ticket, Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

// resolveRegistrationIdentity consumes a parked OAuth identity and enforces PRD
// §4.5's double binding.
//
// The stored oauth_state must equal the one the caller submitted. That is the
// whole point of the pair: a leaked registration_state is not enough, because the
// attacker would also need the state value the victim's browser carried through
// the redirect chain. A mismatch is reported the same way as a missing state so
// the caller cannot tell which half was wrong.
func (s Service) resolveRegistrationIdentity(
	ctx context.Context,
	registrationState string,
	oauthState string,
) (*model.Identity, error) {
	if s.OAuthRegistration == nil {
		return nil, newError(ErrInvalidInput, "第三方 OAuth 注册未启用", nil)
	}
	payload, found, err := s.OAuthRegistration.ConsumeRegistrationState(ctx, registrationState)
	if err != nil {
		// Fail-closed: falling through would create an unbound account for a
		// user who asked to register through a provider.
		return nil, newError(ErrDependencyUnavailable, "读取 registration_state 失败", err)
	}
	if !found {
		return nil, newError(ErrInvalidInput, "registration_state 无效或已过期", nil)
	}
	// A stored state must be non-empty before it is compared. Two empty strings
	// compare equal, so a payload written without one would satisfy the pairing
	// against an empty submitted value and turn the double binding off. Callers
	// currently reject that shape before reaching here and the callback never
	// stores an empty state, but neither guarantee belongs to this function, and
	// the failure mode is silent.
	if payload.OAuthState == "" || payload.ProviderID == "" || payload.Provider == "" {
		return nil, newError(ErrInvalidInput, "registration_state 内容不完整", nil)
	}
	// Constant-time comparison is unnecessary here: both values are already
	// known to the caller, and the timing of a string compare reveals nothing
	// they did not submit.
	if payload.OAuthState != oauthState {
		return nil, newError(ErrInvalidInput, "registration_state 与 oauth_state 不匹配", nil)
	}

	identity := &model.Identity{
		Provider:       payload.Provider,
		ProviderID:     payload.ProviderID,
		IdentityData:   payload.IdentityData,
		TokenExpiresAt: payload.TokenExpiresAt,
	}
	if payload.AccessToken != "" {
		identity.AccessToken = &payload.AccessToken
	}
	if payload.RefreshToken != "" {
		identity.RefreshToken = &payload.RefreshToken
	}
	return identity, nil
}

func (s Service) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	ticket := strings.TrimSpace(input.RegisterTicket)
	if ticket == "" {
		return nil, newError(ErrRegisterTicketInvalid, "Register-Ticket 不能为空", nil)
	}
	// The third-party OAuth branch needs both halves of PRD §4.5's double
	// binding. Shape is checked before the ticket is read so a malformed request
	// does not burn the one-time ticket.
	registrationState := strings.TrimSpace(input.RegistrationState)
	oauthState := strings.TrimSpace(input.OAuthState)
	if (registrationState == "") != (oauthState == "") {
		return nil, newError(ErrInvalidInput,
			"registration_state 与 oauth_state 必须同时提供", nil)
	}

	name := strings.TrimSpace(input.Name)
	studentID := strings.TrimSpace(input.StudentID)
	phone := strings.TrimSpace(input.PhoneNumber)
	qq := strings.TrimSpace(input.QQNumber)
	college := model.College(strings.TrimSpace(input.College))
	major := strings.TrimSpace(input.Major)
	password := input.Password
	if name == "" || studentID == "" || phone == "" || qq == "" || college == "" || major == "" || password == "" {
		return nil, newError(ErrInvalidInput, "注册信息不完整", nil)
	}
	if !college.Valid() {
		return nil, newError(ErrInvalidInput, "学院不在枚举范围内", nil)
	}
	if len(password) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}

	// Read the ticket first and only spend it once every rejectable condition has
	// been checked: a recoverable error such as an occupied student ID must not
	// cost the user their one-time ticket and force a new send-code round trip.
	email, found, err := s.RegisterTicket.PeekRegisterTicket(ctx, ticket)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取 Register-Ticket 失败", err)
	}
	if !found {
		return nil, newError(ErrRegisterTicketInvalid, "Register-Ticket 无效或已过期", nil)
	}
	if !validate.IsLoginEmailDomain(email) {
		return nil, &Error{Kind: KindInvalidInput, Code: errcode.CodeEmailDomainNotAllowed, Message: "邮箱域名不允许"}
	}

	exists, err := s.Users.ExistsAsEmailAnywhere(ctx, email)
	if err != nil {
		return nil, newError(ErrInternal, "查询邮箱是否已存在失败", err)
	}
	if exists {
		return nil, newError(ErrEmailAlreadyRegistered, "邮箱已被注册", nil)
	}
	exists, err = s.Users.ExistsByStudentID(ctx, studentID)
	if err != nil {
		return nil, newError(ErrInternal, "查询学号是否已存在失败", err)
	}
	if exists {
		return nil, newError(ErrStudentIDOccupied, "学号已被占用", nil)
	}

	// Throttled here rather than at the top of the function: the cap exists to
	// bound argon2id derivations, and this is the last point before the flow starts
	// spending things. Every rejection above — a short password, a bad college, an
	// occupied student ID — costs nothing to produce, so charging quota for it
	// would let a user lock themselves out by mistyping their own form. It still
	// precedes the registration_state consumption below, so a throttled call
	// spends neither one-time credential.
	//
	// The subject is the Register-Ticket, not the caller IP. The ticket is one
	// verified email address, which is what the derivation cost should be metered
	// against; an IP key would put an entire campus NAT behind a single counter.
	if err = s.checkEndpointLimit(ctx, s.RegisterLimiter, "register", "ticket:"+ticket); err != nil {
		return nil, err
	}

	// The parked OAuth identity is resolved last among the rejectable checks, so
	// an email or student-ID clash does not consume the one-time
	// registration_state. Once consumed it is gone even on a later failure: the
	// pair was presented, and leaving it live would let a leaked
	// registration_state be retried against other OAuth states.
	var oauthIdentity *model.Identity
	if registrationState != "" {
		oauthIdentity, err = s.resolveRegistrationIdentity(ctx, registrationState, oauthState)
		if err != nil {
			return nil, err
		}
	}

	passwordHash, err := s.Passwords.HashPassword(ctx, password)
	if err != nil {
		return nil, s.hashError(ctx, err)
	}

	user := &model.User{
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		College:      college,
		Name:         name,
		PhoneNumber:  phone,
		QQNumber:     qq,
		PasswordHash: passwordHash,
		StudentID:    studentID,
		LoginEmail:   email,
		Major:        major,
	}
	profile := &model.Profile{}
	client, err := s.findInternalClient(ctx)
	if err != nil {
		return nil, err
	}
	var pair *issuedPair

	// Account, profile and initial session share one PostgreSQL transaction. The
	// pair is built after INSERT assigns user.ID; any signing or token persistence
	// failure rolls the account back and leaves the Register-Ticket retryable.
	// The account, its profile, the optional third-party binding and the initial
	// session all commit together, so registering through GitHub or Lark cannot
	// leave an account whose binding failed to persist.
	if createErr := s.Users.CreateRegistrationWithIdentity(ctx, user, profile, oauthIdentity, func(created *model.User) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error) {
		issued, issueErr := s.issuePair(created, client, 0, "", sessionScopes)
		if issueErr != nil {
			return nil, nil, issueErr
		}
		pair = issued
		return issued.access, issued.refresh, nil
	}); createErr != nil {
		// A unique violation here means the pre-flight checks raced a concurrent
		// registration. The table has two unique constraints, so dispatch on the
		// constraint name: reporting "邮箱已被注册" for a student-ID clash points the
		// user at the wrong field.
		switch constraint := duplicateConstraint(createErr); constraint {
		case userStudentIDConstraint:
			return nil, newError(ErrStudentIDOccupied, "学号已被占用", createErr)
		case userLoginEmailConstraint, userLoginEmailIsIdentityConstraint:
			// The second name comes from V005: the address is already bound as
			// someone's other_mail identity. From the registrant's side that is the
			// same outcome as a taken login email, and saying more would reveal that
			// another account has it bound.
			return nil, newError(ErrEmailAlreadyRegistered, "邮箱已被注册", createErr)
		case identityProviderConstraint:
			// The OAuth callback saw this provider account unbound, but up to 15
			// minutes pass before registration completes, and someone else can
			// bind it in that window. Naming the real cause matters: the
			// registrant's own fields are all fine, and the generic conflict
			// message would send them hunting through their email and student ID.
			return nil, newError(ErrIdentityOccupied, "该第三方账号已被其他用户绑定", createErr)
		case "":
		default:
			// An unmapped unique constraint. Report a generic conflict rather than
			// guessing a field, and log the name so the mapping can be added.
			slog.ErrorContext(ctx, "unmapped unique violation on register", "constraint", constraint)
			return nil, newError(ErrConflict, "注册信息与现有账号冲突", createErr)
		}
		return nil, newError(ErrInternal, "创建用户失败", createErr)
	}

	// The account exists, so the ticket has served its purpose. A failure here
	// leaves a live ticket whose email is already registered; the next attempt is
	// rejected by the email-exists check, so it cannot create a second account.
	if consumeErr := s.RegisterTicket.ConsumeRegisterTicket(ctx, ticket); consumeErr != nil {
		slog.WarnContext(ctx, "consume register ticket after account creation", "user_id", user.ID, "error", consumeErr)
	}

	if auditErr := s.audit(ctx, &user.ID, "register", "session", nil, nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"login_email": email}); auditErr != nil {
		slog.Error("audit register", "user_id", user.ID, "error", auditErr)
	}
	// Registration is the user's first login, so the initial session registers
	// as a device exactly like a password login. Fail-open: the account and its
	// session already committed.
	if s.Devices != nil {
		evicted, err := s.Devices.RegisterDevice(ctx, user.ID, pair.familyID, input.UserAgent, input.ClientIP, s.now())
		if err != nil {
			slog.WarnContext(ctx, "register device failed", "user_id", user.ID, "error", err)
		}
		s.revokeEvictedDevice(ctx, user.ID, evicted, s.now(), input.ClientIP, input.UserAgent)
	}
	// The registration transaction inserts user, profile and any third-party
	// binding but does not reload them, so the in-memory user still has an empty
	// Profile and Identities — which would make this response disagree with a
	// Login response for the same account. Read the aggregate back.
	reloaded, reloadErr := s.Users.FindByID(ctx, user.ID)
	if reloadErr != nil {
		slog.ErrorContext(ctx, "reload registered user", "user_id", user.ID, "error", reloadErr)
		return nil, newError(ErrInternal, "读取注册结果失败", reloadErr)
	}
	return &RegisterResult{
		AccessToken:      pair.accessToken,
		RefreshToken:     pair.refreshToken,
		TokenType:        BearerTokenType,
		Scope:            pair.scopeClaim,
		AccessExpiresAt:  pair.access.ExpiresAt,
		RefreshExpiresAt: pair.refresh.ExpiresAt,
		Profile:          profileDTO(reloaded),
	}, nil
}

func (s Service) ForgotPasswordSendCode(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" {
		return nil, newError(ErrInvalidInput, "邮箱不能为空", nil)
	}
	if !validate.EmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	if s.ForgotPasswords == nil {
		return nil, newError(ErrInternal, "忘记密码任务队列未配置", nil)
	}
	accepted := s.ForgotPasswords.EnqueueForgotPassword(ForgotPasswordJob{
		Email: email, ClientIP: input.ClientIP, UserAgent: input.UserAgent,
	})
	if !accepted {
		slog.WarnContext(ctx, "forgot password request dropped", "operation", "forgot_password_send_code", "stage", "enqueue")
	}
	return &ForgotPasswordResult{Email: email, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) ResetPassword(ctx context.Context, input ResetPasswordInput) (*ResetPasswordResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" || input.Code == "" || input.Password == "" {
		return nil, newError(ErrInvalidInput, "邮箱、验证码与密码不能为空", nil)
	}
	if !validate.EmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	// Validate everything possible before consuming the one-time code, so a
	// rejected request does not force the user to request a fresh code.
	if len(input.Password) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}
	if err := s.verifyCode(ctx, string(mailer.VerificationPurposeResetPassword), email, input.Code); err != nil {
		return nil, err
	}
	user, err := s.Users.FindAuthUserByLoginIdentifier(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrUnknownIdentifier, "邮箱不存在", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询账号失败", err)
	}
	if user.State == model.UserStateDeleted {
		// A deleted account's other_mail identity can still resolve here; do not let
		// the reset flow proceed or reveal that the address ever belonged to anyone.
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}
	// Distinguish "differs from the old password" from "could not check": a
	// cancelled verification returns non-nil too, which would otherwise be read as
	// a successful difference check.
	switch sameErr := s.Passwords.VerifyPassword(ctx, input.Password, user.PasswordHash); {
	case sameErr == nil:
		return nil, newError(ErrPasswordUnchanged, "新密码不能与旧密码相同", nil)
	case ctx.Err() != nil:
		return nil, newError(ErrDependencyUnavailable, "密码比对被中断", sameErr)
	}
	passwordHash, err := s.Passwords.HashPassword(ctx, input.Password)
	if err != nil {
		return nil, s.hashError(ctx, err)
	}
	now := s.now()
	// The password rewrite and the session revocation share one transaction:
	// reporting success while live refresh tokens survive would contradict the
	// "请重新登录" contract, so a revocation failure must fail the whole call.
	entries, err := s.Users.UpdatePasswordAndRevokeSessions(ctx, user.ID, passwordHash, now)
	if err != nil {
		return nil, newError(ErrInternal, "重置密码并撤销会话失败", err)
	}
	s.deliverBlacklist(ctx, entries, now)
	s.clearLoginFailures(ctx, user, email)
	// Same device cleanup as ChangePassword: reset revokes every session, so the
	// device set must not survive it.
	if s.Devices != nil {
		if err := s.Devices.RemoveAllDevices(ctx, user.ID); err != nil {
			slog.WarnContext(ctx, "remove all devices on password reset failed", "user_id", user.ID, "error", err)
		}
	}
	if auditErr := s.audit(ctx, &user.ID, "reset_password", "session", nil, nil, true, 0, input.ClientIP, input.UserAgent, map[string]any{"email": email}); auditErr != nil {
		slog.Error("audit reset password", "user_id", user.ID, "error", auditErr)
	}
	return &ResetPasswordResult{Email: email}, nil
}

func (s Service) ChangePassword(ctx context.Context, input ChangePasswordInput) (*ChangePasswordResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if input.OldPassword == "" || input.NewPassword == "" {
		return nil, newError(ErrInvalidInput, "old_password 与 new_password 不能为空", nil)
	}
	if len(input.NewPassword) < 8 {
		return nil, newError(ErrPasswordTooShort, "密码长度不足 8 位", nil)
	}
	if input.NewPassword == input.OldPassword {
		return nil, newError(ErrPasswordUnchanged, "新密码不能与旧密码相同", nil)
	}
	user, err := s.Users.FindAuthUserByID(ctx, input.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询待修改密码的用户失败", err)
	}
	if user.State == model.UserStateDeleted {
		return nil, newError(ErrUserDeleted, "用户已注销", nil)
	}
	if verifyErr := s.Passwords.VerifyPassword(ctx, input.OldPassword, user.PasswordHash); verifyErr != nil {
		// An abandoned verification is not a wrong password: auditing it as one
		// would fill the log with phantom failures for clients that disconnected.
		if ctx.Err() != nil {
			return nil, newError(ErrDependencyUnavailable, "密码校验被中断", verifyErr)
		}
		if auditErr := s.audit(ctx, &user.ID, "change_password", "session", nil, nullableString(s.actorClientID(input.ActorClientID)), false, errcode.CodePasswordInvalid, input.ClientIP, input.UserAgent, nil); auditErr != nil {
			slog.Error("audit change password failure", "user_id", user.ID, "error", auditErr)
		}
		return nil, newError(ErrPasswordInvalid, "旧密码错误", verifyErr)
	}
	passwordHash, err := s.Passwords.HashPassword(ctx, input.NewPassword)
	if err != nil {
		return nil, s.hashError(ctx, err)
	}
	now := s.now()
	entries, err := s.Users.UpdatePasswordAndRevokeSessions(ctx, user.ID, passwordHash, now)
	if err != nil {
		return nil, newError(ErrInternal, "修改密码并撤销会话失败", err)
	}
	s.deliverBlacklist(ctx, entries, now)
	s.clearLoginFailures(ctx, user, user.LoginEmail)
	// Every session of the user was just revoked, so the device set must die
	// with it (PRD §6.1: 设备记录清除). Fail-open: the revocation is durable in
	// PostgreSQL and a leftover device record cannot authenticate anything.
	if s.Devices != nil {
		if err := s.Devices.RemoveAllDevices(ctx, user.ID); err != nil {
			slog.WarnContext(ctx, "remove all devices on password change failed", "user_id", user.ID, "error", err)
		}
	}
	if auditErr := s.audit(ctx, &user.ID, "change_password", "session", nil, nullableString(s.actorClientID(input.ActorClientID)), true, 0, input.ClientIP, input.UserAgent, nil); auditErr != nil {
		slog.Error("audit change password", "user_id", user.ID, "error", auditErr)
	}
	return &ChangePasswordResult{UserID: user.ID}, nil
}

func (s Service) BindEmailSendCode(ctx context.Context, input BindEmailSendCodeInput) (*BindEmailSendCodeResult, error) {
	email := normalizeIdentifier(input.Email)
	if email == "" {
		return nil, newError(ErrInvalidInput, "邮箱不能为空", nil)
	}
	if !validate.EmailFormat(email) {
		return nil, newError(ErrInvalidInput, "邮箱格式不正确", nil)
	}
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	if err := s.checkEmailLimit(ctx, email, input.ClientIP); err != nil {
		return nil, err
	}
	if _, findErr := s.Identities.FindByProviderID(ctx, model.LoginMethodOtherMail, email); findErr == nil {
		// The conflict response must not reveal who owns the address: a distinct
		// "already bound to you" error lets any authenticated caller enumerate
		// other users' bindings. Every occupied email gets the same reply; the
		// caller refreshes their own binding list through GET /user/profile.
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
	} else if !errors.Is(findErr, repository.ErrNotFound) {
		return nil, newError(ErrInternal, "查询第三方绑定记录失败", findErr)
	}
	if emailExists, err := s.Users.ExistsAsEmailAnywhere(ctx, email); err != nil {
		return nil, newError(ErrInternal, "查询邮箱是否已存在失败", err)
	} else if emailExists {
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
	}
	count, err := s.Identities.CountByUserAndProvider(ctx, input.UserID, model.LoginMethodOtherMail)
	if err != nil {
		return nil, newError(ErrInternal, "统计第三方绑定数量失败", err)
	}
	if count >= maxOtherMailBindings {
		return nil, newError(ErrIdentityLimitReached, "第三方邮箱绑定数量已达上限", nil)
	}
	code, err := GenerateVerificationCode()
	if err != nil {
		return nil, newError(ErrInternal, "生成验证码失败", err)
	}
	if saveErr := s.VerificationCode.SaveVerificationCode(ctx, string(mailer.VerificationPurposeBindEmail), email, code, verificationTTL); saveErr != nil {
		return nil, newError(ErrDependencyUnavailable, "保存验证码失败", saveErr)
	}
	ticket, err := generateBindTicket()
	if err != nil {
		return nil, newError(ErrInternal, "生成 Bind-Ticket 失败", err)
	}
	if err := s.BindTicket.SaveBindTicket(ctx, ticket, BindTicketPayload{Email: email, UserID: input.UserID}, verificationTTL); err != nil {
		return nil, newError(ErrInternal, "保存 Bind-Ticket 失败", err)
	}
	if err := s.Mailer.SendVerificationCode(ctx, email, code, mailer.VerificationPurposeBindEmail); err != nil {
		slog.Error("send bind email verification", "email", email, "error", err)
		return nil, newError(ErrEmailFailed, "邮件发送失败，请稍后重试", err)
	}
	if auditErr := s.audit(ctx, &input.UserID, "bind_email_send_code", "verification_code", nil, nullableString(s.actorClientID(input.ActorClientID)), true, 0, input.ClientIP, input.UserAgent, map[string]any{"email": email}); auditErr != nil {
		slog.Error("audit bind email send code", "email", email, "error", auditErr)
	}
	return &BindEmailSendCodeResult{BindTicket: ticket, ExpiresIn: int(verificationTTL.Seconds())}, nil
}

func (s Service) BindEmailVerify(ctx context.Context, input BindEmailVerifyInput) (*BindEmailVerifyResult, error) {
	if input.UserID <= 0 {
		return nil, newError(ErrInvalidToken, "身份主体无效", nil)
	}
	ticket := strings.TrimSpace(input.BindTicket)
	if ticket == "" || input.Code == "" {
		return nil, newError(ErrInvalidInput, "bind_ticket 与 code 不能为空", nil)
	}
	// Read the ticket without consuming it: a wrong verification code must not
	// cost the user their Bind-Ticket, or every typo forces a fresh send-code
	// round trip. The ticket is consumed only once the binding is about to happen.
	payload, found, err := s.BindTicket.PeekBindTicket(ctx, ticket)
	if err != nil {
		return nil, newError(ErrDependencyUnavailable, "读取 Bind-Ticket 失败", err)
	}
	if !found {
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 无效或已过期", nil)
	}
	if payload.UserID != input.UserID {
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 不属于当前用户", nil)
	}
	purpose := string(mailer.VerificationPurposeBindEmail)
	if verifyErr := s.verifyCode(ctx, purpose, payload.Email, input.Code); verifyErr != nil {
		return nil, verifyErr
	}
	// The code matched, so the ticket has served its purpose. Consuming it here
	// also serializes concurrent requests replaying the same ticket: only the
	// caller that removes the key proceeds to insert the identity.
	consumed, err := s.BindTicket.ConsumeBindTicket(ctx, ticket)
	if err != nil {
		s.discardCode(ctx, purpose, payload.Email)
		return nil, newError(ErrDependencyUnavailable, "消费 Bind-Ticket 失败", err)
	}
	if !consumed {
		s.discardCode(ctx, purpose, payload.Email)
		return nil, newError(ErrBindTicketInvalid, "Bind-Ticket 无效或已过期", nil)
	}
	if _, findErr := s.Identities.FindByProviderID(ctx, model.LoginMethodOtherMail, payload.Email); findErr == nil {
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
	} else if !errors.Is(findErr, repository.ErrNotFound) {
		return nil, newError(ErrInternal, "查询第三方绑定记录失败", findErr)
	}
	if emailExists, err := s.Users.ExistsAsEmailAnywhere(ctx, payload.Email); err != nil {
		return nil, newError(ErrInternal, "查询邮箱是否已存在失败", err)
	} else if emailExists {
		return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", nil)
	}
	identity := &model.Identity{
		UserID:     input.UserID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: payload.Email,
	}
	if err := s.Identities.CreateWithinLimit(ctx, identity, maxOtherMailBindings); err != nil {
		if errors.Is(err, repository.ErrLimitExceeded) {
			return nil, newError(ErrIdentityLimitReached, "第三方邮箱绑定数量已达上限", nil)
		}
		// Covers both the identities unique index and the V005 trigger that rejects
		// an address already serving as somebody's login email. The reply stays
		// deliberately vague about which one it was, and about who holds it.
		if isDuplicateError(err) {
			return nil, newError(ErrIdentityOccupied, "该邮箱已被绑定或占用", err)
		}
		return nil, newError(ErrInternal, "创建第三方绑定记录失败", err)
	}
	if auditErr := s.audit(ctx, &input.UserID, "oauth_bind", "identity", nil, nullableString(s.actorClientID(input.ActorClientID)), true, 0, input.ClientIP, input.UserAgent, map[string]any{"provider": string(model.LoginMethodOtherMail), "provider_id": payload.Email}); auditErr != nil {
		slog.Error("audit bind email", "user_id", input.UserID, "error", auditErr)
	}
	return &BindEmailVerifyResult{
		Email:    payload.Email,
		Identity: identityDTO(*identity),
	}, nil
}

// checkEndpointLimit throttles one endpoint against one subject. The limiter is a
// parameter because each endpoint carries its own quota on its own instance; the
// endpoint name only scopes the Redis key.
func (s Service) checkEndpointLimit(ctx context.Context, limiter EndpointLimiter, endpoint, subject string) error {
	// An empty subject (a request without a usable client IP) has nothing to key
	// the window on; the Redis limiter rejects it, which this helper would
	// otherwise read as "limiter unavailable" and log a WARN per request.
	if limiter == nil || strings.TrimSpace(subject) == "" {
		return nil
	}
	result, err := limiter.Allow(ctx, endpoint, subject)
	if err != nil {
		// Redis-backed throttling has no durable fallback. Rejecting every
		// request would take the endpoint down entirely, so allow the call and
		// rely on argon2id cost plus alerting during the outage.
		slog.WarnContext(ctx, "endpoint limiter unavailable, allowing request", "endpoint", endpoint, "error", err)
		return nil
	}
	if !result.Allowed {
		return withRetryAfter(newError(ErrRateLimited, "请求过于频繁", nil), result.RetryAfter)
	}
	return nil
}

// checkEmailLimit throttles verification-code sending on two independent
// dimensions: the target email (stops repeated mail to one inbox) and the
// caller IP (stops one attacker fanning out across many addresses to drain
// SMTP quota). Limiter outages fail open per the Redis degradation policy
// (PRD §6.0): the flow still fails closed at the Redis code store when Redis
// is fully down, so degradation only matters for transient limiter errors.
func (s Service) checkEmailLimit(ctx context.Context, email, clientIP string) error {
	if s.EmailLimiter != nil {
		result, err := s.EmailLimiter.Allow(ctx, "send_email", "email:"+email)
		switch {
		case err != nil:
			slog.WarnContext(ctx, "email limiter unavailable, allowing request", "error", err)
		case !result.Allowed:
			return withRetryAfter(newError(ErrRateLimited, "请求过于频繁", nil), result.RetryAfter)
		}
	}
	if s.EmailIPLimiter != nil && strings.TrimSpace(clientIP) != "" {
		result, err := s.EmailIPLimiter.Allow(ctx, "send_email", "ip:"+strings.TrimSpace(clientIP))
		switch {
		case err != nil:
			slog.WarnContext(ctx, "email ip limiter unavailable, allowing request", "error", err)
		case !result.Allowed:
			return withRetryAfter(newError(ErrRateLimited, "请求过于频繁", nil), result.RetryAfter)
		}
	}
	return nil
}

func (s Service) deliverBlacklist(ctx context.Context, entries []model.BlacklistEntry, now time.Time) {
	if s.Blacklist == nil {
		return
	}
	jtis := make([]string, 0, len(entries))
	for _, entry := range entries {
		// The auth-state cache entry must be deleted so the middleware cannot
		// serve a stale non-revoked state for a token the DB now says revoked.
		if entry.ExpiresAt.Sub(now) <= 0 || strings.TrimSpace(entry.TokenID) == "" {
			continue
		}
		jtis = append(jtis, entry.TokenID)
	}
	if len(jtis) == 0 {
		return
	}
	if err := s.Blacklist.DeleteAuthStates(ctx, jtis); err != nil {
		// The same-transaction outbox row guarantees a worker retry, so a
		// failed synchronous delivery is expected degradation, not an error.
		slog.WarnContext(ctx, "deliver auth-state invalidation, outbox worker will retry", "count", len(jtis), "error", err)
	}
}

// verifyCode checks a submitted email code. The store keeps the code alive
// through a bounded number of wrong guesses, so a mistyped digit no longer burns
// it — a wrong guess used to delete the valid code, which let anyone who knew an
// address invalidate its code at will. Once the budget is spent the store drops
// the code and the caller sees the expired outcome.
func (s Service) verifyCode(ctx context.Context, purpose, email, code string) error {
	matched, remaining, err := s.VerificationCode.VerifyVerificationCode(ctx, purpose, email, code)
	if err != nil {
		return newError(ErrDependencyUnavailable, "校验验证码失败", err)
	}
	if matched {
		return nil
	}
	if remaining <= 0 {
		return newError(ErrVerificationCodeExpired, "验证码已过期或不存在", nil)
	}
	return newError(ErrVerificationCodeWrong, "验证码错误", nil)
}

// hashError classifies a password-derivation failure. Hashing queues behind a
// concurrency gate, so a cancelled caller gets ctx.Err() rather than a genuine
// fault; reporting that as a 500 would blame the server for a client that left.
func (s Service) hashError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return newError(ErrDependencyUnavailable, "密码哈希计算被中断", err)
	}
	return newError(ErrInternal, "计算密码哈希失败", err)
}

// discardCode drops an already-matched code when a later step of the same flow
// fails, so the spent code cannot be replayed by a retry.
func (s Service) discardCode(ctx context.Context, purpose, email string) {
	if err := s.VerificationCode.DiscardVerificationCode(ctx, purpose, email); err != nil {
		slog.WarnContext(ctx, "discard consumed verification code", "purpose", purpose, "error", err)
	}
}

// clearLoginFailures releases the lockout after a successful password reset or
// change. Login records failures under "user:<id>" once the account is known and
// under "identifier:<email>" before that, so both keys must be cleared or a
// locked-out user stays locked for the rest of the window — defeating the very
// recovery path they just completed. Failures are logged, not returned: the
// password is already changed, and a stale counter expires on its own.
func (s Service) clearLoginFailures(ctx context.Context, user *model.User, email string) {
	if s.Failures == nil || user == nil {
		return
	}
	keys := []string{loginFailureKey(user, email)}
	if identifier := normalizeIdentifier(email); identifier != "" {
		keys = append(keys, "identifier:"+identifier)
	}
	for _, key := range keys {
		if err := s.Failures.Reset(ctx, key); err != nil {
			slog.WarnContext(ctx, "reset login failures after password update", "key", key, "error", err)
		}
	}
}

func (s Service) checkLoginLock(ctx context.Context, key string) error {
	if s.Failures == nil {
		return nil
	}
	locked, retryAfter, err := s.Failures.IsLocked(ctx, key)
	if err != nil {
		slog.WarnContext(ctx, "login lockout state unavailable, allowing attempt", "error", err)
		return nil
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "登录已被锁定", nil), retryAfter)
	}
	return nil
}

func (s Service) failLogin(ctx context.Context, user *model.User, input LoginInput, failureKey string, sentinel *Error, message string, cause error) error {
	locked := false
	lockTTL := time.Duration(0)
	if s.Failures != nil {
		result, err := s.Failures.RecordFailure(ctx, failureKey)
		if err != nil {
			// Losing a counter increment must not mask the real rejection
			// reason with a 500; report the original failure instead.
			slog.WarnContext(ctx, "record login failure unavailable", "error", err)
		} else {
			locked = result.Locked
			lockTTL = result.TTL
		}
	}
	if err := s.audit(ctx, loginUserID(user), "login", "session", nil, nil, false, sentinel.Code, input.ClientIP, input.UserAgent, map[string]any{"method": loginMethod(user, input.Identifier)}); err != nil {
		slog.Error("audit login failure", "error", err)
	}
	if locked {
		return withRetryAfter(newError(ErrLocked, "登录已被锁定", nil), lockTTL)
	}
	return newError(sentinel, message, cause)
}

// Refresh audit outcomes. These name why a rotation ended, which the action and
// error code alone cannot: every failure carries the same invalid-token code, and
// only some of them mean an attack.
const (
	// refreshOutcomeRotated is a successful rotation.
	refreshOutcomeRotated = "rotated"
	// refreshOutcomeReplayed is a presented token that was already revoked or
	// rotated. This is the replay defense firing, and it revoked the whole
	// family — the one outcome here that needs to be searchable on its own.
	refreshOutcomeReplayed = "refresh_replayed"
	// refreshOutcomeConcurrent is a presented token already rotated by a sibling
	// request within the 30s grace window. The family is preserved, so this is a
	// benign multi-tab cold-start, not a replay — audited separately with the
	// concurrent-refresh code so reviewers are not misled into treating routine
	// tab races as replay attacks.
	refreshOutcomeConcurrent = "concurrent_refresh"
	// refreshOutcomeExpired is a token that aged out. Benign on its own, but it
	// has to be in the log for refresh_replayed to be meaningful: without the
	// mundane outcomes recorded, a replay row cannot be told apart from the
	// failures nobody wrote down.
	refreshOutcomeExpired = "expired"
	// refreshOutcomeClientMismatch is a token presented against a client other
	// than the one it was issued to. Not reachable through the first-party flow,
	// so it means either a misrouted client or a token being probed.
	refreshOutcomeClientMismatch = "client_mismatch"
)

// auditRefresh records a refresh rotation outcome. Failures mean the token
// family was revoked as a replay defense, so they carry the invalid-token code;
// the audit itself is fail-open like every other audit call in this service.
//
// The outcome is recorded because the action and error code alone do not say why
// a rotation failed: every failed row carries the same invalid-token code, and
// the name is what separates a replay — a leaked token, family cut in response —
// from an ordinary rejection. True replays share the oauth service's
// refresh_replayed name and the benign in-grace variant shares concurrent_refresh,
// so a reviewer can filter both token paths with one query.
func (s Service) auditRefresh(
	ctx context.Context,
	userID int64,
	familyID *string,
	success bool,
	outcome string,
	input RefreshInput,
) {
	errCode := 0
	if !success {
		errCode = errcode.CodeAccessTokenInvalid
		if outcome == refreshOutcomeConcurrent {
			// A benign concurrent refresh keeps the family; the audit code should
			// match the 40108 the client actually sees, not the replay code.
			errCode = errcode.CodeConcurrentRefresh
		}
	}
	detail := map[string]any{"outcome": outcome}
	if auditErr := s.audit(ctx, &userID, "refresh", "session", familyID, nil, success, errCode, input.ClientIP, input.UserAgent, detail); auditErr != nil {
		slog.Error("audit refresh", "family_id", familyID, "outcome", outcome, "error", auditErr)
	}
}

func (s Service) findInternalClient(ctx context.Context) (*model.OAuthClient, error) {
	clientID := strings.TrimSpace(s.InternalClientID)
	if clientID == "" || s.Clients == nil {
		return nil, newError(ErrInternal, "内置 OAuth 客户端未配置", nil)
	}
	// The internal client is immutable and startup-validated, so the repository
	// serves it from a process-local cache after the first load — no DB round trip
	// per login/refresh.
	client, err := s.Clients.FindActiveInternalClient(ctx, clientID)
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
		return nil, newError(ErrInternal, "内置 OAuth 客户端不可用", err)
	}
	if err != nil {
		return nil, newError(ErrInternal, "查询内置 OAuth 客户端失败", err)
	}
	if client.ClientType != model.ClientTypeFirstParty || client.ClientSecretHash != nil {
		return nil, newError(ErrInternal, "内置 OAuth 客户端不是公开的第一方客户端", nil)
	}
	if ok, err := scope.Equal([]string(client.Scopes), sessionScopes); err != nil || !ok {
		return nil, newError(ErrInternal, "内置 OAuth 客户端的 scope 必须是标准会话 scope", err)
	}
	return client, nil
}
