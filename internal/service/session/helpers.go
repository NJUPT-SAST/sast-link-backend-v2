package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

type issuedPair struct {
	accessToken  string
	refreshToken string
	scopeClaim   string
	familyID     string
	access       *model.OAuthAccessToken
	refresh      *model.OAuthRefreshToken
}

func (s Service) issuePair(user *model.User, client *model.OAuthClient, sequence int, familyID string, requestedScopes []string) (*issuedPair, error) {
	if user == nil || client == nil || s.JWT == nil || s.RefreshTokens == nil || s.Tokens == nil {
		return nil, newError(ErrInternal, "会话服务依赖未配置", nil)
	}
	now := s.now()
	accessTTL := s.AccessTTL
	if accessTTL <= 0 {
		accessTTL = defaultAccessTTL
	}
	refreshTTL := s.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}
	scopes, err := scope.Normalize(requestedScopes)
	if err != nil {
		return nil, newError(ErrInternal, "规范化 Token scope 失败", err)
	}
	scopeClaim, err := scope.Claim(scopes)
	if err != nil {
		return nil, newError(ErrInternal, "编码会话 scope 失败", err)
	}
	if familyID == "" {
		familyID = uuid.NewString()
	}
	jti := uuid.NewString()
	accessToken, err := s.JWT.SignAccessToken(auth.TokenInput{
		Subject:      strconv.FormatInt(user.ID, 10),
		JTI:          jti,
		Role:         string(user.Role),
		State:        string(user.State),
		TokenVersion: user.TokenVersion,
		Scopes:       scopes,
		TTL:          accessTTL,
		NotBefore:    now,
	})
	if err != nil {
		return nil, newError(ErrInternal, "签发 Access Token 失败", err)
	}
	refreshToken, err := s.RefreshTokens.NewRefreshToken()
	if err != nil {
		return nil, newError(ErrInternal, "创建 Refresh Token 失败", err)
	}
	refreshHash, err := s.RefreshTokens.HashRefreshToken(refreshToken)
	if err != nil {
		return nil, newError(ErrInternal, "计算 Refresh Token 哈希失败", err)
	}
	access := &model.OAuthAccessToken{
		TokenID:   jti,
		ClientID:  client.ID,
		UserID:    user.ID,
		FamilyID:  &familyID,
		Scopes:    model.StringArray(scopes),
		ExpiresAt: now.Add(accessTTL).UTC(),
		CreatedAt: now.UTC(),
	}
	refresh := &model.OAuthRefreshToken{
		TokenHash: refreshHash,
		FamilyID:  familyID,
		Sequence:  sequence,
		ClientID:  client.ID,
		UserID:    user.ID,
		Scopes:    model.StringArray(scopes),
		ExpiresAt: now.Add(refreshTTL).UTC(),
		CreatedAt: now.UTC(),
	}
	return &issuedPair{
		accessToken:  accessToken,
		refreshToken: refreshToken,
		scopeClaim:   scopeClaim,
		familyID:     familyID,
		access:       access,
		refresh:      refresh,
	}, nil
}

func (s Service) now() time.Time {
	clock := s.Clock
	if clock == nil {
		clock = auth.SystemClock
	}
	return clock.Now().UTC()
}

func normalizeIdentifier(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
}

func isAllowedEmailDomain(email string) bool {
	return strings.HasSuffix(email, "@njupt.edu.cn") || strings.HasSuffix(email, "@sast.fun")
}

// validEmailFormat is the input-layer guard against SMTP header injection and
// key/audit corruption. It rejects control characters (notably CR/LF, which
// the go-playground "email" validator lets through), address separators and
// display-name brackets, and requires exactly one @. This is defense in depth
// ahead of the mailer's own mail.ParseAddress check; it also keeps Redis keys
// and audit detail free of unprintable bytes.
//
// Whitespace is rejected everywhere, not just at the ends. An address is used as
// a Redis key segment and a rate-limit subject before the mailer ever sees it, so
// letting whitespace through means "a b@x" and "ab@x" occupy different buckets
// while naming the same mailbox. A bare `r < 0x20` test misses this: U+0020 sits
// just outside it, and NBSP, U+3000, U+200B and U+2028 are far above it. Those
// four also survive mail.ParseAddress, so the request would travel all the way to
// SMTP before failing — surfacing a 50001 delivery error for what is really
// malformed input.
// Invisible codepoints that unicode.IsSpace does not classify as space. Named
// rather than written as literals so they stay reviewable in source.
const (
	zeroWidthSpace     = '\u200b'
	zeroWidthNonJoiner = '\u200c'
	zeroWidthJoiner    = '\u200d'
	byteOrderMark      = '\ufeff'
)

func validEmailFormat(email string) bool {
	if email == "" || strings.Count(email, "@") != 1 {
		return false
	}
	if strings.ContainsAny(email, ",<>") {
		return false
	}
	for _, symbol := range email {
		if symbol < 0x20 || symbol == 0x7f {
			return false
		}
		// unicode.IsSpace covers ASCII space, NBSP, U+2028/U+2029 and the U+2000
		// block; the zero-width and BOM codepoints are invisible rather than space
		// by Unicode's definition, so they need naming.
		switch symbol {
		case zeroWidthSpace, zeroWidthNonJoiner, zeroWidthJoiner, byteOrderMark:
			return false
		}
		if unicode.IsSpace(symbol) {
			return false
		}
	}
	return true
}

func generateVerificationCode() (string, error) {
	// Six-digit numeric code.
	const max = 1_000_000
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func generateRegisterTicket() (string, error) {
	const prefix = "reg_"
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(bytes[:]), nil
}

func generateBindTicket() (string, error) {
	const prefix = "be_"
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(bytes[:]), nil
}

// PostgreSQL's default unique-index names for the "user" table. The table
// carries two unique constraints, so a bare SQLSTATE 23505 check cannot tell
// which column collided — reporting "邮箱已被注册" for a student-ID clash sends the
// user looking at the wrong field.
const (
	userLoginEmailConstraint = "user_login_email_key"
	userStudentIDConstraint  = "user_student_id_key"
	// V005 raises these from triggers, using unique_violation so they arrive here
	// like any other duplicate. They fire when a login email and an other_mail
	// identity would end up holding the same address.
	userLoginEmailIsIdentityConstraint = "ck_user_login_email_not_identity"
	identityIsLoginEmailConstraint     = "ck_identities_provider_id_not_login_email"
)

func isDuplicateError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation
}

// duplicateConstraint returns the violated unique constraint's name, or "" when
// err is not a unique violation. PostgreSQL leaves ColumnName empty for index
// violations, so the constraint name is the only reliable discriminator.
func duplicateConstraint(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != pgerrcode.UniqueViolation {
		return ""
	}
	return pgErr.ConstraintName
}

func loginLimitSubject(input LoginInput, identifier string) string {
	if strings.TrimSpace(input.ClientIP) != "" {
		return strings.TrimSpace(input.ClientIP)
	}
	return identifier
}

func loginFailureKey(user *model.User, identifier string) string {
	if user == nil {
		return "identifier:" + normalizeIdentifier(identifier)
	}
	return "user:" + strconv.FormatInt(user.ID, 10)
}

func loginUserID(user *model.User) *int64 {
	if user == nil {
		return nil
	}
	id := user.ID
	return &id
}

func loginMethod(user *model.User, identifier string) string {
	if user != nil && normalizeIdentifier(user.LoginEmail) != identifier {
		return "other_mail"
	}
	return "password"
}

func profileDTO(user *model.User) UserProfileDTO {
	dto := UserProfileDTO{
		ID:          user.ID,
		Name:        user.Name,
		LoginEmail:  user.LoginEmail,
		Role:        string(user.Role),
		State:       string(user.State),
		EmailType:   string(user.EmailType),
		PhoneNumber: user.PhoneNumber,
		QQNumber:    user.QQNumber,
		StudentID:   user.StudentID,
		College:     string(user.College),
		Major:       user.Major,
		Identities:  make([]IdentityDTO, 0, len(user.Identities)),
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
	if user.Profile != nil {
		dto.Profile = &ProfileDetailDTO{
			Nickname:  user.Profile.Nickname,
			Intro:     user.Profile.Intro,
			Email:     user.Profile.Email,
			Avatar:    user.Profile.Avatar,
			BlogURL:   user.Profile.BlogURL,
			GitHubURL: user.Profile.GitHubURL,
			CreatedAt: user.Profile.CreatedAt,
			UpdatedAt: user.Profile.UpdatedAt,
		}
		if user.Profile.Department != nil {
			department := string(*user.Profile.Department)
			dto.Profile.Department = &department
		}
	}
	for _, identity := range user.Identities {
		dto.Identities = append(dto.Identities, IdentityDTO{
			ID:             identity.ID,
			Provider:       string(identity.Provider),
			ProviderID:     identity.ProviderID,
			IdentityData:   identity.IdentityData,
			TokenExpiresAt: identity.TokenExpiresAt,
			CreatedAt:      identity.CreatedAt,
			UpdatedAt:      identity.UpdatedAt,
		})
	}
	return dto
}

func (s Service) audit(ctx context.Context, userID *int64, action, resource string, resourceID *string, success bool, errCode int, clientIP, userAgent string, detail map[string]any) error {
	if s.Audit == nil {
		return nil
	}
	var detailValue model.JSONB
	if detail != nil {
		encoded, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("marshal audit detail: %w", err)
		}
		detailValue = model.JSONB(encoded)
	}
	var errCodePtr *int
	if errCode != 0 {
		errCodePtr = &errCode
	}
	var clientIPPtr *string
	if strings.TrimSpace(clientIP) != "" {
		clientIPPtr = &clientIP
	}
	var userAgentPtr *string
	if strings.TrimSpace(userAgent) != "" {
		userAgentPtr = &userAgent
	}
	successPtr := success
	return s.Audit.Create(ctx, &model.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Detail:     detailValue,
		ClientIP:   clientIPPtr,
		UserAgent:  userAgentPtr,
		Success:    &successPtr,
		ErrCode:    errCodePtr,
		CreatedAt:  s.now(),
	})
}
