package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/tokenissue"
)

type issuedPair struct {
	accessToken  string
	refreshToken string
	scopeClaim   string
	familyID     string
	access       *model.OAuthAccessToken
	refresh      *model.OAuthRefreshToken
}

// issuePair signs a session token pair through the shared issuer.
//
// The issuer is shared with the OAuth token endpoint so both paths produce
// identical token metadata. Errors are translated to session errors here, since
// every failure at this layer is a server-side signing or configuration fault
// rather than anything the caller submitted.
func (s Service) issuePair(user *model.User, client *model.OAuthClient, sequence int, familyID string, requestedScopes []string) (*issuedPair, error) {
	if user == nil || client == nil || s.JWT == nil || s.RefreshTokens == nil || s.Tokens == nil {
		return nil, newError(ErrInternal, "会话服务依赖未配置", nil)
	}
	accessTTL := s.AccessTTL
	if accessTTL <= 0 {
		accessTTL = defaultAccessTTL
	}
	refreshTTL := s.RefreshTTL
	if refreshTTL <= 0 {
		refreshTTL = defaultRefreshTTL
	}
	issuer := tokenissue.Issuer{JWT: s.JWT, Refresh: s.RefreshTokens, Clock: s.Clock}
	pair, err := issuer.Issue(tokenissue.Request{
		User:       user,
		Client:     client,
		Sequence:   sequence,
		FamilyID:   familyID,
		Scopes:     requestedScopes,
		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	})
	if err != nil {
		return nil, newError(ErrInternal, "签发会话 Token Pair 失败", err)
	}
	return &issuedPair{
		accessToken:  pair.AccessToken,
		refreshToken: pair.RefreshToken,
		scopeClaim:   pair.ScopeClaim,
		familyID:     pair.FamilyID,
		access:       pair.Access,
		refresh:      pair.Refresh,
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

// validHTTPURL reports whether value is an absolute http/https URL with a host.
//
// The scheme allowlist is the point: blog_url and github_url are rendered as
// links on the public card, so accepting an arbitrary URL would let a user store
// javascript: or data: and turn every viewer of their card into a target. A
// relative or scheme-less value is rejected too, since it would resolve against
// whichever site embeds the card.
func validHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return false
	}
	if parsed.Host == "" {
		return false
	}
	for _, symbol := range value {
		if symbol < 0x20 || symbol == 0x7f || unicode.IsSpace(symbol) {
			return false
		}
	}
	return true
}

func GenerateVerificationCode() (string, error) {
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
		dto.Identities = append(dto.Identities, identityDTO(identity))
	}
	return dto
}

func identityDTO(identity model.Identity) IdentityDTO {
	return IdentityDTO{
		ID:             identity.ID,
		Provider:       string(identity.Provider),
		ProviderID:     identity.ProviderID,
		IdentityData:   identity.IdentityData,
		TokenExpiresAt: identity.TokenExpiresAt,
		CreatedAt:      identity.CreatedAt,
		UpdatedAt:      identity.UpdatedAt,
	}
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
