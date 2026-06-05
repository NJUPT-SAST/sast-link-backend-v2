package service

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/pbkdf2"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/dto"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const (
	registerTicketPrefix = "sastlink:auth:register_ticket:"
	registerTicketTTL    = 5 * time.Minute
	registerTicketLen    = 32
)

// RegisterService handles user registration.
type RegisterService struct {
	userRepo    repository.UserRepository
	profileRepo repository.ProfileRepository
	emailSvc    *EmailService
	captchaSvc  *CaptchaService
	rdb         *redis.Client
}

// NewRegisterService creates a new RegisterService.
func NewRegisterService(
	userRepo repository.UserRepository,
	profileRepo repository.ProfileRepository,
	emailSvc *EmailService,
	captchaSvc *CaptchaService,
	rdb *redis.Client,
) *RegisterService {
	return &RegisterService{
		userRepo:    userRepo,
		profileRepo: profileRepo,
		emailSvc:    emailSvc,
		captchaSvc:  captchaSvc,
		rdb:         rdb,
	}
}

// SendVerificationCode validates the email domain and sends a verification code.
func (s *RegisterService) SendVerificationCode(ctx context.Context, email string) error {
	email = strings.ToLower(email)
	if !isAllowedEmailDomain(email) {
		return domain.NewError(domain.ErrEmailDomainNotAllowed,
			"邮箱域名不允许（仅限 @njupt.edu.cn / @sast.fun）")
	}

	code, err := s.captchaSvc.Generate(ctx, email)
	if err != nil {
		return fmt.Errorf("send verification code: %w", err)
	}

	if err := s.emailSvc.SendVerificationCode(email, code); err != nil {
		return fmt.Errorf("send verification code: %w", err)
	}

	return nil
}

// VerifyCode validates the captcha and returns a Register-Ticket.
func (s *RegisterService) VerifyCode(ctx context.Context, email, code string) (string, error) {
	email = strings.ToLower(email)
	if !isAllowedEmailDomain(email) {
		return "", domain.NewError(domain.ErrEmailDomainNotAllowed,
			"邮箱域名不允许（仅限 @njupt.edu.cn / @sast.fun）")
	}

	ok, err := s.captchaSvc.Verify(ctx, email, code)
	if err != nil {
		return "", fmt.Errorf("verify code: %w", err)
	}
	if !ok {
		return "", domain.NewError(domain.ErrCaptchaInvalid, "验证码错误或已过期")
	}

	ticket, err := generateRegisterTicket()
	if err != nil {
		return "", fmt.Errorf("verify code: %w", err)
	}

	key := registerTicketPrefix + ticket
	if err := s.rdb.Set(ctx, key, email, registerTicketTTL).Err(); err != nil {
		return "", fmt.Errorf("verify code: store ticket: %w", err)
	}

	return ticket, nil
}

// Register completes registration using a Register-Ticket.
func (s *RegisterService) Register(ctx context.Context, req *dto.RegisterRequest) (*domain.User, error) {
	// Atomically fetch and delete the register ticket to prevent replay.
	key := registerTicketPrefix + req.RegisterTicket
	email, err := s.rdb.GetDel(ctx, key).Result()
	if err == redis.Nil {
		return nil, domain.NewError(domain.ErrRegisterTicketInvalid, "Register-Ticket 无效或已过期")
	}
	if err != nil {
		return nil, fmt.Errorf("register: get ticket: %w", err)
	}

	// TODO: Handle RegistrationState + OAuthState for OAuth registration binding.
	// When both are provided: GetDel RegistrationState from Redis → verify OAuthState
	// matches the stored oauth_state → create identities binding.
	// See PRD §4.3 and §4.5 for the full flow.

	emailType, err := resolveEmailType(email)
	if err != nil {
		return nil, err
	}

	// Check email not already registered
	existing, err := s.userRepo.FindByLoginEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("register: check email: %w", err)
	}
	if existing != nil {
		return nil, domain.NewError(domain.ErrEmailAlreadyRegistered, "邮箱已被注册")
	}

	// Validate password
	if len(req.Password) < 8 {
		return nil, domain.NewError(domain.ErrPasswordTooShort, "密码长度不足（最短 8 位）")
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	college := domain.College(req.College)
	if !isValidCollege(college) {
		college = domain.CollegeOther
	}

	user := &domain.User{
		Role:         domain.UserRoleFreshman,
		Name:         req.Name,
		Phone:        req.PhoneNumber,
		QQNumber:     req.QQNumber,
		Password:     hash,
		TokenVersion: 0,
		StudentID:    req.StudentID,
		State:        domain.UserStateNJUPter,
		EmailType:    emailType,
		LoginEmail:   email,
		College:      college,
		Major:        req.Major,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("register: create user: %w", err)
	}

	profile := &domain.Profile{
		UserID:   user.ID,
		Nickname: req.Name,
		Email:    email,
	}

	if err := s.profileRepo.Create(ctx, profile); err != nil {
		// Best-effort rollback: remove the orphaned user record.
		// TODO: replace with DB transaction when repository layer supports it.
		_ = s.userRepo.UpdateState(ctx, user.ID, domain.UserStateIsDeleted)
		return nil, fmt.Errorf("register: create profile: %w", err)
	}

	// TODO: Write audit_logs record (action="register", detail={"login_email": email}).
	// See PRD §4.13 for audit log detail schema.

	return user, nil
}

func resolveEmailType(email string) (domain.EmailType, error) {
	switch {
	case strings.HasSuffix(email, "@njupt.edu.cn"):
		return domain.EmailTypeNJUPT, nil
	case strings.HasSuffix(email, "@sast.fun"):
		return domain.EmailTypeSAST, nil
	default:
		return "", domain.NewError(domain.ErrEmailDomainNotAllowed,
			"仅支持教育邮箱（@njupt.edu.cn）或飞书邮箱（@sast.fun）注册")
	}
}

func isAllowedEmailDomain(email string) bool {
	return strings.HasSuffix(email, "@njupt.edu.cn") || strings.HasSuffix(email, "@sast.fun")
}

func isValidCollege(c domain.College) bool {
	for _, valid := range domain.ValidCollegeValues() {
		if c == valid {
			return true
		}
	}
	return false
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := pbkdf2.Key([]byte(password), salt, 600000, 64, sha512.New)
	return fmt.Sprintf("pbkdf2$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

func generateRegisterTicket() (string, error) {
	buf := make([]byte, registerTicketLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "reg_" + hex.EncodeToString(buf), nil
}
