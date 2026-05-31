package service

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/dto"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// RegisterService handles user registration.
type RegisterService struct {
	userRepo    repository.UserRepository
	profileRepo repository.ProfileRepository
	emailSvc    *EmailService
	captchaSvc  *CaptchaService
}

// NewRegisterService creates a new RegisterService.
func NewRegisterService(
	userRepo repository.UserRepository,
	profileRepo repository.ProfileRepository,
	emailSvc *EmailService,
	captchaSvc *CaptchaService,
) *RegisterService {
	return &RegisterService{
		userRepo:    userRepo,
		profileRepo: profileRepo,
		emailSvc:    emailSvc,
		captchaSvc:  captchaSvc,
	}
}

// SendVerificationEmail validates the email and sends a verification code.
func (s *RegisterService) SendVerificationEmail(ctx context.Context, email string) error {
	emailType, err := resolveEmailType(email)
	if err != nil {
		return err
	}
	_ = emailType // used during registration to set User.EmailType

	code, err := s.captchaSvc.Generate(ctx, email)
	if err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}

	if err := s.emailSvc.SendVerificationCode(email, code); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}

	return nil
}

// Register verifies the captcha and creates a new user with profile.
func (s *RegisterService) Register(ctx context.Context, req *dto.RegisterRequest) (*domain.User, error) {
	emailType, err := resolveEmailType(req.Email)
	if err != nil {
		return nil, err
	}

	ok, err := s.captchaSvc.Verify(ctx, req.Email, req.Captcha)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	if !ok {
		return nil, domain.NewError(domain.ErrCaptchaInvalid, "验证码错误或已过期")
	}

	hash, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	user := &domain.User{
		Role:       domain.UserRoleFreshman,
		Name:       req.Name,
		Phone:      req.Phone,
		QQNumber:   req.QQNumber,
		Password:   hash,
		StudentID:  req.StudentID,
		State:      domain.UserStateNJUPter,
		EmailType:  emailType,
		LoginEmail: req.Email,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("register: create user: %w", err)
	}

	profile := &domain.Profile{
		UserID:   user.ID,
		Nickname: req.Name,
		Email:    req.Email,
	}

	if err := s.profileRepo.Create(ctx, profile); err != nil {
		return nil, fmt.Errorf("register: create profile: %w", err)
	}

	return user, nil
}

func resolveEmailType(email string) (domain.EmailType, error) {
	switch {
	case strings.HasSuffix(email, "@njupt.edu.cn"):
		return domain.EmailTypeNJUPT, nil
	case strings.HasSuffix(email, "@sast.fun"):
		return domain.EmailTypeSAST, nil
	default:
		return "", domain.NewError(domain.ErrEmailFormat, "仅支持教育邮箱（@njupt.edu.cn）或飞书邮箱（@sast.fun）注册")
	}
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := pbkdf2.Key([]byte(password), salt, 600000, 64, sha512.New)
	return fmt.Sprintf("pbkdf2$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}
