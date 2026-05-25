package service

import (
	"context"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/domain"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

const (
	VerifyFlagRegister = 0
	VerifyFlagLogin    = 1
	VerifyFlagResetPwd = 2
)

type UserService struct {
	repo repository.UserRepository
	// TODO: ticketStore emailProvider tokenService
}

func NewUserService(repo repository.UserRepository) *UserService {
	return &UserService{repo: repo}
}

// VerifyAccount checks account existence and returns a ticket based on flag.
// flag=0: registration, 1: login, 2: reset password
func (s *UserService) VerifyAccount(ctx context.Context, username string, flag int) (string, error) {
	var (
		user *domain.User
		err  error
	)

	if strings.Contains(username, "@") {
		user, err = s.repo.FindByEmail(ctx, username)
	} else {
		user, err = s.repo.FindByStudentID(ctx, username)
	}
	if err != nil {
		return "", domain.WrapError(domain.ErrVerifyAccountFail, "verify account failed", err)
	}

	switch flag {
	case VerifyFlagRegister:
		if user != nil {
			return "", domain.NewError(domain.ErrAccountExists, "account already exists")
		}
		// TODO: generate register ticket
		return "", nil
	case VerifyFlagLogin:
		if user == nil {
			return "", domain.NewError(domain.ErrAccountNotFound, "account not found")
		}
		// TODO: generate login ticket
		return "", nil
	case VerifyFlagResetPwd:
		if user == nil {
			return "", domain.NewError(domain.ErrAccountNotFound, "account not found")
		}
		// TODO: generate reset password ticket
		return "", nil
	default:
		return "", domain.NewError(domain.ErrInvalidParams, "flag is invalid")
	}
}
