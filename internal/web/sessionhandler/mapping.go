package sessionhandler

import (
	"errors"
	"net/http"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

func mapServiceError(err error) error {
	var serviceErr *session.Error
	if !errors.As(err, &serviceErr) {
		return err
	}
	message := defaultMessage(serviceErr.Kind)
	var status int
	switch serviceErr.Kind {
	case session.KindInvalidInput:
		status = http.StatusBadRequest
	case session.KindRateLimited, session.KindLocked:
		status = http.StatusTooManyRequests
	case session.KindUnknownIdentifier, session.KindPasswordInvalid, session.KindInvalidToken:
		status = http.StatusUnauthorized
	case session.KindUserDeleted:
		status = http.StatusForbidden
	case session.KindInvalidClient, session.KindInternal:
		message = "服务器内部错误"
		status = http.StatusInternalServerError
	default:
		message = "服务器内部错误"
		status = http.StatusInternalServerError
	}
	code := serviceErr.Code
	if code == 0 {
		code = defaultCode(serviceErr.Kind)
	}
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message}
}

func defaultCode(kind session.Kind) int {
	switch kind {
	case session.KindInvalidInput:
		return session.CodeInvalidInput
	case session.KindUnknownIdentifier:
		return session.CodeUnknownIdentifier
	case session.KindPasswordInvalid:
		return session.CodePasswordInvalid
	case session.KindInvalidToken:
		return session.CodeInvalidToken
	case session.KindUserDeleted:
		return session.CodeUserDeleted
	case session.KindRateLimited, session.KindLocked:
		return session.CodeRateLimited
	default:
		return session.CodeInternal
	}
}

func defaultMessage(kind session.Kind) string {
	switch kind {
	case session.KindInvalidInput:
		return "请求参数错误"
	case session.KindRateLimited:
		return "请求过于频繁，请稍后再试"
	case session.KindLocked:
		return "登录失败次数过多，账号已锁定"
	case session.KindUnknownIdentifier:
		return "登录邮箱不存在"
	case session.KindPasswordInvalid:
		return "密码错误"
	case session.KindUserDeleted:
		return "账号已注销"
	case session.KindInvalidToken:
		return "Access Token 无效或已被撤销"
	default:
		return "服务器内部错误"
	}
}

func mapAuthUser(input session.UserProfileDTO) authUserDTO {
	return authUserDTO{
		ID:         input.ID,
		Name:       input.Name,
		LoginEmail: input.LoginEmail,
		Role:       input.Role,
		State:      input.State,
		EmailType:  input.EmailType,
		CreatedAt:  input.CreatedAt,
	}
}

func mapProfile(input session.UserProfileDTO) profileDTO {
	output := profileDTO{
		ID:          input.ID,
		Name:        input.Name,
		LoginEmail:  input.LoginEmail,
		Role:        input.Role,
		State:       input.State,
		EmailType:   input.EmailType,
		PhoneNumber: input.PhoneNumber,
		QQNumber:    input.QQNumber,
		StudentID:   input.StudentID,
		College:     input.College,
		Major:       input.Major,
		Identities:  make([]identityDTO, 0, len(input.Identities)),
		CreatedAt:   input.CreatedAt,
		UpdatedAt:   input.UpdatedAt,
	}
	if input.Profile != nil {
		output.Profile = &profileDetailDTO{
			Nickname:   input.Profile.Nickname,
			Department: input.Profile.Department,
			Intro:      input.Profile.Intro,
			Email:      input.Profile.Email,
			Avatar:     input.Profile.Avatar,
			BlogURL:    input.Profile.BlogURL,
			GitHubURL:  input.Profile.GitHubURL,
			CreatedAt:  input.Profile.CreatedAt,
			UpdatedAt:  input.Profile.UpdatedAt,
		}
	}
	for _, identity := range input.Identities {
		output.Identities = append(output.Identities, identityDTO{
			ID:             identity.ID,
			Provider:       identity.Provider,
			ProviderID:     identity.ProviderID,
			IdentityData:   identity.IdentityData,
			TokenExpiresAt: identity.TokenExpiresAt,
			CreatedAt:      identity.CreatedAt,
			UpdatedAt:      identity.UpdatedAt,
		})
	}
	return output
}
