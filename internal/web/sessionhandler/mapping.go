package sessionhandler

import (
	"errors"
	"net/http"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

func mapServiceError(err error) error {
	var serviceErr *session.Error
	if !errors.As(err, &serviceErr) {
		return err
	}
	message := defaultMessage(serviceErr.Kind)
	switch serviceErr.Code {
	case errcode.CodeRegisterTicketInvalid:
		message = errcode.Messages[errcode.CodeRegisterTicketInvalid]
	case errcode.CodeConcurrentRefresh:
		message = errcode.Messages[errcode.CodeConcurrentRefresh]
	case errcode.CodeBindTicketInvalid:
		message = errcode.Messages[errcode.CodeBindTicketInvalid]
	case errcode.CodeVerificationCodeWrong:
		message = errcode.Messages[errcode.CodeVerificationCodeWrong]
	case errcode.CodeVerificationCodeExpired:
		message = errcode.Messages[errcode.CodeVerificationCodeExpired]
	case errcode.CodeEmailDomainNotAllowed:
		message = errcode.Messages[errcode.CodeEmailDomainNotAllowed]
	case errcode.CodeEmailAlreadyRegistered:
		message = errcode.Messages[errcode.CodeEmailAlreadyRegistered]
	case errcode.CodeStudentIDOccupied:
		message = errcode.Messages[errcode.CodeStudentIDOccupied]
	case errcode.CodeIdentityOccupied:
		// The bind flow names the mailbox, more specific than the canonical
		// "third-party account" wording; both stay reachable.
		message = "该邮箱已被绑定或占用"
	case errcode.CodeIdentityAlreadyBound:
		message = errcode.Messages[errcode.CodeIdentityAlreadyBound]
	case errcode.CodeIdentityLimitReached:
		message = errcode.Messages[errcode.CodeIdentityLimitReached]
	case errcode.CodePasswordTooShort:
		message = errcode.Messages[errcode.CodePasswordTooShort]
	case errcode.CodePasswordUnchanged:
		message = errcode.Messages[errcode.CodePasswordUnchanged]
	case errcode.CodeUserNotFound:
		// The KindNotFound default would contradict this code's own meaning.
		message = errcode.Messages[errcode.CodeUserNotFound]
	case errcode.CodeNotFound:
		// The service error carries the right message for either the unbind or
		// the device-logout path; stamping one here would mislabel the other.
		if serviceErr.Message != "" {
			message = serviceErr.Message
		}
	case errcode.CodeValidationFailed:
		// Only ErrLastLoginMethod raises this; the default would drop the rule
		// it broke.
		message = "不能解绑唯一的登录方式"
	case errcode.CodeAvatarRejected:
		// A policy verdict, not a malformed request; the generic default would
		// mislabel it.
		message = errcode.Messages[errcode.CodeAvatarRejected]
	}
	var status int
	switch serviceErr.Kind {
	case session.KindInvalidInput:
		status = http.StatusBadRequest
	case session.KindRateLimited, session.KindLocked:
		status = http.StatusTooManyRequests
	case session.KindUnknownIdentifier, session.KindPasswordInvalid, session.KindLoginFailed, session.KindInvalidToken:
		status = http.StatusUnauthorized
	case session.KindUserDeleted:
		status = http.StatusForbidden
	case session.KindEmailFailed:
		// "请稍后重试" is a handler-side UX addition over errcode's canonical
		// "邮件发送失败", deliberately not folded into errcode.
		message = "邮件发送失败，请稍后重试"
		status = http.StatusInternalServerError
	case session.KindObjectUploadFailed:
		message = "头像上传失败，请稍后重试"
		status = http.StatusInternalServerError
	case session.KindConflict:
		status = http.StatusConflict
	case session.KindValidationFailed:
		status = http.StatusUnprocessableEntity
	case session.KindNotFound:
		status = http.StatusNotFound
	case session.KindDependencyUnavailable:
		// Same UX addition as KindEmailFailed.
		message = "依赖服务暂不可用，请稍后重试"
		status = http.StatusServiceUnavailable
	case session.KindInternal:
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
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message, RetryAfter: serviceErr.RetryAfter}
}

func defaultCode(kind session.Kind) int {
	switch kind {
	case session.KindInvalidInput:
		return errcode.CodeBadRequest
	case session.KindUnknownIdentifier:
		return errcode.CodeUnknownIdentifier
	case session.KindPasswordInvalid:
		return errcode.CodePasswordInvalid
	case session.KindLoginFailed:
		return errcode.CodePasswordInvalid
	case session.KindInvalidToken:
		return errcode.CodeAccessTokenInvalid
	case session.KindUserDeleted:
		return errcode.CodeAccountDeleted
	case session.KindRateLimited, session.KindLocked:
		return errcode.CodeRateLimited
	case session.KindConflict:
		return errcode.CodeConflict
	case session.KindValidationFailed:
		return errcode.CodeValidationFailed
	case session.KindNotFound:
		return errcode.CodeNotFound
	case session.KindDependencyUnavailable:
		return errcode.CodeDependencyUnavailable
	case session.KindObjectUploadFailed:
		return errcode.CodeObjectUploadFailed
	default:
		return errcode.CodeInternal
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
	case session.KindLoginFailed:
		return "邮箱或密码错误"
	case session.KindUserDeleted:
		return "账号已注销"
	case session.KindInvalidToken:
		return "Access Token 无效或已被撤销"
	case session.KindConflict:
		return "资源已存在"
	case session.KindValidationFailed:
		return "业务校验失败"
	case session.KindNotFound:
		return "资源不存在"
	case session.KindDependencyUnavailable:
		return "依赖服务暂不可用，请稍后重试"
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

		ProfileNeedsCompletion: input.ProfileNeedsCompletion,
		IncompleteFields:       incompleteFields(input.IncompleteFields),
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

		ProfileNeedsCompletion: input.ProfileNeedsCompletion,
		IncompleteFields:       incompleteFields(input.IncompleteFields),

		Identities: make([]identityDTO, 0, len(input.Identities)),
		CreatedAt:  input.CreatedAt,
		UpdatedAt:  input.UpdatedAt,
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
		output.Identities = append(output.Identities, mapIdentity(identity))
	}
	return output
}

func mapIdentity(input session.IdentityDTO) identityDTO {
	return identityDTO{
		ID:             input.ID,
		Provider:       input.Provider,
		ProviderID:     input.ProviderID,
		IdentityData:   input.IdentityData,
		TokenExpiresAt: input.TokenExpiresAt,
		CreatedAt:      input.CreatedAt,
		UpdatedAt:      input.UpdatedAt,
	}
}

// incompleteFields normalizes a nil slice to an empty one so the JSON field is
// always an array. A client reading response.data.incomplete_fields.length must
// not have to special-case null, and "no fields" is the common case: every
// healthy account returns it.
func incompleteFields(fields []string) []string {
	if fields == nil {
		return []string{}
	}
	return fields
}
