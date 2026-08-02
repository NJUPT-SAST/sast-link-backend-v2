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
		message = "Register-Ticket 无效或已过期"
	case errcode.CodeBindTicketInvalid:
		message = "Bind-Ticket 无效或已过期"
	case errcode.CodeVerificationCodeWrong:
		message = "验证码错误"
	case errcode.CodeVerificationCodeExpired:
		message = "验证码已过期"
	case errcode.CodeEmailDomainNotAllowed:
		message = "邮箱域名不允许"
	case errcode.CodeEmailAlreadyRegistered:
		message = "邮箱已被注册"
	case errcode.CodeStudentIDOccupied:
		message = "学号已被占用"
	case errcode.CodeIdentityOccupied:
		message = "该邮箱已被绑定或占用"
	case errcode.CodeIdentityAlreadyBound:
		message = "该类型账号已绑定"
	case errcode.CodeIdentityLimitReached:
		message = "第三方邮箱绑定数量已达上限"
	case errcode.CodePasswordTooShort:
		message = "密码长度不足"
	case errcode.CodePasswordUnchanged:
		message = "新旧密码相同"
	case errcode.CodeUserNotFound:
		// Without a case here the message falls back to the KindNotFound default
		// ("资源不存在"), which contradicts the code's own meaning and the handler's
		// malformed-ID path.
		message = "用户不存在"
	case errcode.CodeNotFound:
		// Only the unbind path raises this. The handler's malformed-ID branch already
		// answers "绑定记录不存在"; without this case the service path answered the
		// KindNotFound default instead, so the same 40400 had two messages.
		message = "绑定记录不存在"
	case errcode.CodeValidationFailed:
		// Only ErrLastLoginMethod raises this. The KindValidationFailed default
		// ("业务校验失败") drops the one thing the client needs to know: which rule
		// it broke.
		message = "不能解绑唯一的登录方式"
	}
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
	case session.KindEmailFailed:
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
