package oauthloginhandler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// mapServiceError turns a typed service error into the standard envelope's
// business error. Mirrors sessionhandler.mapServiceError: Code selects the
// message, Kind selects the HTTP status.
func mapServiceError(err error) error {
	var serviceErr *oauthlogin.Error
	if !errors.As(err, &serviceErr) {
		return err
	}
	message := defaultMessage(serviceErr.Kind)
	switch serviceErr.Code {
	case errcode.CodeLoginCodeInvalid:
		message = errcode.Messages[errcode.CodeLoginCodeInvalid]
	case errcode.CodeLarkTenantRequired:
		// Tenant gate names the rule; distinct from errcode's generic wording.
		message = "仅限 SAST 成员登录"
	case errcode.CodeIdentityOccupied:
		message = errcode.Messages[errcode.CodeIdentityOccupied]
	case errcode.CodeIdentityAlreadyBound:
		// Bound-once surface spells out the constraint the canonical message leaves.
		message = "该类型账号已绑定，不可重复绑定"
	case errcode.CodeUserNotFound:
		message = errcode.Messages[errcode.CodeUserNotFound]
	case errcode.CodeAccountDeleted:
		message = errcode.Messages[errcode.CodeAccountDeleted]
	case errcode.CodePasswordInvalid:
		message = errcode.Messages[errcode.CodePasswordInvalid]
	}

	var status int
	switch serviceErr.Kind {
	case oauthlogin.KindInvalidInput, oauthlogin.KindInvalidState:
		status = http.StatusBadRequest
	case oauthlogin.KindRateLimited:
		message = errcode.Messages[errcode.CodeRateLimited]
		status = http.StatusTooManyRequests
	case oauthlogin.KindInvalidToken:
		status = http.StatusUnauthorized
	case oauthlogin.KindUserDeleted, oauthlogin.KindForbidden:
		status = http.StatusForbidden
	case oauthlogin.KindConflict:
		status = http.StatusConflict
	case oauthlogin.KindNotFound:
		status = http.StatusNotFound
	case oauthlogin.KindProviderUnavailable:
		// 502, not 503: this service is healthy and the request well formed; the
		// fix is on GitHub's or Lark's side, and a 503 would suggest retrying here
		// helps.
		message = "第三方服务暂时不可用"
		status = http.StatusBadGateway
	case oauthlogin.KindDependencyUnavailable:
		message = errcode.Messages[errcode.CodeDependencyUnavailable]
		status = http.StatusServiceUnavailable
	case oauthlogin.KindInternal:
		message = errcode.Messages[errcode.CodeInternal]
		status = http.StatusInternalServerError
	default:
		message = errcode.Messages[errcode.CodeInternal]
		status = http.StatusInternalServerError
	}

	// Last, so it wins over both tables above. Only messages the service marked
	// as user-facing get here; internal ones keep their generic replacement.
	if serviceErr.Display && strings.TrimSpace(serviceErr.Message) != "" {
		message = serviceErr.Message
	}

	code := serviceErr.Code
	if code == 0 {
		code = defaultCode(serviceErr.Kind)
	}
	return &response.BusinessError{
		HTTPStatus: status,
		Code:       code,
		Message:    message,
		RetryAfter: serviceErr.RetryAfter,
	}
}

func defaultCode(kind oauthlogin.Kind) int {
	switch kind {
	case oauthlogin.KindInvalidInput, oauthlogin.KindInvalidState:
		return errcode.CodeBadRequest
	case oauthlogin.KindRateLimited:
		return errcode.CodeRateLimited
	case oauthlogin.KindInvalidToken:
		return errcode.CodeLoginCodeInvalid
	case oauthlogin.KindUserDeleted:
		return errcode.CodeAccountDeleted
	case oauthlogin.KindForbidden:
		return errcode.CodeForbidden
	case oauthlogin.KindConflict:
		return errcode.CodeConflict
	case oauthlogin.KindNotFound:
		return errcode.CodeNotFound
	case oauthlogin.KindProviderUnavailable, oauthlogin.KindDependencyUnavailable:
		return errcode.CodeDependencyUnavailable
	default:
		return errcode.CodeInternal
	}
}

func defaultMessage(kind oauthlogin.Kind) string {
	switch kind {
	case oauthlogin.KindInvalidInput:
		return "请求参数错误"
	case oauthlogin.KindRateLimited:
		return "请求过于频繁"
	case oauthlogin.KindInvalidState:
		return "state 无效或已过期"
	case oauthlogin.KindInvalidToken:
		return "login_code 无效或已过期"
	case oauthlogin.KindUserDeleted:
		return "账号已注销"
	case oauthlogin.KindForbidden:
		return "无权限"
	case oauthlogin.KindConflict:
		return "资源已存在"
	case oauthlogin.KindNotFound:
		return "资源不存在"
	case oauthlogin.KindProviderUnavailable:
		return "第三方服务暂时不可用"
	case oauthlogin.KindDependencyUnavailable:
		return "依赖服务暂不可用"
	default:
		return "服务器内部错误"
	}
}
