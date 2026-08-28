package oauthhandler

import (
	"errors"
	"net/http"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
)

// consentRequest is the consent page's submission.
//
// Approve is a pointer so an omitted field is a bad request rather than silently
// meaning "deny": a page that fails to send the user's choice must be corrected,
// not have a decision inferred for it.
type consentRequest struct {
	RequestID string `json:"request_id" binding:"required"`
	Approve   *bool  `json:"approve" binding:"required"`
}

type consentResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// consentInfoResponse is the verified client metadata for a pending request,
// served to the consent page so it never renders URL-supplied values.
type consentInfoResponse struct {
	ClientName string   `json:"client_name"`
	Scopes     []string `json:"scopes"`
	ExpiresIn  int      `json:"expires_in"`
}

// tokenResponse is the RFC 6749 §5.1 success body. IDToken is omitempty so a
// grant without openid — which this service does not currently issue — would not
// advertise an empty ID token.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// invalidRequest builds a non-redirectable invalid_request error.
func invalidRequest(description string) error {
	return &oauth.Error{
		Kind:        oauth.KindInvalidRequest,
		Code:        oauth.ErrorInvalidRequest,
		Description: description,
	}
}

// invalidToken builds an RFC 6750 invalid_token error.
func invalidToken(description string) error {
	return &oauth.Error{
		Kind:        oauth.KindInvalidToken,
		Code:        oauth.ErrorInvalidToken,
		Description: description,
	}
}

// authorizeErrorParts extracts what a redirect needs from an authorize failure.
// An unmapped error becomes a non-redirectable server_error: without a verified
// redirect_uri the safe destination is our own consent page.
func authorizeErrorParts(err error) (code, description string, redirectable bool) {
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) {
		return oauth.ErrorServerError, "服务器内部错误", false
	}
	return oauthErr.Code, oauthErr.Description, oauthErr.Redirectable
}

// mapConsentError maps a consent failure onto the standard envelope, which this
// project-owned endpoint keeps. invalid_client is 404, not 401: the caller is a
// logged-in human whose own credentials are fine, and 401 would send them to a
// useless re-login.
func mapConsentError(err error) error {
	return mapEnvelopeError(err, http.StatusNotFound)
}

// mapGrantsError maps an authorized-apps failure onto the standard envelope.
// invalid_client cannot occur here (the caller's own token authenticated), so it
// keeps the RFC 6749 default 401 rather than consent's 404.
func mapGrantsError(err error) error {
	return mapEnvelopeError(err, http.StatusUnauthorized)
}

// mapEnvelopeError maps an OAuth service failure onto the standard envelope, for
// the authenticated endpoints that keep the envelope instead of an RFC 6749 body.
// invalidClientStatus supplies the status for KindInvalidClient, which differs per
// endpoint (see mapConsentError); every other kind uses the shared statusForKind
// table, so a rate limit surfaces as 429 with Retry-After.
func mapEnvelopeError(err error, invalidClientStatus int) error {
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) {
		return internalError()
	}
	status := statusForKind(oauthErr.Kind)
	if oauthErr.Kind == oauth.KindInvalidClient {
		status = invalidClientStatus
	}
	code := businessCodeForKind(oauthErr.Kind)
	message := oauthErr.Description
	if oauthErr.Kind == oauth.KindInternal || message == "" {
		message = errcode.Messages[errcode.CodeInternal]
	}
	return &response.BusinessError{
		HTTPStatus: status,
		Code:       code,
		Message:    message,
		RetryAfter: oauthErr.RetryAfter,
	}
}

// businessCodeForKind maps an OAuth failure to the project's business codes, for
// the envelope-answering endpoints only.
func businessCodeForKind(kind oauth.Kind) int {
	switch kind {
	case oauth.KindInvalidRequest, oauth.KindInvalidGrant:
		return errcode.CodeBadRequest
	case oauth.KindInvalidClient:
		// Paired with 404 on consent (mapConsentError), not the 401 statusForKind gives.
		return errcode.CodeClientNotFound
	case oauth.KindInvalidToken:
		return errcode.CodeAccessTokenInvalid
	case oauth.KindAccessDenied:
		return errcode.CodeForbidden
	case oauth.KindRateLimited:
		return errcode.CodeRateLimited
	case oauth.KindDependencyUnavailable:
		return errcode.CodeDependencyUnavailable
	case oauth.KindInternal:
		return errcode.CodeInternal
	default:
		return errcode.CodeInternal
	}
}

func badRequest() error {
	return webutil.BadRequest()
}

func internalError() error {
	return webutil.InternalError()
}
