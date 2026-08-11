package oauthhandler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

const maxJSONRequestBodyBytes int64 = 8 << 10

var (
	errInvalidJSONContentType = errors.New("request Content-Type must be application/json")
	errTrailingJSONValue      = errors.New("JSON request body contains multiple values")
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

// decodeStrictJSON applies the same body policy as the session handlers: exact
// media type, bounded size, no unknown fields, exactly one JSON value.
func decodeStrictJSON(c *gin.Context, destination any) error {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errInvalidJSONContentType
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errTrailingJSONValue
	}
	return binding.Validator.ValidateStruct(destination)
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
//
// An unmapped error becomes a non-redirectable server_error: without a verified
// redirect_uri the safe destination is our own consent page, and an unknown error
// is exactly the case where redirectability cannot be established.
func authorizeErrorParts(err error) (code, description string, redirectable bool) {
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) {
		return oauth.ErrorServerError, "服务器内部错误", false
	}
	return oauthErr.Code, oauthErr.Description, oauthErr.Redirectable
}

// mapConsentError maps a consent failure onto the standard envelope. The consent
// endpoint is this project's own API rather than an RFC-defined one, so it keeps
// the envelope its front end already parses.
func mapConsentError(err error) error {
	// invalid_client on consent is 404, not 401: the caller is a logged-in human
	// whose own credentials are fine; what went wrong is that the third-party
	// client was disabled between the two legs. Answering 401 would tell the
	// consent page the user was not authenticated and send them to re-login,
	// which cannot help. 404 keeps the business code's {HTTP status}{sequence}
	// convention (API 文档 §1) intact, since the code is 40402.
	return mapEnvelopeError(err, http.StatusNotFound)
}

// mapGrantsError maps an authorized-apps failure onto the standard envelope. The
// grants endpoints are authenticated and answer in the envelope like consent; the
// only service failure they can raise is a rate limit (429 + Retry-After), which
// this must not collapse into a 500 that reads as an outage.
func mapGrantsError(err error) error {
	// invalid_client cannot occur here (the caller's own token authenticated the
	// request), so keep the RFC 6749 default 401 rather than consent's 404.
	return mapEnvelopeError(err, http.StatusUnauthorized)
}

// mapEnvelopeError maps an OAuth service failure onto the standard envelope, for
// the authenticated endpoints that keep the envelope instead of an RFC 6749 body.
// invalidClientStatus supplies the status for KindInvalidClient, which differs
// per endpoint (see mapConsentError). Every other kind uses the shared
// statusForKind table, so a rate limit surfaces as 429 with Retry-After.
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
		message = "服务器内部错误"
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
		// Paired with 404 on consent (mapConsentError), not the 401 that statusForKind
		// gives this kind on the RFC endpoints. See there for why.
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
	return &response.BusinessError{
		HTTPStatus: http.StatusBadRequest,
		Code:       errcode.CodeBadRequest,
		Message:    "请求参数错误",
	}
}

func internalError() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusInternalServerError,
		Code:       errcode.CodeInternal,
		Message:    "服务器内部错误",
	}
}
