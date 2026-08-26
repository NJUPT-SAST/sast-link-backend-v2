package adminhandler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

const maxJSONRequestBodyBytes int64 = 64 << 10

var (
	errInvalidJSONContentType = errors.New("request Content-Type must be application/json")
	errTrailingJSONValue      = errors.New("JSON request body contains multiple values")
)

// clientDTO is one registration on the wire. Written out field by field rather
// than serializing model.OAuthClient, which carries the secret hash: a response
// type with no such field cannot leak it no matter how the model changes later.
type clientDTO struct {
	ID           int64     `json:"id"`
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name"`
	ClientType   string    `json:"client_type"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// createdClientDTO is the registration response. It is a distinct type from
// clientDTO so client_secret exists on exactly the one response that answers the
// request that generated it.
type createdClientDTO struct {
	clientDTO
	// ClientSecret is present only for a confidential (third_party) client, and only
	// in this response. It is never retrievable afterwards.
	ClientSecret string `json:"client_secret,omitempty"`
}

// rotatedClientSecretDTO is the secret-rotation response. Like createdClientDTO,
// the plaintext exists on exactly this one response shape.
type rotatedClientSecretDTO struct {
	ClientID     int64  `json:"id"`
	ClientSecret string `json:"client_secret"`
}

type clientListResponse struct {
	Clients []clientDTO `json:"clients"`
}

type messageResponse struct {
	Message string `json:"message"`
}

func mapClient(client adminclient.Client) clientDTO {
	return clientDTO{
		ID:           client.ID,
		ClientID:     client.ClientID,
		ClientName:   client.ClientName,
		ClientType:   client.ClientType,
		RedirectURIs: nonNilStrings(client.RedirectURIs),
		GrantTypes:   nonNilStrings(client.GrantTypes),
		Scopes:       nonNilStrings(client.Scopes),
		IsActive:     client.IsActive,
		CreatedAt:    client.CreatedAt,
		UpdatedAt:    client.UpdatedAt,
	}
}

// nonNilStrings keeps an empty array from serializing as null, which would force
// every consumer to handle two shapes for "no entries".
func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// mapServiceError converts a typed service error into the HTTP envelope.
func mapServiceError(err error) error {
	var serviceErr *adminclient.Error
	if !errors.As(err, &serviceErr) {
		return internalError()
	}
	status := http.StatusInternalServerError
	message := "服务器内部错误"
	switch serviceErr.Kind {
	case adminclient.KindInvalidInput:
		status = http.StatusBadRequest
		// The service's messages are literals naming which rule was broken, never
		// echoes of submitted values, so they are safe to return verbatim.
		message = serviceErr.Message
	case adminclient.KindNotFound:
		status = http.StatusNotFound
		message = "OAuth 客户端不存在"
	case adminclient.KindConflict:
		status = http.StatusConflict
		message = "OAuth 客户端已存在"
	case adminclient.KindProtected:
		// 403 rather than 400: the request is well formed and the administrator is
		// authorized, but the built-in client is not theirs to disable; the message
		// names the rule.
		status = http.StatusForbidden
		message = serviceErr.Message
	case adminclient.KindInternal:
	}
	code := serviceErr.Code
	if code == 0 {
		code = errcode.CodeInternal
	}
	return &response.BusinessError{HTTPStatus: status, Code: code, Message: message}
}

func internalError() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusInternalServerError,
		Code:       errcode.CodeInternal,
		Message:    "服务器内部错误",
	}
}

func badRequest() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusBadRequest,
		Code:       errcode.CodeBadRequest,
		Message:    "请求参数错误",
	}
}

func notFound() error {
	return &response.BusinessError{
		HTTPStatus: http.StatusNotFound,
		Code:       errcode.CodeClientNotFound,
		Message:    "OAuth 客户端不存在",
	}
}

// decodeStrictJSON applies the shared request-body policy: exact content type, a
// size cap, no unknown fields, and no trailing values.
func decodeStrictJSON(c *gin.Context, destination any) error {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errInvalidJSONContentType
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxJSONRequestBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	// Unknown fields are rejected, which is what makes the immutable properties
	// safe: a request trying to change client_id / client_secret / client_type /
	// id is refused outright instead of silently ignored.
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
