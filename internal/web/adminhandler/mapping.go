package adminhandler

import (
	"errors"
	"net/http"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/adminclient"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/webutil"
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
		message = errcode.Messages[errcode.CodeClientNotFound]
	case adminclient.KindConflict:
		status = http.StatusConflict
		// This surface names the exact duplicate, unlike the canonical 40900.
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
	return webutil.InternalError()
}

func badRequest() error {
	return webutil.BadRequest()
}

func notFound() error {
	return webutil.NotFound(errcode.CodeClientNotFound, "OAuth 客户端不存在")
}

// decodeStrictJSON is the shared strict body decoder, kept here under its
// historical lowercase name so the call sites in this package did not change.
var decodeStrictJSON = webutil.DecodeStrictJSON
