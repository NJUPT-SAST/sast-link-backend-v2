package sessionhandler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/web/response"
)

// PRD §10.1 exempts the card from the standard envelope, so the fields sit at the
// top level with no code/message wrapper.
func TestCardReturnsBarePayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{cardResult: &session.CardResult{Card: session.CardDTO{
		ID: 1, Nickname: stringPtr("张三"), Department: stringPtr("software"),
		Intro: stringPtr("自我介绍"), Avatar: stringPtr("https://cos.example.com/avatar/1.jpg"),
	}}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/card/1", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode card: %v; body=%s", err, recorder.Body.String())
	}
	if _, wrapped := payload["code"]; wrapped {
		t.Fatalf("body = %s, want no envelope", recorder.Body.String())
	}
	if payload["id"] != float64(1) || payload["nickname"] != "张三" {
		t.Fatalf("payload = %#v", payload)
	}
	if payload["blog_url"] != nil {
		t.Fatalf("blog_url = %#v, want null", payload["blog_url"])
	}
	if service.cardInput.UserID != 1 {
		t.Fatalf("user id = %d, want 1", service.cardInput.UserID)
	}
}

// The card must stay reachable without an Authorization header; it backs homepage
// friend links and the OIDC profile claim target.
func TestCardIsPublic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{cardResult: &session.CardResult{Card: session.CardDTO{ID: 7}}}
	router := gin.New()
	// A middleware that rejects everything: the card must not pass through it.
	RegisterRoutes(router, Handler{Service: service}, func(c *gin.Context) {
		response.Error(c, &response.BusinessError{
			HTTPStatus: http.StatusUnauthorized, Code: errcode.CodeUnauthenticated, Message: "未登录",
		})
		c.Abort()
	})
	recorder := doJSON(router, http.MethodGet, "/card/7", "")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 without auth; body=%s", recorder.Code, recorder.Body.String())
	}
	if service.cardCalls != 1 {
		t.Fatalf("service called %d times, want 1", service.cardCalls)
	}
}

func TestCardRejectsMalformedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/card/abc", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusNotFound || body.Code != errcode.CodeUserNotFound {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	if service.cardCalls != 0 {
		t.Fatalf("service called %d times, want 0", service.cardCalls)
	}
}

// A malformed ID and a missing or soft-deleted user must be indistinguishable, so
// a scraper cannot learn which IDs were once real. They previously disagreed on
// both fields: the handler answered 40400/"用户不存在" while the service path
// answered 40401 relabelled with the KindNotFound default "资源不存在".
func TestCardUnknownUserMatchesMalformedID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	malformed := decodeBody(t, doJSON(authedRouter(&fakeService{}), http.MethodGet, "/card/abc", ""))
	unknown := decodeBody(t, doJSON(
		authedRouter(&fakeService{cardErr: session.ErrUserNotFound}),
		http.MethodGet, "/card/999999", "",
	))

	if malformed.Code != unknown.Code || malformed.Message != unknown.Message {
		t.Fatalf("malformed = %#v, unknown = %#v, want identical code and message", malformed, unknown)
	}
	if unknown.Code != errcode.CodeUserNotFound {
		t.Fatalf("code = %d, want %d", unknown.Code, errcode.CodeUserNotFound)
	}
	if unknown.Message != "用户不存在" {
		t.Fatalf("message = %q, want 用户不存在", unknown.Message)
	}
}
