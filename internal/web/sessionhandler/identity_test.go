package sessionhandler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/session"
)

func TestListIdentitiesReturnsArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	created := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	service := &fakeService{listIdentitiesResult: &session.ListIdentitiesResult{
		Identities: []session.IdentityDTO{
			{ID: 1, Provider: "github", ProviderID: "145339646", CreatedAt: created, UpdatedAt: created},
			{ID: 3, Provider: "other_mail", ProviderID: "me@qq.com", CreatedAt: created, UpdatedAt: created},
		},
	}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/user/identities", "")

	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || body.Code != 0 {
		t.Fatalf("response = %d %#v", recorder.Code, body)
	}
	identities := body.Data.(map[string]any)["identities"].([]any)
	if len(identities) != 2 {
		t.Fatalf("identities = %#v, want 2", identities)
	}
	first := identities[0].(map[string]any)
	if first["provider"] != "github" || first["provider_id"] != "145339646" {
		t.Fatalf("first identity = %#v", first)
	}
	if service.listIdentitiesInput.UserID != 42 {
		t.Fatalf("user id = %d, want 42", service.listIdentitiesInput.UserID)
	}
}

// An empty binding list must serialize as [] rather than null, so clients can
// iterate the field unconditionally.
func TestListIdentitiesRendersEmptyArray(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := &fakeService{listIdentitiesResult: &session.ListIdentitiesResult{}}
	router := authedRouter(service)
	recorder := doJSON(router, http.MethodGet, "/user/identities", "")

	if !strings.Contains(recorder.Body.String(), `"identities":[]`) {
		t.Fatalf("body = %s, want an empty JSON array", recorder.Body.String())
	}
}
