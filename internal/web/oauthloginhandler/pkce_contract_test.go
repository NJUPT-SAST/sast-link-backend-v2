package oauthloginhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
)

type pkceCodeStore struct {
	calls     int
	available bool
}

func (s *pkceCodeStore) SaveLoginCode(context.Context, string, int64, string, time.Duration) error {
	return nil
}
func (s *pkceCodeStore) ConsumeLoginCode(context.Context, string) (int64, string, bool, error) {
	s.calls++
	found := s.available
	s.available = false
	return 42, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", found, nil
}
func TestExchangeCodeInvalidVerifierHTTPContract(t *testing.T) {
	for name, body := range map[string]string{
		"missing": `{"code":"lc_review"}`,
		"empty":   `{"code":"lc_review","code_verifier":""}`,
		"null":    `{"code":"lc_review","code_verifier":null}`,
		"short":   `{"code":"lc_review","code_verifier":"short"}`,
		"wrong":   `{"code":"lc_review","code_verifier":"wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"}`,
	} {
		t.Run(name, func(t *testing.T) {
			store := &pkceCodeStore{available: true}
			router := newTestRouter(Handler{Service: oauthlogin.Service{LoginCodes: store}}, 0)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			out := httptest.NewRecorder()
			router.ServeHTTP(out, req)
			code, msg, _ := decodeEnvelope(t, out.Body.String())
			t.Logf("status=%d code=%d message=%q consume_calls=%d code_remaining=%t", out.Code, code, msg, store.calls, store.available)
			if out.Code != 401 || code != 40107 || store.calls != 1 || store.available {
				t.Error("missing/invalid verifier must reach one-time consumption and the documented 40107 outcome")
			}
		})
	}
}

// Malformed JSON remains a transport error and must not consume a credential.
func TestExchangeCodeMalformedJSONDoesNotConsumeCode(t *testing.T) {
	for _, body := range []string{
		`{"code":"lc_review","code_verifier":123}`,
		`{"code":"lc_review","code_verifier":"wrong","extra":true}`,
		`{"code":"lc_review",`,
		`{"code_verifier":"wrong"}`,
	} {
		store := &pkceCodeStore{available: true}
		router := newTestRouter(Handler{Service: oauthlogin.Service{LoginCodes: store}}, 0)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		router.ServeHTTP(out, req)
		code, _, _ := decodeEnvelope(t, out.Body.String())
		if out.Code != 400 || code != 40000 || store.calls != 0 || !store.available {
			t.Fatalf("body=%s status=%d code=%d calls=%d available=%t", body, out.Code, code, store.calls, store.available)
		}
	}
}
