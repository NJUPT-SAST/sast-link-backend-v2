package oauthloginhandler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/service/oauthlogin"
)

// This package has its own authUserDTO and mapUser, unrelated to sessionhandler's
// identically named pair, so the completion fields have to be added here
// separately. That makes this the easiest exit to forget and the most damaging one
// to miss: the accounts carrying migration debris are largely the ones that sign
// in through GitHub or Lark, so an omission here would hide the prompt from
// exactly the population it exists for.
//
// Note the DTO is populated from a model.User rather than from a service DTO, so
// this also covers mapUser deriving the field list through internal/validate.
func TestExchangeCodeCarriesProfileCompletionFlag(t *testing.T) {
	service := &fakeService{exchangeResult: &oauthlogin.ExchangeCodeResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		AccessExpiresAt: time.Now().Add(time.Hour),
		User: &model.User{
			ID: 42, Name: "B24040525", LoginEmail: "b24040525@njupt.edu.cn",
			Role: model.UserRoleFreshman, State: model.UserStateNJUPTer,
			StudentID: "B24040525", PhoneNumber: "", Major: "",
			ProfileNeedsCompletion: true,
		},
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", recorder.Code, recorder.Body.String())
	}
	_, _, data := decodeEnvelope(t, recorder.Body.String())
	user, ok := data["user"].(map[string]any)
	if !ok {
		t.Fatalf("user = %+v", data["user"])
	}
	if user["profile_needs_completion"] != true {
		t.Fatalf("profile_needs_completion = %#v, want true", user["profile_needs_completion"])
	}
	fields, ok := user["incomplete_fields"].([]any)
	if !ok {
		t.Fatalf("incomplete_fields = %#v, want an array", user["incomplete_fields"])
	}
	// name is reported because it duplicates the student ID, not because it is
	// blank; phone_number and major are blank.
	if len(fields) != 3 || fields[0] != "name" || fields[1] != "phone_number" || fields[2] != "major" {
		t.Fatalf("incomplete_fields = %#v", fields)
	}
}

func TestExchangeCodeReportsEmptyArrayForCompleteProfile(t *testing.T) {
	service := &fakeService{exchangeResult: &oauthlogin.ExchangeCodeResult{
		AccessToken:     "access",
		RefreshToken:    "refresh",
		TokenType:       "Bearer",
		AccessExpiresAt: time.Now().Add(time.Hour),
		User: &model.User{
			ID: 7, Name: "张三", LoginEmail: "pt@sast.fun",
			Role: model.UserRoleMember, State: model.UserStateOnSAST,
			StudentID: "B24040001", PhoneNumber: "13800000000", Major: "软件工程",
			ProfileNeedsCompletion: false,
		},
	}}
	router := newTestRouter(Handler{Service: service}, 0)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth/exchange-code",
		strings.NewReader(`{"code":"lc_abc"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	_, _, data := decodeEnvelope(t, recorder.Body.String())
	user := data["user"].(map[string]any)
	if user["profile_needs_completion"] != false {
		t.Fatalf("profile_needs_completion = %#v, want false", user["profile_needs_completion"])
	}
	fields, ok := user["incomplete_fields"].([]any)
	if !ok {
		t.Fatalf("incomplete_fields = %#v, want [] rather than null", user["incomplete_fields"])
	}
	if len(fields) != 0 {
		t.Fatalf("incomplete_fields = %#v, want empty", fields)
	}
}
