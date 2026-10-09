package alumnirequest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRegressionMalformedRequestsBoundedDuringLimiterOutage(t *testing.T) {
	a := &fakeAudit{}
	c := &fakeCaptcha{}
	l := &fakeLimiter{err: errors.New("review fixture: redis unavailable")}
	s := newService(&fakeRequests{}, &fakeUsers{}, a, c)
	s.Limiter = l
	s.SubmitRateLimit = 5
	input := validSubmit()
	input.Name = ""
	input.StudentID = strings.Repeat("A", 60*1024)
	for range 20 {
		_, _ = s.Submit(context.Background(), input)
	}
	bytes := 0
	for _, e := range a.entries {
		bytes += len(e.Detail)
	}
	t.Logf("requests=20 configured_limit=5 audit_rows=%d audit_detail_bytes=%d captcha_calls=%d", len(a.entries), bytes, len(c.tokens))
	if len(a.entries) > 5 {
		t.Error("limiter outage leaves captcha-free malformed submissions able to create unbounded audit rows")
	}
}

func TestRegressionAuditIdentifiersAreByteBounded(t *testing.T) {
	input := validSubmit()
	input.StudentID = strings.Repeat("中", 20000)
	input.LoginEmail = strings.Repeat("a", 5000)
	input.PersonalEmail = strings.Repeat("b", 5000)
	detail := attemptedSubmitDetail(input)
	for key, value := range detail {
		s := value.(string)
		if len(s) > 320 || !utf8.ValidString(s) {
			t.Fatalf("%s len=%d invalid=%v", key, len(s), !utf8.ValidString(s))
		}
	}
}

func TestRegressionVerifiedSubmissionRetainsAuditDuringLimiterOutage(t *testing.T) {
	a := &fakeAudit{}
	c := &fakeCaptcha{}
	s := newService(&fakeRequests{}, &fakeUsers{}, a, c)
	s.Limiter = &fakeLimiter{err: errors.New("limiter down")}
	s.SubmitRateLimit = 5
	if _, err := s.Submit(context.Background(), validSubmit()); err != nil {
		t.Fatal(err)
	}
	if len(a.entries) != 1 || len(c.tokens) != 1 {
		t.Fatalf("audits=%d captcha=%d", len(a.entries), len(c.tokens))
	}
}
