package oauthlogin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/provider"
)

func TestAppCodeInvalidChallengeDoesNotConsumeProviderCode(t *testing.T) {
	for _, challenge := range []string{"", "nonempty-but-short", strings.Repeat("a", 44), strings.Repeat("a", 42) + "=", strings.Repeat("a", 42) + "!"} {
		t.Run(challenge, func(t *testing.T) {
			service, doubles := newTestService(t)
			lark := enableLarkAppCode(service)
			doubles.Users.byID[42] = activeUser(42)
			doubles.Identities.put(&model.Identity{UserID: 42, Provider: model.LoginMethodLark, ProviderID: "on_union"})
			_, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "same-jsapi-code", CodeChallenge: challenge})
			assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
			if lark.appCodeCalls != 0 {
				t.Fatalf("invalid challenge consumed provider code: calls=%d", lark.appCodeCalls)
			}
			if len(doubles.LoginCodes.codes) != 0 || doubles.Tokens.pairs != 0 {
				t.Fatal("invalid challenge issued a credential")
			}
			entry := lastAuditEntry(t, doubles.Audits)
			if got := detailString(t, entry, "failure_reason"); got != "invalid_challenge" {
				t.Fatalf("failure_reason=%q", got)
			}
			result, err := service.AppCodeLogin(context.Background(), AppCodeLoginInput{Code: "same-jsapi-code", CodeChallenge: testPKCEChallenge})
			if err != nil || result == nil || !result.Bound {
				t.Fatalf("corrected request failed: result=%+v err=%v", result, err)
			}
			if lark.appCodeCalls != 1 {
				t.Fatalf("valid request provider calls=%d", lark.appCodeCalls)
			}
			if doubles.LoginCodes.codes[result.LoginCode].challenge != testPKCEChallenge {
				t.Fatal("challenge binding lost")
			}
		})
	}
}

// Observe the provider context without waiting for the production timeout.
type budgetAppCodeProvider struct {
	*fakeAppCodeProvider
	exchangeCtx context.Context
	remaining   time.Duration
	hasDeadline bool
}

func (p *budgetAppCodeProvider) ExchangeAppCode(ctx context.Context, code string) (*provider.Identity, error) {
	p.exchangeCtx = ctx
	deadline, ok := ctx.Deadline()
	p.hasDeadline = ok
	p.remaining = time.Until(deadline)
	return p.fakeAppCodeProvider.ExchangeAppCode(ctx, code)
}

func TestAppCodePKCEAndExchangeBudgetCompose(t *testing.T) {
	for _, outerBudget := range []time.Duration{0, 3 * time.Second} {
		t.Run(outerBudget.String(), func(t *testing.T) {
			service, doubles := newTestService(t)
			lark := &budgetAppCodeProvider{fakeAppCodeProvider: enableLarkAppCode(service)}
			service.Providers[model.LoginMethodLark] = lark
			doubles.Users.byID[42] = activeUser(42)
			doubles.Identities.put(&model.Identity{UserID: 42, Provider: model.LoginMethodLark, ProviderID: "on_union"})
			ctx := context.Background()
			if outerBudget > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, outerBudget)
				defer cancel()
			}
			_, err := service.AppCodeLogin(ctx, AppCodeLoginInput{Code: "same-code", CodeChallenge: "invalid"})
			assertKind(t, err, KindInvalidInput, errcode.CodeBadRequest)
			if lark.exchangeCtx != nil {
				t.Fatal("invalid challenge reached provider")
			}
			result, err := service.AppCodeLogin(ctx, AppCodeLoginInput{Code: "same-code", CodeChallenge: testPKCEChallenge})
			if err != nil || result == nil || !result.Bound {
				t.Fatalf("valid request: result=%+v error=%v", result, err)
			}
			maximum := callbackExchangeBudget
			if outerBudget > 0 {
				maximum = outerBudget - time.Second
			}
			if !lark.hasDeadline || lark.remaining <= 0 || lark.remaining > maximum {
				t.Fatalf("provider deadline: present=%t remaining=%s max=%s", lark.hasDeadline, lark.remaining, maximum)
			}
			if !errors.Is(lark.exchangeCtx.Err(), context.Canceled) {
				t.Fatal("provider context not canceled after exchange")
			}
			if ctx.Err() != nil {
				t.Fatal("provider cleanup canceled caller")
			}
			if lark.appCodeCalls != 1 || doubles.LoginCodes.codes[result.LoginCode].challenge != testPKCEChallenge {
				t.Fatal("provider calls or challenge binding changed")
			}
		})
	}
}
