package oauthlogin

import (
	"context"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
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
