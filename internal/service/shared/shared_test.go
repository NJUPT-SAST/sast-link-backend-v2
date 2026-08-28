package shared

import (
	"context"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestDurationOrDefault(t *testing.T) {
	fallback := 5 * time.Minute
	cases := []struct {
		name  string
		value time.Duration
		want  time.Duration
	}{
		{"positive keeps value", 10 * time.Minute, 10 * time.Minute},
		{"zero falls back", 0, fallback},
		{"negative falls back", -time.Second, fallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DurationOrDefault(tc.value, fallback); got != tc.want {
				t.Fatalf("DurationOrDefault(%v) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestNullableString(t *testing.T) {
	if got := NullableString(""); got != nil {
		t.Fatalf("NullableString(\"\") = %v, want nil", got)
	}
	got := NullableString("abc")
	if got == nil || *got != "abc" {
		t.Fatalf("NullableString(\"abc\") = %v, want &abc", got)
	}
}

func TestActorClientID(t *testing.T) {
	if got := ActorClientID("cl-1", "console"); got != "cl-1" {
		t.Fatalf("with actor = %q, want the actor", got)
	}
	if got := ActorClientID("  cl-1  ", "console"); got != "cl-1" {
		t.Fatalf("actor trimmed = %q, want cl-1", got)
	}
	if got := ActorClientID("", "console"); got != "console" {
		t.Fatalf("empty actor = %q, want the console client", got)
	}
	if got := ActorClientID("", ""); got != "" {
		t.Fatalf("both empty = %q, want empty (caller stores NULL)", got)
	}
}

type collectingBlacklist struct {
	jtis []string
	err  error
}

func (b *collectingBlacklist) DeleteAuthStates(_ context.Context, jtis []string) error {
	if b.err != nil {
		return b.err
	}
	b.jtis = append(b.jtis, jtis...)
	return nil
}

func TestDeliverBlacklistFiltersExpiredAndEmpty(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	b := &collectingBlacklist{}
	DeliverBlacklist(context.Background(), b, []model.BlacklistEntry{
		{TokenID: "live", ExpiresAt: now.Add(time.Hour)},
		{TokenID: "expired", ExpiresAt: now.Add(-time.Minute)},
		{TokenID: "  ", ExpiresAt: now.Add(time.Hour)},
	}, now)
	if len(b.jtis) != 1 || b.jtis[0] != "live" {
		t.Fatalf("delivered = %v, want only the live, non-empty entry", b.jtis)
	}
}

func TestDeliverBlacklistNoops(t *testing.T) {
	DeliverBlacklist(context.Background(), nil, []model.BlacklistEntry{{TokenID: "x", ExpiresAt: time.Now().Add(time.Hour)}}, time.Now())
	DeliverBlacklist(context.Background(), &collectingBlacklist{}, nil, time.Now())
}
