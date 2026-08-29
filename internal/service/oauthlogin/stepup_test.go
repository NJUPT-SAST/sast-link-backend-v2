package oauthlogin

import (
	"context"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// The audit row must name the acting client (the azp), so a delegated bind is
// not mistaken for an unauthenticated one (NULL keeps its "no credential"
// meaning).
func TestBindRecordsActorClientID(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	service.InternalClientID = "sast-link-web"

	if _, err := service.Bind(context.Background(), BindInput{
		UserID: 42, Provider: model.LoginMethodGitHub, Code: "provider-code",
		ActorClientID: "cl-9",
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	entry := doubles.Audits.entries[len(doubles.Audits.entries)-1]
	if entry.ActorClientID == nil || *entry.ActorClientID != "cl-9" {
		t.Fatalf("actor_client_id = %v, want the requesting client cl-9", entry.ActorClientID)
	}
}

func TestBindAuditsConsoleClientForInternalSession(t *testing.T) {
	service, doubles := newTestService(t)
	doubles.Users.byID[42] = activeUser(42)
	service.InternalClientID = "sast-link-web"

	if _, err := service.Bind(context.Background(), BindInput{
		UserID: 42, Provider: model.LoginMethodGitHub, Code: "provider-code",
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	entry := doubles.Audits.entries[len(doubles.Audits.entries)-1]
	if entry.ActorClientID == nil || *entry.ActorClientID != "sast-link-web" {
		t.Fatalf("actor_client_id = %v, want the built-in console client", entry.ActorClientID)
	}
}
