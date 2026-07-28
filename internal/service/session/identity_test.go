package session

import (
	"context"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestListIdentitiesReturnsOwnedBindings(t *testing.T) {
	service := newRegisterService(t)
	identities := service.Identities.(*fakeIdentities)
	identities.byProviderID = map[string]*model.Identity{
		"mine@gmail.com":  {ID: 2, UserID: 42, Provider: model.LoginMethodOtherMail, ProviderID: "mine@gmail.com"},
		"other@gmail.com": {ID: 3, UserID: 99, Provider: model.LoginMethodOtherMail, ProviderID: "other@gmail.com"},
		"145339646":       {ID: 1, UserID: 42, Provider: model.LoginMethodGitHub, ProviderID: "145339646"},
	}
	result, err := service.ListIdentities(context.Background(), ListIdentitiesInput{UserID: 42})
	if err != nil {
		t.Fatalf("ListIdentities returned error: %v", err)
	}
	if len(result.Identities) != 2 {
		t.Fatalf("identities = %d, want only the caller's 2", len(result.Identities))
	}
	if result.Identities[0].ID != 1 || result.Identities[1].ID != 2 {
		t.Fatalf("identities = %+v, want ascending IDs", result.Identities)
	}
}

func TestListIdentitiesReturnsEmptySliceNotNil(t *testing.T) {
	service := newRegisterService(t)
	result, err := service.ListIdentities(context.Background(), ListIdentitiesInput{UserID: 42})
	if err != nil {
		t.Fatalf("ListIdentities returned error: %v", err)
	}
	if result.Identities == nil {
		t.Fatal("identities = nil, want empty slice so the JSON renders []")
	}
}
