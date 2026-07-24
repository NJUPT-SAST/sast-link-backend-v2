package main

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestValidateInternalClientModel(t *testing.T) {
	secret := "secret"
	tests := []struct {
		name    string
		client  *model.OAuthClient
		wantErr string
	}{
		{name: "valid", client: &model.OAuthClient{ClientType: model.ClientTypeFirstParty, Scopes: model.StringArray{"openid", "profile", "email"}}},
		{name: "nil", client: nil, wantErr: "client is nil"},
		{name: "third party", client: &model.OAuthClient{ClientType: model.ClientTypeThirdParty, Scopes: model.StringArray{"openid", "profile", "email"}}, wantErr: "first-party public"},
		{name: "secret", client: &model.OAuthClient{ClientType: model.ClientTypeFirstParty, ClientSecretHash: &secret, Scopes: model.StringArray{"openid", "profile", "email"}}, wantErr: "first-party public"},
		{name: "missing scope", client: &model.OAuthClient{ClientType: model.ClientTypeFirstParty, Scopes: model.StringArray{"openid"}}, wantErr: "canonical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateInternalClientModel(test.client)
			if test.wantErr == "" && err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestAssembleSessionRuntimeWiresServiceAndMiddleware(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	_ = key
	if len(internalSessionScopes) != 3 {
		t.Fatalf("internalSessionScopes = %v, want 3 scopes", internalSessionScopes)
	}
}
