package adminclient

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/auth"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/scope"
)

// A confidential client's secret is returned once in plaintext and stored only as a
// hash. The returned plaintext must verify against what was persisted, or the
// administrator would be handed a secret the token endpoint rejects.
func TestCreateClientIssuesVerifiableSecretForThirdParty(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.CreateClient(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if result.ClientSecret == "" {
		t.Fatal("third_party client got no client_secret")
	}
	if h.clients.created.ClientSecretHash == nil {
		t.Fatal("no secret hash was persisted")
	}
	// The plaintext must never be what lands in the column.
	if *h.clients.created.ClientSecretHash == result.ClientSecret {
		t.Fatal("the plaintext secret was stored instead of its hash")
	}
	if err := auth.VerifyClientSecret(result.ClientSecret, *h.clients.created.ClientSecretHash); err != nil {
		t.Fatalf("VerifyClientSecret(returned, stored) error = %v; the issued secret would not authenticate", err)
	}
}

// Delegated administration is grantable at registration time, but only under the
// conditions checkAdminScopeGrant enforces. This is the create door; the update door
// has to refuse the same things, and both are covered because with the delegate no
// longer pinned by client_id the registration is the only barrier left.
func TestCreateClientAdminScopeGuards(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		clientType string
		scopes     []string
		grantTypes []string
		actor      string
		wantKind   Kind
	}{
		{
			// A first-party client is public: the token endpoint authenticates it by PKCE
			// alone, so an intercepted authorization code is one barrier short of an
			// administrative token. Refused here as well as at authorize, so the registry
			// never stores a grant that could never be exercised.
			name: "first party is refused", clientType: "first_party",
			scopes: []string{"openid", scope.AdminWrite}, grantTypes: []string{"authorization_code"},
			wantKind: KindInvalidInput,
		},
		{
			// The refresh grant inherits scopes without narrowing, so this would renew itself
			// indefinitely.
			name: "refresh_token is refused", clientType: "third_party",
			scopes: []string{"openid", scope.AdminRead}, grantTypes: []string{"authorization_code", "refresh_token"},
			wantKind: KindInvalidInput,
		},
		{
			// Otherwise a delegate could register another delegate, and the set of clients
			// reaching /admin would grow without an operator approving it.
			name: "a delegated actor is refused", clientType: "third_party",
			scopes: []string{"openid", scope.AdminWrite}, grantTypes: []string{"authorization_code"},
			actor: "sast-people-admin", wantKind: KindProtected,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			input := validCreateInput()
			input.ClientType = testCase.clientType
			input.Scopes = testCase.scopes
			input.GrantTypes = testCase.grantTypes
			input.ActorClientID = testCase.actor

			_, err := h.service.CreateClient(context.Background(), input)
			assertKind(t, err, testCase.wantKind)
			if h.clients.created != nil {
				t.Fatalf("a client was persisted despite the rejection: %#v", h.clients.created)
			}
		})
	}
}

// The console may grant delegated administration to a confidential client that holds
// no refresh grant. This is the whole point of the change: onboarding an ops tool is a
// console action, not a migration.
func TestCreateClientAcceptsAdminScopeFromConsole(t *testing.T) {
	h := newHarness(t)
	input := validCreateInput()
	input.Scopes = []string{"openid", scope.AdminRead, scope.AdminWrite}
	input.GrantTypes = []string{"authorization_code"}

	result, err := h.service.CreateClient(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateClient() error = %v, want success", err)
	}
	if h.clients.created == nil {
		t.Fatal("no client was persisted")
	}
	if !scope.ContainsAdmin([]string(h.clients.created.Scopes)) {
		t.Fatalf("persisted scopes = %v, want the admin scopes", h.clients.created.Scopes)
	}
	if result.ClientSecret == "" {
		t.Fatal("a delegated client must be confidential and receive a secret")
	}
	// The audit row has to be findable without joining the row it created.
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	if detail := string(h.audit.entries[0].Detail); !strings.Contains(detail, "admin_scope") {
		t.Fatalf("audit detail = %s, want an admin_scope marker", detail)
	}
}

// A first_party client is public and authenticates with PKCE, matching the built-in
// client seeded by V003. Issuing it a secret would imply a credential that no
// first-party flow presents.
func TestCreateClientWithholdsSecretForFirstParty(t *testing.T) {
	h := newHarness(t)
	input := validCreateInput()
	input.ClientType = "first_party"

	result, err := h.service.CreateClient(context.Background(), input)
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if result.ClientSecret != "" {
		t.Fatal("first_party client was issued a client_secret")
	}
	if h.clients.created.ClientSecretHash != nil {
		t.Fatal("first_party client stored a secret hash, want NULL")
	}
}

// client_id is generated, never taken from the request: an operator-supplied value
// could claim an identifier another client expects to own — including the built-in
// client that the internal API's azp gate is pinned to.
func TestCreateClientGeneratesClientID(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.CreateClient(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if result.Client.ClientID != "generated-client-id" {
		t.Fatalf("client_id = %q, want the generated value", result.Client.ClientID)
	}
	// Real generation must be unguessable; the harness stubs it, so check the
	// production generator directly.
	first, err := newClientID()
	if err != nil {
		t.Fatalf("newClientID() error = %v", err)
	}
	second, err := newClientID()
	if err != nil {
		t.Fatalf("newClientID() error = %v", err)
	}
	if first == second || len(first) != 32 {
		t.Fatalf("newClientID() = %q then %q, want distinct 128-bit hex values", first, second)
	}
}

// Grants are stored in canonical order so two registrations listing the same set
// are byte-identical in the database.
func TestCreateClientCanonicalizesGrantTypes(t *testing.T) {
	h := newHarness(t)
	input := validCreateInput()
	input.GrantTypes = []string{"refresh_token", "authorization_code"}

	if _, err := h.service.CreateClient(context.Background(), input); err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	stored := []string(h.clients.created.GrantTypes)
	if len(stored) != 2 || stored[0] != "authorization_code" || stored[1] != "refresh_token" {
		t.Fatalf("stored grant types = %v, want canonical order", stored)
	}
}

// Disabling a client must revoke its live tokens. An administrator disabling a
// client expects access to stop now; leaving access tokens valid for up to their
// full hour would contradict the action they just took.
func TestUpdateClientDisablingRevokesTokens(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = activeClient(5)
	h.clients.updateEntries = []model.BlacklistEntry{
		{TokenID: "jti-1", ExpiresAt: testNow.Add(30 * time.Minute)},
		{TokenID: "jti-2", ExpiresAt: testNow.Add(time.Hour)},
	}
	disabled := false

	result, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 5, IsActive: &disabled, AdminUserID: 99,
	})
	if err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}
	if !h.clients.updateRevoked {
		t.Fatal("disabling the client did not request revocation")
	}
	if result.RevokedTokens != 2 {
		t.Fatalf("RevokedTokens = %d, want 2", result.RevokedTokens)
	}
	// The revoked JTIs must reach the auth-state cache for immediate invalidation.
	if len(h.blacklist.jtis) != 2 || !slices.Contains(h.blacklist.jtis, "jti-1") || !slices.Contains(h.blacklist.jtis, "jti-2") {
		t.Fatalf("blacklist jtis = %v, want both JTIs delivered", h.blacklist.jtis)
	}
}

// Disabling the built-in client is an unrecoverable lockout: session
// .findInternalClient resolves it through an is_active filter, so login, refresh
// and registration all fail afterwards — including for the administrator who would
// undo it — and the same call revokes every internal session token. Rewriting its
// redirect_uris would redirect first-party authorization codes elsewhere. Both must
// be refused, and neither may reach the repository.
func TestUpdateClientRefusesToBreakTheBuiltinClient(t *testing.T) {
	disabled := false
	for _, test := range []struct {
		name  string
		input UpdateClientInput
	}{
		{
			name:  "disable",
			input: UpdateClientInput{ClientPK: 1, IsActive: &disabled, AdminUserID: 99},
		},
		{
			name: "rewrite redirect_uris",
			input: UpdateClientInput{
				ClientPK:     1,
				RedirectURIs: &[]string{"https://attacker.test/cb"},
				AdminUserID:  99,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			h.clients.findResult = protectedClient(1)

			_, err := h.service.UpdateClient(context.Background(), test.input)

			assertKind(t, err, KindProtected)
			if h.clients.updateCalls != 0 {
				t.Fatalf("update reached the repository %d times, want 0", h.clients.updateCalls)
			}
			// The refusal is audited: an attempt to disable authentication for everyone is
			// exactly what an operator needs to see afterwards.
			if len(h.audit.entries) != 1 || h.audit.entries[0].Success == nil || *h.audit.entries[0].Success {
				t.Fatalf("audit entries = %+v, want one failed entry", h.audit.entries)
			}
		})
	}
}

// The guard keys on client_id, not the primary key, so ordinary clients are
// untouched — and renaming the built-in one is still allowed, since client_name is
// cosmetic.
func TestUpdateClientGuardIsScopedToTheBuiltinClient(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = activeClient(5)
	disabled := false

	if _, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 5, IsActive: &disabled, AdminUserID: 99,
	}); err != nil {
		t.Fatalf("disabling an ordinary client failed: %v", err)
	}

	renamed := newHarness(t)
	renamed.clients.findResult = protectedClient(1)
	name := "SAST Link Web (renamed)"
	if _, err := renamed.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 1, ClientName: &name, AdminUserID: 99,
	}); err != nil {
		t.Fatalf("renaming the built-in client failed: %v", err)
	}
}

// Registry changes are audited with the acting credential too, so a client created
// by the ops tool is distinguishable from one an administrator registered by hand.
func TestClientAuditRecordsTheActingClient(t *testing.T) {
	const delegated = "sast-people-admin"
	for _, test := range []struct {
		name  string
		actor string
		want  string
	}{
		{name: "delegated client", actor: delegated, want: delegated},
		// An empty azp is the console; ProtectedClientID doubles as its identity.
		{name: "console session", actor: "", want: testProtectedClientID},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			input := validCreateInput()
			input.ActorClientID = test.actor

			if _, err := h.service.CreateClient(context.Background(), input); err != nil {
				t.Fatalf("CreateClient() error = %v", err)
			}
			if len(h.audit.entries) != 1 {
				t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
			}
			actor := h.audit.entries[0].ActorClientID
			if actor == nil || *actor != test.want {
				t.Fatalf("actor client id = %v, want %q", actor, test.want)
			}
		})
	}
}

// The update door must refuse everything the create door refuses, and it has to
// decide on the MERGED registration rather than on the submitted fields. A guard that
// only inspected the request would be bypassable by splitting a change in two.
func TestUpdateClientAdminScopeGuards(t *testing.T) {
	adminScopes := []string{"openid", scope.AdminWrite}
	refreshGrants := []string{"authorization_code", "refresh_token"}
	otherURIs := []string{"https://ops.test/cb"}
	openIDOnly := []string{"openid"}

	for _, testCase := range []struct {
		name     string
		current  *model.OAuthClient
		input    UpdateClientInput
		wantKind Kind
	}{
		{
			name:    "granting to a first_party client is refused",
			current: firstPartyClient(5),
			// client_type is absent from UpdateClientInput by design, so the guard has to read
			// it from the stored row.
			input:    UpdateClientInput{ClientPK: 5, Scope: &adminScopes, AdminUserID: 99},
			wantKind: KindInvalidInput,
		},
		{
			name:     "granting alongside a refresh grant is refused",
			current:  activeClient(5),
			input:    UpdateClientInput{ClientPK: 5, Scope: &adminScopes, GrantTypes: &refreshGrants, AdminUserID: 99},
			wantKind: KindInvalidInput,
		},
		{
			// This is the split-request bypass. The client already holds admin scope, so a
			// request naming only grant_types would slip past any input-only check — and
			// tokenissue has already minted refresh halves for it, which adding the grant
			// type would bring to life.
			name:     "adding refresh_token to an already delegated client is refused",
			current:  delegatedClient(5),
			input:    UpdateClientInput{ClientPK: 5, GrantTypes: &refreshGrants, AdminUserID: 99},
			wantKind: KindProtected,
		},
		{
			name:     "a delegated actor may not grant admin scope",
			current:  activeClient(5),
			input:    UpdateClientInput{ClientPK: 5, Scope: &adminScopes, AdminUserID: 99, ActorClientID: "sast-people-admin"},
			wantKind: KindProtected,
		},
		{
			name:     "a delegated actor may not edit a delegated client at all",
			current:  delegatedClient(5),
			input:    UpdateClientInput{ClientPK: 5, IsActive: boolPointer(true), AdminUserID: 99, ActorClientID: "sast-people-admin"},
			wantKind: KindProtected,
		},
		{
			// Granting and repointing in one request would collapse two things worth reading
			// separately into a single audit row.
			name:     "granting while rewriting redirect_uris is refused",
			current:  activeClient(5),
			input:    UpdateClientInput{ClientPK: 5, Scope: &adminScopes, RedirectURIs: &otherURIs, AdminUserID: 99},
			wantKind: KindInvalidInput,
		},
		{
			// The built-in client's scopes are asserted at startup, so editing them here is a
			// delayed refusal to boot, recoverable only through the database.
			name:     "the built-in client's scopes are immutable",
			current:  protectedClient(5),
			input:    UpdateClientInput{ClientPK: 5, Scope: &openIDOnly, AdminUserID: 99},
			wantKind: KindProtected,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.clients.findResult = testCase.current

			_, err := h.service.UpdateClient(context.Background(), testCase.input)
			assertKind(t, err, testCase.wantKind)
			if h.clients.updateCalls != 0 {
				t.Fatalf("update reached the repository %d times, want 0", h.clients.updateCalls)
			}
		})
	}
}

// Granting delegated administration revokes the target's existing tokens, and so does
// narrowing any client's scopes. Both are "the capability changed, credentials
// asserting the old one must stop working now" — the same reasoning as disabling.
func TestUpdateClientRevokesOnCapabilityChange(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		current    *model.OAuthClient
		scopes     []string
		wantRevoke bool
	}{
		{
			// A promoted client already has refresh families in the database; cutting them
			// forces a fresh authorization under the new scope set.
			name: "granting admin scope revokes", current: activeClient(5),
			scopes: []string{"openid", scope.AdminWrite}, wantRevoke: true,
		},
		{
			// An access token carries the scope it was signed with, so without this the
			// narrowed registration leaves credentials asserting a revoked capability.
			name: "narrowing revokes", current: delegatedClient(5),
			scopes: []string{"openid"}, wantRevoke: true,
		},
		{
			// Widening must not revoke: existing tokens do not gain the new scope, so cutting
			// them would log users out for a change that grants them nothing.
			name: "widening does not revoke", current: activeClient(5),
			scopes: []string{"openid", "profile", "email"}, wantRevoke: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHarness(t)
			h.clients.findResult = testCase.current

			if _, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
				ClientPK: 5, Scope: &testCase.scopes, AdminUserID: 99,
			}); err != nil {
				t.Fatalf("UpdateClient() error = %v", err)
			}
			if h.clients.updateFields == nil {
				t.Fatal("no fields were written")
			}
			if h.clients.updateRevoked != testCase.wantRevoke {
				t.Fatalf("revokeTokens = %v, want %v", h.clients.updateRevoked, testCase.wantRevoke)
			}
		})
	}
}

// The delegated client's redirect_uris are as sensitive as the built-in client's: an
// administrative authorization code sent to an operator-chosen host is the whole
// grant, handed over.
func TestUpdateClientRefusesRewritingDelegatedRedirectURIs(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(7)

	_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK:     7,
		RedirectURIs: &[]string{"https://attacker.test/cb"},
		AdminUserID:  99,
	})

	assertKind(t, err, KindProtected)
	if h.clients.updateCalls != 0 {
		t.Fatalf("update reached the repository %d times, want 0", h.clients.updateCalls)
	}
}

// Disabling it, unlike the built-in client, must work: it is the kill switch for
// delegated administration, and nothing about running this service depends on the
// ops tool. Renaming stays cosmetic and allowed.
func TestUpdateClientAllowsDisablingAndRenamingDelegatedClient(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = delegatedClient(7)
	disabled := false

	if _, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 7, IsActive: &disabled, AdminUserID: 99,
	}); err != nil {
		t.Fatalf("disabling the delegated client failed: %v", err)
	}

	renamed := newHarness(t)
	renamed.clients.findResult = delegatedClient(7)
	name := "SAST People (ops)"
	if _, err := renamed.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 7, ClientName: &name, AdminUserID: 99,
	}); err != nil {
		t.Fatalf("renaming the delegated client failed: %v", err)
	}
}

// A missing client must still leave an audit trail, or walking primary keys to
// discover which ones exist is invisible afterwards.
func TestUpdateClientAuditsUnknownClient(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = nil
	name := "whatever"

	_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 999999, ClientName: &name, AdminUserID: 99,
	})

	assertKind(t, err, KindNotFound)
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1 for a probed primary key", len(h.audit.entries))
	}
}

// Revocation follows the true -> false transition, not the submitted value.
// Re-sending is_active=false for an already disabled client must not re-revoke.
func TestUpdateClientDoesNotRevokeWhenAlreadyDisabled(t *testing.T) {
	h := newHarness(t)
	inactive := activeClient(5)
	disabled := false
	inactive.IsActive = &disabled
	h.clients.findResult = inactive

	result, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 5, IsActive: &disabled, AdminUserID: 99,
	})
	if err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}
	if h.clients.updateRevoked || result.RevokedTokens != 0 {
		t.Fatalf("revoked = %v, count = %d; want no revocation for an already disabled client",
			h.clients.updateRevoked, result.RevokedTokens)
	}
}

// Enabling a client, or renaming one, must not revoke anything.
func TestUpdateClientEnablingAndRenamingDoNotRevoke(t *testing.T) {
	for _, test := range []struct {
		name  string
		input UpdateClientInput
	}{
		{"enable", UpdateClientInput{ClientPK: 5, IsActive: boolPtr(true), AdminUserID: 99}},
		{"rename", UpdateClientInput{ClientPK: 5, ClientName: stringPtr("Renamed"), AdminUserID: 99}},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			h.clients.findResult = activeClient(5)

			result, err := h.service.UpdateClient(context.Background(), test.input)
			if err != nil {
				t.Fatalf("UpdateClient() error = %v", err)
			}
			if h.clients.updateRevoked || result.RevokedTokens != 0 {
				t.Fatalf("revoked = %v for %s, want no revocation", h.clients.updateRevoked, test.name)
			}
		})
	}
}

// A partial update must touch only the submitted columns; anything else would
// overwrite a property the administrator never mentioned.
func TestUpdateClientAppliesOnlySubmittedFields(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = activeClient(5)

	if _, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 5, ClientName: stringPtr("New Name"), AdminUserID: 99,
	}); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}
	if len(h.clients.updateFields) != 1 || h.clients.updateFields["client_name"] != "New Name" {
		t.Fatalf("update fields = %v, want only client_name", h.clients.updateFields)
	}
}

func TestUpdateClientRejectsEmptyUpdateAndMissingClient(t *testing.T) {
	t.Run("no fields", func(t *testing.T) {
		h := newHarness(t)
		h.clients.findResult = activeClient(5)
		_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{ClientPK: 5, AdminUserID: 99})
		assertKind(t, err, KindInvalidInput)
		if h.clients.updateCalls != 0 {
			t.Fatal("an empty update reached the repository")
		}
	})
	t.Run("missing client", func(t *testing.T) {
		h := newHarness(t)
		h.clients.findErr = repository.ErrNotFound
		_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
			ClientPK: 404, ClientName: stringPtr("X"), AdminUserID: 99,
		})
		assertKind(t, err, KindNotFound)
	})
	t.Run("non-positive id", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
			ClientPK: 0, ClientName: stringPtr("X"), AdminUserID: 99,
		})
		assertKind(t, err, KindNotFound)
	})
}

// The update must also reject an invalid redirect list, or an existing client could
// be repointed at a dangerous callback that registration would have refused.
func TestUpdateClientValidatesRedirectURIs(t *testing.T) {
	h := newHarness(t)
	h.clients.findResult = activeClient(5)
	uris := []string{"javascript:alert(1)"}

	_, err := h.service.UpdateClient(context.Background(), UpdateClientInput{
		ClientPK: 5, RedirectURIs: &uris, AdminUserID: 99,
	})
	assertKind(t, err, KindInvalidInput)
	if h.clients.updateCalls != 0 {
		t.Fatal("a javascript: redirect URI reached the repository")
	}
}

func TestListClientsMapsRowsWithoutSecrets(t *testing.T) {
	h := newHarness(t)
	hash := "sha256-v1$abc"
	stored := activeClient(1)
	stored.ClientSecretHash = &hash
	h.clients.listed = []model.OAuthClient{*stored}

	clients, err := h.service.ListClients(context.Background())
	if err != nil {
		t.Fatalf("ListClients() error = %v", err)
	}
	if len(clients) != 1 || clients[0].ClientID != "existing-client" || !clients[0].IsActive {
		t.Fatalf("clients = %+v, want the mapped active client", clients)
	}
}

func TestListClientsWrapsRepositoryFailure(t *testing.T) {
	h := newHarness(t)
	h.clients.listErr = errors.New("db down")

	_, err := h.service.ListClients(context.Background())
	assertKind(t, err, KindInternal)
}

// The plaintext secret must never reach the audit trail: audit rows are long-lived
// and broadly readable, which is exactly what storing only a hash guards against.
func TestCreateClientAuditOmitsSecret(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.CreateClient(context.Background(), validCreateInput())
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if len(h.audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(h.audit.entries))
	}
	detail := string(h.audit.entries[0].Detail)
	if result.ClientSecret != "" && strings.Contains(detail, result.ClientSecret) {
		t.Fatalf("audit detail %q contains the client secret", detail)
	}
	if h.audit.entries[0].Action != actionCreateClient {
		t.Fatalf("audit action = %q, want %q", h.audit.entries[0].Action, actionCreateClient)
	}
}

func boolPtr(value bool) *bool { return &value }

func stringPtr(value string) *string { return &value }
