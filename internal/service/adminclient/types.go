package adminclient

import (
	"context"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// auditResource is the audit_logs.resource value for every action here.
const auditResource = "oauth_client"

// ClientRepository persists OAuth client registrations.
type ClientRepository interface {
	List(ctx context.Context) ([]model.OAuthClient, error)
	Create(ctx context.Context, client *model.OAuthClient) error
	// FindByID resolves a client regardless of active state, so the update path can
	// see the current is_active value.
	FindByID(ctx context.Context, id int64) (*model.OAuthClient, error)
	// UpdateAndRevoke applies fields and, when revokeTokens is set, revokes the
	// client's live tokens in the same transaction, returning the access-token
	// entries that still need revocation delivery.
	UpdateAndRevoke(
		ctx context.Context,
		id int64,
		fields map[string]any,
		revokeTokens bool,
		revokedAt time.Time,
	) ([]model.BlacklistEntry, error)
}

// TokenBlacklist invalidates the auth-state cache entries for revoked access
// tokens. Revocation is authoritative in PostgreSQL; this clears the short-TTL
// cache so the middleware's next request re-checks the database immediately.
type TokenBlacklist interface {
	DeleteAuthStates(ctx context.Context, jtis []string) error
}

// AuditRepository records audit events.
type AuditRepository interface {
	Create(ctx context.Context, entry *model.AuditLog) error
}

// CreateClientInput registers a new client. ClientID is not accepted from the
// caller: it is generated here, so nobody can register under a chosen identifier
// and impersonate an existing or future client.
type CreateClientInput struct {
	ClientName   string
	ClientType   string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	// AdminUserID is the authenticated administrator, for the audit trail.
	AdminUserID int64
	ClientIP    string
	UserAgent   string
}

// UpdateClientInput is a partial update. A nil field is left unchanged; the
// immutable properties (client_id, client_type, scopes, grant_types) are absent by
// construction rather than validated away, so this type cannot express a change to
// them.
type UpdateClientInput struct {
	ClientPK     int64
	ClientName   *string
	RedirectURIs *[]string
	IsActive     *bool
	AdminUserID  int64
	ClientIP     string
	UserAgent    string
}

// Client is one registration as reported to the console. It deliberately omits the
// secret hash: a DTO that has no such field cannot leak it, whereas a model with a
// json:"-" tag relies on that tag surviving every future edit.
type Client struct {
	ID           int64
	ClientID     string
	ClientName   string
	ClientType   string
	RedirectURIs []string
	GrantTypes   []string
	Scopes       []string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CreateClientResult carries the new registration plus, for a confidential client,
// the one and only plaintext copy of its secret.
type CreateClientResult struct {
	Client Client
	// ClientSecret is empty for a first_party (public) client, which uses PKCE and
	// has no secret. Returned once and never retrievable again: only its hash is
	// stored.
	ClientSecret string
}

// UpdateClientResult reports what the update did.
type UpdateClientResult struct {
	// RevokedTokens counts the access tokens revoked because the client was disabled.
	RevokedTokens int
}
