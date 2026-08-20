package oauthloginhandler

import (
	"encoding/json"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/validate"
)

// authResultDTO mirrors the session handler's login response, so a third-party
// login is indistinguishable from a password login to the client.
type authResultDTO struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    int         `json:"expires_in"`
	User         authUserDTO `json:"user"`
}

type authUserDTO struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	LoginEmail string    `json:"login_email"`
	Role       string    `json:"role"`
	State      string    `json:"state"`
	EmailType  string    `json:"email_type"`
	CreatedAt  time.Time `json:"created_at"`
	// ProfileNeedsCompletion and IncompleteFields carry the same meaning as in
	// sessionhandler: an account imported from the previous database still holds
	// values no current write path would accept, and the client routes it to the
	// completion page.
	//
	// This DTO is a separate type from sessionhandler's identically named one, and
	// this is the exit that matters most for the flag: the accounts carrying
	// migration debris are largely the ones that sign in through GitHub or Lark,
	// so omitting the fields here would leave exactly the target population
	// unable to see the prompt.
	ProfileNeedsCompletion bool     `json:"profile_needs_completion"`
	IncompleteFields       []string `json:"incomplete_fields"`
}

// identityBindDTO is the bind response envelope payload.
type identityBindDTO struct {
	Message  string      `json:"message"`
	Identity identityDTO `json:"identity"`
}

type identityDTO struct {
	ID             int64      `json:"id"`
	Provider       string     `json:"provider"`
	ProviderID     string     `json:"provider_id"`
	IdentityData   any        `json:"identity_data"`
	TokenExpiresAt *time.Time `json:"token_expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func mapUser(user *model.User) authUserDTO {
	if user == nil {
		return authUserDTO{}
	}
	fields := validate.IncompleteProfileFields(
		user.Name, user.PhoneNumber, user.Major, user.StudentID)
	if fields == nil {
		// Always an array in JSON, so a client can read .length unconditionally.
		fields = []string{}
	}
	return authUserDTO{
		ID:         user.ID,
		Name:       user.Name,
		LoginEmail: user.LoginEmail,
		Role:       string(user.Role),
		State:      string(user.State),
		EmailType:  string(user.EmailType),
		CreatedAt:  user.CreatedAt,

		ProfileNeedsCompletion: user.ProfileNeedsCompletion,
		IncompleteFields:       fields,
	}
}

func mapIdentity(identity model.Identity) identityDTO {
	return identityDTO{
		ID:             identity.ID,
		Provider:       string(identity.Provider),
		ProviderID:     identity.ProviderID,
		IdentityData:   decodeIdentityData(identity.IdentityData),
		TokenExpiresAt: identity.TokenExpiresAt,
		CreatedAt:      identity.CreatedAt,
		UpdatedAt:      identity.UpdatedAt,
	}
}

// decodeIdentityData turns the raw JSONB column into a value the response
// encoder emits as a JSON object rather than a base64 string.
//
// model.JSONB is []byte underneath, so handing it to the encoder directly would
// serialize it as base64. Invalid stored JSON yields nil instead of an error: the
// binding itself is valid, and failing the whole response over unreadable
// display metadata would be a worse outcome.
func decodeIdentityData(raw model.JSONB) any {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	return decoded
}
