package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestUserRepositoryCreateWithProfileIsAtomic(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := testUser("atomic@njupt.edu.cn")
	profile := &model.Profile{}
	if err := userRepository.CreateWithProfile(context.Background(), user, profile); err != nil {
		t.Fatalf("CreateWithProfile() error = %v", err)
	}
	if user.ID == 0 || profile.ID == 0 || profile.UserID != user.ID {
		t.Fatalf("created user/profile = %#v/%#v, want linked records", user, profile)
	}

	duplicate := testUser("atomic@njupt.edu.cn")
	duplicateProfile := &model.Profile{}
	if err := userRepository.CreateWithProfile(context.Background(), duplicate, duplicateProfile); err == nil {
		t.Fatal("CreateWithProfile() duplicate login_email error = nil")
	}
	var profileCount int64
	if err := database.Model(&model.Profile{}).Count(&profileCount).Error; err != nil {
		t.Fatalf("count profiles: %v", err)
	}
	if profileCount != 1 {
		t.Fatalf("profile count = %d, want 1 after failed transaction", profileCount)
	}
}

func TestUserRepositoryCreateRegistrationRollsBackWhenPairFactoryFails(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := testUser("registration-rollback@njupt.edu.cn")
	profile := &model.Profile{}

	err := userRepository.CreateRegistration(context.Background(), user, profile, func(*model.User) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error) {
		return nil, nil, errors.New("signing failed")
	})
	if err == nil {
		t.Fatal("CreateRegistration() error = nil")
	}
	var userCount, profileCount int64
	if queryErr := database.Model(&model.User{}).Where("login_email = ?", "registration-rollback@njupt.edu.cn").Count(&userCount).Error; queryErr != nil {
		t.Fatalf("count users: %v", queryErr)
	}
	if queryErr := database.Model(&model.Profile{}).Count(&profileCount).Error; queryErr != nil {
		t.Fatalf("count profiles: %v", queryErr)
	}
	if userCount != 0 || profileCount != 0 {
		t.Fatalf("rollback counts = user %d profile %d, want 0/0", userCount, profileCount)
	}
}

func TestUserRepositoryCreateWithProfileRejectsNilInputs(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := testUser("nil-profile@njupt.edu.cn")
	if err := userRepository.CreateWithProfile(context.Background(), user, nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("CreateWithProfile(user, nil) error = %v, want ErrInvalidArgument", err)
	}
	var userCount int64
	if err := database.Model(&model.User{}).Where("login_email = ?", user.LoginEmail).Count(&userCount).Error; err != nil {
		t.Fatalf("count user after nil profile: %v", err)
	}
	if userCount != 0 || user.ID != 0 {
		t.Fatalf("nil-profile user count/ID = %d/%d, want 0/0", userCount, user.ID)
	}

	profile := &model.Profile{}
	if err := userRepository.CreateWithProfile(context.Background(), nil, profile); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("CreateWithProfile(nil, profile) error = %v, want ErrInvalidArgument", err)
	}
	if profile.ID != 0 || profile.UserID != 0 {
		t.Fatalf("profile after nil user = %#v, want unmodified", profile)
	}
}

func TestUserRepositoryFindAuthUserByLoginIdentifier(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "primary@njupt.edu.cn")
	for _, identity := range []model.Identity{
		{UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "other@example.test"},
		{UserID: user.ID, Provider: model.LoginMethodGitHub, ProviderID: "github@example.test"},
		{UserID: user.ID, Provider: model.LoginMethodLark, ProviderID: "lark@example.test"},
	} {
		if err := database.Create(&identity).Error; err != nil {
			t.Fatalf("create %s identity: %v", identity.Provider, err)
		}
	}

	// The lean login lookup resolves the login email or an other-mail identity,
	// returning only the scalar columns (no Profile/Identities preloads).
	for _, identifier := range []string{"primary@njupt.edu.cn", "other@example.test"} {
		found, err := userRepository.FindAuthUserByLoginIdentifier(context.Background(), identifier)
		if err != nil {
			t.Fatalf("FindAuthUserByLoginIdentifier(%q) error = %v", identifier, err)
		}
		if found.ID != user.ID || found.LoginEmail != user.LoginEmail {
			t.Fatalf("FindAuthUserByLoginIdentifier(%q) = %#v, want user %d's scalar fields", identifier, found, user.ID)
		}
	}
	for _, identifier := range []string{"github@example.test", "lark@example.test", "missing@example.test"} {
		_, err := userRepository.FindAuthUserByLoginIdentifier(context.Background(), identifier)
		if !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("FindAuthUserByLoginIdentifier(%q) error = %v, want ErrNotFound", identifier, err)
		}
	}

	found, err := userRepository.FindByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	assertLoadedUser(t, found, user.ID)
	_, err = userRepository.FindByID(context.Background(), user.ID+100)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindByID(absent) error = %v, want ErrNotFound", err)
	}

	updateErr := database.Model(&model.User{}).Where("id = ?", user.ID).Update("token_version", 7).Error
	if updateErr != nil {
		t.Fatalf("update token_version: %v", updateErr)
	}
	authState, err := userRepository.FindAuthStateByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("FindAuthStateByID() error = %v", err)
	}
	if authState.ID != user.ID || authState.State != model.UserStateNJUPTer || authState.TokenVersion != 7 {
		t.Fatalf("FindAuthStateByID() = %#v, want ID/state/token_version", authState)
	}
	_, err = userRepository.FindAuthStateByID(context.Background(), user.ID+100)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAuthStateByID(absent) error = %v, want ErrNotFound", err)
	}
}

// FindAuthUserByLoginIdentifier must match the same identifiers as
// FindByLoginIdentifier but skip the Profile/Identities preloads: the login
// response serializes only scalar user fields, so loading the associations is
// pure waste.
func TestUserRepositoryFindAuthUserByLoginIdentifierSkipsPreloads(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "lean@njupt.edu.cn")
	if err := database.Create(&model.Identity{
		UserID: user.ID, Provider: model.LoginMethodOtherMail, ProviderID: "lean-other@example.test",
	}).Error; err != nil {
		t.Fatalf("create other_mail identity: %v", err)
	}

	for _, identifier := range []string{"lean@njupt.edu.cn", "lean-other@example.test"} {
		found, err := userRepository.FindAuthUserByLoginIdentifier(context.Background(), identifier)
		if err != nil {
			t.Fatalf("FindAuthUserByLoginIdentifier(%q) error = %v", identifier, err)
		}
		if found.ID != user.ID || found.LoginEmail != "lean@njupt.edu.cn" {
			t.Fatalf("FindAuthUserByLoginIdentifier(%q) = %#v, want user %d", identifier, found, user.ID)
		}
		if found.Profile != nil {
			t.Fatal("lean lookup must not preload Profile")
		}
		if len(found.Identities) != 0 {
			t.Fatal("lean lookup must not preload Identities")
		}
	}
	if _, err := userRepository.FindAuthUserByLoginIdentifier(context.Background(), "github@example.test"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAuthUserByLoginIdentifier(non-login identity) error = %v, want ErrNotFound", err)
	}
	if _, err := userRepository.FindAuthUserByLoginIdentifier(context.Background(), "missing@example.test"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAuthUserByLoginIdentifier(absent) error = %v, want ErrNotFound", err)
	}
}

func TestUserRepositoryFindAuthUserByLoginEmailAndExistenceChecks(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "lookup@njupt.edu.cn")

	found, err := userRepository.FindAuthUserByLoginEmail(context.Background(), "lookup@njupt.edu.cn")
	if err != nil {
		t.Fatalf("FindAuthUserByLoginEmail() error = %v", err)
	}
	if found.ID != user.ID || found.LoginEmail != user.LoginEmail {
		t.Fatalf("FindAuthUserByLoginEmail() = %#v, want user %d's scalar fields", found, user.ID)
	}

	// FindAuthUserByLoginEmail must not resolve other-mail identities: password
	// reset targets the login email only.
	identityRepository := repository.NewIdentity(database)
	if err := identityRepository.CreateWithinLimit(context.Background(), &model.Identity{
		UserID:     user.ID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: "alias@qq.com",
	}, 2); err != nil {
		t.Fatalf("CreateWithinLimit() error = %v", err)
	}
	if _, err := userRepository.FindAuthUserByLoginEmail(context.Background(), "alias@qq.com"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("FindAuthUserByLoginEmail(other mail) error = %v, want ErrNotFound", err)
	}

	for _, test := range []struct {
		name  string
		check func() (bool, error)
		want  bool
	}{
		{"login email present", func() (bool, error) {
			return userRepository.ExistsByLoginEmail(context.Background(), "lookup@njupt.edu.cn")
		}, true},
		{"login email absent", func() (bool, error) {
			return userRepository.ExistsByLoginEmail(context.Background(), "nobody@njupt.edu.cn")
		}, false},
		{"student id present", func() (bool, error) {
			return userRepository.ExistsByStudentID(context.Background(), user.StudentID)
		}, true},
		{"student id absent", func() (bool, error) {
			return userRepository.ExistsByStudentID(context.Background(), "B0000000000")
		}, false},
	} {
		got, err := test.check()
		if err != nil {
			t.Fatalf("%s: error = %v", test.name, err)
		}
		if got != test.want {
			t.Fatalf("%s = %t, want %t", test.name, got, test.want)
		}
	}
}

// ExistsAsEmailAnywhere is the cross-table uniqueness guard: an address that
// lives in either "user".login_email or identities.provider_id (other_mail)
// must be reported, otherwise Register could capture an address someone else
// already uses for login and silently hijack their identifier.
func TestUserRepositoryExistsAsEmailAnywhere(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "anywhere@njupt.edu.cn")

	identityRepository := repository.NewIdentity(database)
	if err := identityRepository.CreateWithinLimit(context.Background(), &model.Identity{
		UserID:     user.ID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: "anywhere-bound@qq.com",
	}, 2); err != nil {
		t.Fatalf("CreateWithinLimit() error = %v", err)
	}

	for _, test := range []struct {
		email string
		want  bool
	}{
		{"anywhere@njupt.edu.cn", true},
		{"anywhere-bound@qq.com", true},
		{"free@sast.fun", false},
	} {
		got, err := userRepository.ExistsAsEmailAnywhere(context.Background(), test.email)
		if err != nil {
			t.Fatalf("ExistsAsEmailAnywhere(%q) error = %v", test.email, err)
		}
		if got != test.want {
			t.Fatalf("ExistsAsEmailAnywhere(%q) = %t, want %t", test.email, got, test.want)
		}
	}
}

// The password rewrite, the token_version bump and the session revocation must
// commit together: token_version alone does not stop refresh tokens, because the
// refresh flow never compares it.
func TestUserRepositoryUpdatePasswordAndRevokeSessions(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	tokenRepository := repository.NewToken(database)
	user := createUserWithProfile(t, userRepository, "rotate@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokenRepository, "rotate-live", "family-rotate", 0, client.ID, user.ID)

	revokedAt := time.Now().UTC().Truncate(time.Millisecond)
	entries, err := userRepository.UpdatePasswordAndRevokeSessions(context.Background(), user.ID, "new-hash", revokedAt)
	if err != nil {
		t.Fatalf("UpdatePasswordAndRevokeSessions() error = %v", err)
	}
	if len(entries) != 1 || entries[0].TokenID != "rotate-live-access" {
		t.Fatalf("entries = %#v, want the live access token", entries)
	}

	var stored model.User
	if err := database.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if stored.PasswordHash != "new-hash" {
		t.Fatalf("password = %q, want new-hash", stored.PasswordHash)
	}
	if stored.TokenVersion != user.TokenVersion+1 {
		t.Fatalf("token_version = %d, want %d", stored.TokenVersion, user.TokenVersion+1)
	}
	assertTokenRevokedAt(t, database, "rotate-live-access", "rotate-live-refresh", revokedAt)

	var outboxCount int64
	if err := database.Model(&model.TokenBlacklistOutbox{}).
		Where("token_id = ?", "rotate-live-access").
		Count(&outboxCount).Error; err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if outboxCount != 1 {
		t.Fatalf("outbox rows = %d, want 1", outboxCount)
	}
}

// The rehash-on-login write is guarded on the hash the login verified, so a
// concurrent password change/reset cannot have its new hash reverted by a stale
// rehash of the old password. A matching currentHash lands the rehash; a stale
// one is skipped (ErrRehashSkipped) and the newer hash survives.
func TestUserRepositoryUpdatePasswordHashGuarded(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "rehash@njupt.edu.cn")

	if err := userRepository.UpdatePasswordHash(context.Background(), user.ID, user.PasswordHash, "new-hash"); err != nil {
		t.Fatalf("UpdatePasswordHash(matching) error = %v", err)
	}
	var stored model.User
	if err := database.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if stored.PasswordHash != "new-hash" {
		t.Fatalf("password = %q, want new-hash", stored.PasswordHash)
	}
	if stored.TokenVersion != user.TokenVersion {
		t.Fatalf("token_version = %d, want %d (rehash must not bump it)", stored.TokenVersion, user.TokenVersion)
	}

	if err := userRepository.UpdatePasswordHash(context.Background(), user.ID, "obsolete-hash", "reverted-hash"); err != repository.ErrRehashSkipped {
		t.Fatalf("UpdatePasswordHash(stale) error = %v, want ErrRehashSkipped", err)
	}
	if err := database.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if stored.PasswordHash != "new-hash" {
		t.Fatalf("password = %q, want new-hash preserved (stale rehash must not land)", stored.PasswordHash)
	}
}

// Only live tokens need blacklist delivery; already-expired ones fall out of the
// entry set even though the row is still revoked.
func TestUserRepositoryUpdatePasswordSkipsExpiredTokens(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	tokenRepository := repository.NewToken(database)
	user := createUserWithProfile(t, userRepository, "expired@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokenRepository, "expired", "family-expired", 0, client.ID, user.ID)

	// Move the revocation clock past the token's one-hour expiry. Truncate to
	// milliseconds so the value survives PostgreSQL's microsecond precision.
	revokedAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Millisecond)
	entries, err := userRepository.UpdatePasswordAndRevokeSessions(context.Background(), user.ID, "another-hash", revokedAt)
	if err != nil {
		t.Fatalf("UpdatePasswordAndRevokeSessions() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %#v, want none for expired tokens", entries)
	}
	assertTokenRevokedAt(t, database, "expired-access", "expired-refresh", revokedAt)
}

func TestTokenRepositoryRevokeAllByUserLeavesOtherUsersAlone(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	tokenRepository := repository.NewToken(database)
	target := createUserWithProfile(t, userRepository, "target@njupt.edu.cn")
	bystander := createUserWithProfile(t, userRepository, "bystander@njupt.edu.cn")
	client := createOAuthClient(t, database)
	createTokenPair(t, tokenRepository, "target", "family-target", 0, client.ID, target.ID)
	createTokenPair(t, tokenRepository, "bystander", "family-bystander", 0, client.ID, bystander.ID)

	revokedAt := time.Now().UTC().Truncate(time.Millisecond)
	entries, err := tokenRepository.RevokeAllByUser(context.Background(), target.ID, revokedAt)
	if err != nil {
		t.Fatalf("RevokeAllByUser() error = %v", err)
	}
	if len(entries) != 1 || entries[0].TokenID != "target-access" {
		t.Fatalf("entries = %#v, want only the target's access token", entries)
	}
	assertTokenRevokedAt(t, database, "target-access", "target-refresh", revokedAt)
	assertTokenUnrevoked(t, database, "bystander-access", "bystander-refresh")
}

// The session service dispatches duplicate-registration errors on the unique
// constraint's name to tell a student-ID clash from an email clash. Those names
// are PostgreSQL defaults rather than anything the code declares, so pin them
// here: a rename in a future migration would silently break that mapping and
// send users to the wrong field.
func TestUserRepositoryUniqueViolationConstraintNames(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	existing := createUserWithProfile(t, userRepository, "pinned@njupt.edu.cn")

	tests := []struct {
		name           string
		build          func() *model.User
		wantConstraint string
	}{
		{
			name: "login email",
			build: func() *model.User {
				user := testUser("pinned@njupt.edu.cn")
				user.StudentID = "B90000001"
				return user
			},
			wantConstraint: "user_login_email_key",
		},
		{
			name: "student id",
			build: func() *model.User {
				user := testUser("fresh@njupt.edu.cn")
				user.StudentID = existing.StudentID
				return user
			},
			wantConstraint: "user_student_id_key",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := userRepository.CreateWithProfile(context.Background(), test.build(), &model.Profile{})
			if err == nil {
				t.Fatal("CreateWithProfile() error = nil, want a unique violation")
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("error = %v, want a *pgconn.PgError", err)
			}
			if pgErr.Code != pgerrcode.UniqueViolation {
				t.Fatalf("SQLSTATE = %q, want %q", pgErr.Code, pgerrcode.UniqueViolation)
			}
			if pgErr.ConstraintName != test.wantConstraint {
				t.Fatalf("constraint = %q, want %q; update the session service mapping if this was renamed deliberately",
					pgErr.ConstraintName, test.wantConstraint)
			}
		})
	}
}

// A login email must never also exist as an other_mail identity. The service
// checks this before inserting, but the two columns are unique only within their
// own table, so nothing but a cross-table rule can make the invariant hold.
func TestLoginEmailCannotBeBoundAsIdentity(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	const contested = "contested@njupt.edu.cn"
	owner := createUserWithProfile(t, userRepository, contested)

	err := database.WithContext(context.Background()).Create(&model.Identity{
		UserID:     owner.ID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: contested,
	}).Error
	if err == nil {
		t.Fatal("Create(identity) error = nil, want the login email to be rejected")
	}
	assertUniqueViolation(t, err, "ck_identities_provider_id_not_login_email")

	// A different provider is unaffected: only other_mail shares an address space
	// with login_email.
	if githubErr := database.WithContext(context.Background()).Create(&model.Identity{
		UserID:     owner.ID,
		Provider:   model.LoginMethodGitHub,
		ProviderID: contested,
	}).Error; githubErr != nil {
		t.Fatalf("Create(github identity) error = %v, want the rule to apply only to other_mail", githubErr)
	}
}

// The rule holds from the other direction too, so an address cannot be bound
// first and then claimed as a login email.
func TestBoundIdentityCannotBecomeLoginEmail(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	const bound = "bound@njupt.edu.cn"
	holder := createUserWithProfile(t, userRepository, "holder@njupt.edu.cn")

	if err := database.WithContext(context.Background()).Create(&model.Identity{
		UserID:     holder.ID,
		Provider:   model.LoginMethodOtherMail,
		ProviderID: bound,
	}).Error; err != nil {
		t.Fatalf("Create(identity) error = %v", err)
	}

	newcomer := testUser(bound)
	newcomer.StudentID = "B55550001"
	err := userRepository.CreateWithProfile(context.Background(), newcomer, &model.Profile{})
	if err == nil {
		t.Fatal("CreateWithProfile() error = nil, want the bound address to be rejected")
	}
	assertUniqueViolation(t, err, "ck_user_login_email_not_identity")
}

// The pre-flight check in the service cannot close this race: both transactions
// read before either commits, and neither row exists to lock. Only serializing on
// the address itself keeps the address out of both tables.
func TestConcurrentRegisterAndBindCannotShareAnAddress(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	const contested = "raced@njupt.edu.cn"
	holder := createUserWithProfile(t, userRepository, "holder@njupt.edu.cn")

	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		<-start
		user := testUser(contested)
		user.StudentID = "B77770001"
		_ = userRepository.CreateWithProfile(context.Background(), user, &model.Profile{})
	}()
	go func() {
		defer waitGroup.Done()
		<-start
		_ = database.WithContext(context.Background()).Create(&model.Identity{
			UserID:     holder.ID,
			Provider:   model.LoginMethodOtherMail,
			ProviderID: contested,
		}).Error
	}()
	close(start)
	waitGroup.Wait()

	var userRows, identityRows int64
	if err := database.Raw(`SELECT count(*) FROM "user" WHERE login_email = ?`, contested).
		Scan(&userRows).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := database.Raw(`SELECT count(*) FROM identities WHERE provider = ? AND provider_id = ?`,
		model.LoginMethodOtherMail, contested).Scan(&identityRows).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if userRows > 0 && identityRows > 0 {
		t.Fatalf("address landed in both tables: user rows=%d identity rows=%d", userRows, identityRows)
	}
	if userRows+identityRows == 0 {
		t.Fatal("both writers lost; exactly one should have succeeded")
	}
}

func assertUniqueViolation(t *testing.T, err error, wantConstraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("error = %v, want a *pgconn.PgError", err)
	}
	if pgErr.Code != pgerrcode.UniqueViolation {
		t.Fatalf("SQLSTATE = %q, want %q", pgErr.Code, pgerrcode.UniqueViolation)
	}
	if pgErr.ConstraintName != wantConstraint {
		t.Fatalf("constraint = %q, want %q", pgErr.ConstraintName, wantConstraint)
	}
}

// A password reset must also burn the user's unredeemed authorization codes, not
// only the tokens already minted.
//
// The token endpoint reads token_version fresh from the user row when it signs, so a
// code held across a reset would redeem into a session carrying the *new*
// token_version — one the auth middleware accepts. Revoking tokens while leaving the
// codes alive therefore leaves a hole exactly as wide as the code TTL, in the one
// flow (reset after suspected compromise) where that matters most.
func TestUserRepositoryUpdatePasswordBurnsAuthorizationCodes(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)
	user := createUserWithProfile(t, userRepository, "burn-codes@njupt.edu.cn")
	other := createUserWithProfile(t, userRepository, "other-codes@njupt.edu.cn")
	client := createOAuthClient(t, database)
	authorizations := repository.NewOAuthAuthorization(database)

	live := testAuthorization("code-live", client.ID, user.ID, time.Now().Add(5*time.Minute))
	untouched := testAuthorization("code-other-user", client.ID, other.ID, time.Now().Add(5*time.Minute))
	for _, authorization := range []*model.OAuthAuthorization{live, untouched} {
		if err := authorizations.CreateWithGrant(context.Background(), authorization); err != nil {
			t.Fatalf("CreateWithGrant(%s) error = %v", authorization.Code, err)
		}
	}

	revokedAt := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := userRepository.UpdatePasswordAndRevokeSessions(
		context.Background(), user.ID, "new-hash", revokedAt,
	); err != nil {
		t.Fatalf("UpdatePasswordAndRevokeSessions() error = %v", err)
	}

	// The victim's code is spent, so redeeming it now reports a replay rather than
	// minting a post-reset session.
	if _, _, err := authorizations.Consume(context.Background(), "code-live", revokedAt); !errors.Is(
		err, repository.ErrAuthorizationReplayed,
	) {
		t.Fatalf("Consume(code-live) error = %v, want ErrAuthorizationReplayed", err)
	}
	// Another user's pending authorization must survive: the reset is scoped to one
	// account, and burning everyone's codes would log out unrelated users mid-flow.
	if _, _, err := authorizations.Consume(context.Background(), "code-other-user", revokedAt); err != nil {
		t.Fatalf("Consume(code-other-user) error = %v, want the code to survive", err)
	}
}

// Reporting success for a user that does not exist would tell the caller
// "password changed, sessions revoked" while nothing happened.
func TestUserRepositoryUpdatePasswordAndRevokeSessionsReportsMissingUser(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	_, err := userRepository.UpdatePasswordAndRevokeSessions(context.Background(), 999999, "new-hash", time.Now())
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UpdatePasswordAndRevokeSessions(missing) error = %v, want ErrNotFound", err)
	}
}

// A provisioning transaction writes the user, its profile, and an other_mail
// binding in one commit, with each row linked to the same user id. Both
// identifiers are then resolvable for login: the login email and the bound address.
func TestUserRepositoryCreateAdminUserBindsOtherMailAtomically(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := testUser("admin-created@njupt.edu.cn")
	profile := &model.Profile{}
	identity := &model.Identity{
		Provider:   model.LoginMethodOtherMail,
		ProviderID: "member@example.com",
	}
	if err := userRepository.CreateAdminUser(context.Background(), user, profile, identity); err != nil {
		t.Fatalf("CreateAdminUser() error = %v", err)
	}
	if user.ID == 0 || profile.UserID != user.ID || identity.UserID != user.ID {
		t.Fatalf("linked ids = user %d profile %d identity %d, want profile and identity to follow the user",
			user.ID, profile.UserID, identity.UserID)
	}
	for identifier, wantID := range map[string]int64{
		user.LoginEmail: user.ID, "member@example.com": user.ID,
	} {
		found, err := userRepository.FindAuthUserByLoginIdentifier(context.Background(), identifier)
		if err != nil {
			t.Fatalf("FindAuthUserByLoginIdentifier(%q) error = %v", identifier, err)
		}
		if found.ID != wantID {
			t.Fatalf("identifier %q -> user %d, want %d", identifier, found.ID, wantID)
		}
	}
	var identityCount int64
	if err := database.Model(&model.Identity{}).
		Where("provider = ? AND provider_id = ?", model.LoginMethodOtherMail, "member@example.com").
		Count(&identityCount).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if identityCount != 1 {
		t.Fatalf("identity count = %d, want 1", identityCount)
	}
}

// Provisioning without a binding leaves the account with no identities: a plain
// provision is exactly the user + profile rows and nothing else.
func TestUserRepositoryCreateAdminUserWithoutIdentity(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := testUser("admin-plain@njupt.edu.cn")
	if err := userRepository.CreateAdminUser(context.Background(), user, &model.Profile{}, nil); err != nil {
		t.Fatalf("CreateAdminUser() error = %v", err)
	}
	if user.ID == 0 {
		t.Fatal("no user id assigned on a plain provision")
	}
	var identityCount int64
	if err := database.Model(&model.Identity{}).Where("user_id = ?", user.ID).Count(&identityCount).Error; err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if identityCount != 0 {
		t.Fatalf("identity count = %d, want 0 without a binding", identityCount)
	}
}

// V005 forbids an address serving as somebody's login email from also becoming an
// other_mail binding. The trigger aborting the identity insert must roll the whole
// provisioning transaction back: no user row and no profile for the attempted account.
func TestUserRepositoryCreateAdminUserRollsBackOnV005(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	existing := createUserWithProfile(t, userRepository, "occupant@njupt.edu.cn")
	user := testUser("admin-v005@njupt.edu.cn")
	profile := &model.Profile{}
	identity := &model.Identity{
		Provider:   model.LoginMethodOtherMail,
		ProviderID: existing.LoginEmail,
	}
	if err := userRepository.CreateAdminUser(context.Background(), user, profile, identity); err == nil {
		t.Fatal("CreateAdminUser() with a login_email identity collision error = nil")
	}
	var userCount, profileCount, identityCount int64
	if err := database.Model(&model.User{}).
		Where("login_email = ?", "admin-v005@njupt.edu.cn").Count(&userCount).Error; err != nil {
		t.Fatalf("count user rollback: %v", err)
	}
	if err := database.Model(&model.Profile{}).Where("user_id = ?", user.ID).Count(&profileCount).Error; err != nil {
		t.Fatalf("count profile rollback: %v", err)
	}
	if err := database.Model(&model.Identity{}).
		Where("provider = ? AND provider_id = ?", model.LoginMethodOtherMail, existing.LoginEmail).
		Count(&identityCount).Error; err != nil {
		t.Fatalf("count identity rollback: %v", err)
	}
	if userCount != 0 || profileCount != 0 || identityCount != 0 {
		t.Fatalf("rollback counts = user %d profile %d identity %d, want 0/0/0",
			userCount, profileCount, identityCount)
	}
}

// TestUserRepositoryExistsByStudentIDFoldsCase pins the folded occupancy guard:
// user.student_id's unique constraint is case-sensitive, so an existing
// b24040525 must still make a submission for B24040525 look occupied. Without
// this, a case-differing variant sails past the pre-submission check and, on
// the alumni channel, past the approval too (mistake the import once produced).
func TestUserRepositoryExistsByStudentIDFoldsCase(t *testing.T) {
	database := setupDatabase(t)
	userRepository := repository.NewUser(database)

	user := &model.User{
		Name:         "Folded Case User",
		PhoneNumber:  "13800138000",
		QQNumber:     "10000",
		PasswordHash: "password-hash",
		LoginEmail:   "folded-b24040525@njupt.edu.cn",
		StudentID:    "b24040525",
		Role:         model.UserRoleFreshman,
		State:        model.UserStateNJUPTer,
		College:      model.CollegeOther,
	}
	if err := database.Create(user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	for _, candidate := range []string{"b24040525", "B24040525", " b24040525"} {
		got, err := userRepository.ExistsByStudentID(context.Background(), candidate)
		if err != nil {
			t.Fatalf("ExistsByStudentID(%q) error = %v", candidate, err)
		}
		if !got {
			t.Fatalf("ExistsByStudentID(%q) = false, want true (occupied by b24040525)", candidate)
		}
	}
}

// TestAdminUserUpdateBindsPersonalEmail pins W2a: an administrative edit can
// bind an other_mail identity on an existing account in the same transaction —
// the rescue path for an alumnus whose school mailbox died before they bound
// anything. The V005 trigger and the unique index keep a bound address from
// colliding with a login email or a second binding, and the collision surfaces
// as a unique violation the service classifies by constraint name.
func TestAdminUserUpdateBindsPersonalEmail(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	ctx := context.Background()

	user := testUser("rescue-b20040208@njupt.edu.cn")
	if err := database.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("binds and survives a field-only empty columns path", func(t *testing.T) {
		email := "alumni.rescue@example.com"
		_, sessionsRevoked, err := users.UpdateAdminUser(ctx, user.ID,
			repository.AdminUserUpdate{PersonalEmail: &email}, time.Now().UTC())
		if err != nil {
			t.Fatalf("UpdateAdminUser(personal email only) error = %v", err)
		}
		if sessionsRevoked {
			t.Fatal("sessionsRevoked = true, want false: binding an email is not a session cut")
		}
		var count int64
		if err := database.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ? AND provider_id = ?",
				user.ID, model.LoginMethodOtherMail, email).
			Count(&count).Error; err != nil {
			t.Fatalf("count bound identity: %v", err)
		}
		if count != 1 {
			t.Fatalf("bound identity count = %d, want 1", count)
		}
	})

	t.Run("team-dev with a field change also binds", func(t *testing.T) {
		name := "Bound Name"
		email := "alumni.rescue2@example.com"
		_, _, err := users.UpdateAdminUser(ctx, user.ID, repository.AdminUserUpdate{
			Name:          &name,
			PersonalEmail: &email,
		}, time.Now().UTC())
		if err != nil {
			t.Fatalf("UpdateAdminUser(name + personal email) error = %v", err)
		}
		var count int64
		if err := database.Model(&model.Identity{}).
			Where("user_id = ? AND provider = ? AND provider_id = ?",
				user.ID, model.LoginMethodOtherMail, email).
			Count(&count).Error; err != nil {
			t.Fatalf("count second binding: %v", err)
		}
		if count != 1 {
			t.Fatalf("second binding count = %d, want 1", count)
		}
	})

	t.Run("a third bind reaches the per-account cap", func(t *testing.T) {
		// Two binds already landed above; the count check inside the transaction
		// must refuse a third with a classified error rather than the V001
		// trigger's unnamed P0001.
		third := "alumni.rescue3@example.com"
		_, _, err := users.UpdateAdminUser(ctx, user.ID,
			repository.AdminUserUpdate{PersonalEmail: &third}, time.Now().UTC())
		if !errors.Is(err, repository.ErrIdentityLimitExceeded) {
			t.Fatalf("third bind error = %v, want ErrIdentityLimitExceeded", err)
		}
	})

	t.Run("a repeated address collides with the unique index", func(t *testing.T) {
		// A fresh account with a single bind: the cap does not pre-empt, so the
		// unique index is what refuses the duplicate address. provider_id is
		// globally unique, so the address must not be in use anywhere yet.
		fresh := testUser("rescue-b20040209@njupt.edu.cn")
		if err := database.Create(fresh).Error; err != nil {
			t.Fatalf("create fresh user: %v", err)
		}
		email := "alumni.rescue.fresh@example.com"
		if _, _, err := users.UpdateAdminUser(ctx, fresh.ID,
			repository.AdminUserUpdate{PersonalEmail: &email}, time.Now().UTC()); err != nil {
			t.Fatalf("first bind on fresh user error = %v", err)
		}
		_, _, err := users.UpdateAdminUser(ctx, fresh.ID,
			repository.AdminUserUpdate{PersonalEmail: &email}, time.Now().UTC())
		if err == nil {
			t.Fatal("second bind of the same address error = nil")
		}
		if got := repository.DuplicateConstraint(err); got != "uq_identities_provider_provider_id" {
			t.Fatalf("error = %v; constraint = %q, want uq_identities_provider_provider_id", err, got)
		}
	})

	t.Run("an address that is someone's login email is refused by the V005 trigger", func(t *testing.T) {
		fresh := testUser("rescue-b20040210@njupt.edu.cn")
		if err := database.Create(fresh).Error; err != nil {
			t.Fatalf("create fresh user: %v", err)
		}
		_, _, err := users.UpdateAdminUser(ctx, fresh.ID,
			repository.AdminUserUpdate{PersonalEmail: &fresh.LoginEmail}, time.Now().UTC())
		if err == nil {
			t.Fatal("binding a login email error = nil")
		}
		if got := repository.DuplicateConstraint(err); got != "ck_identities_provider_id_not_login_email" {
			t.Fatalf("error = %v; constraint = %q, want ck_identities_provider_id_not_login_email", err, got)
		}
	})
}
