package repository

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// UserRepository persists and retrieves user accounts.
type UserRepository struct {
	database *gorm.DB
}

// UserAuthState is the minimal user state needed for token authentication checks.
type UserAuthState struct {
	ID           int64
	State        model.UserState
	TokenVersion int
}

// TokenPairFactory builds the initial session after PostgreSQL has assigned the
// new user's ID. It must perform local work only; the caller invokes it while a
// registration transaction is open.
type TokenPairFactory func(user *model.User) (*model.OAuthAccessToken, *model.OAuthRefreshToken, error)

// NewUser constructs a UserRepository backed by database.
func NewUser(database *gorm.DB) *UserRepository {
	return &UserRepository{database: database}
}

// CreateWithProfile creates a user and its profile atomically.
func (r *UserRepository) CreateWithProfile(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
) error {
	if user == nil {
		return fmt.Errorf("%w: user is nil", ErrInvalidArgument)
	}
	if profile == nil {
		return fmt.Errorf("%w: profile is nil", ErrInvalidArgument)
	}

	return r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		profile.UserID = user.ID
		if err := transaction.Create(profile).Error; err != nil {
			return fmt.Errorf("create profile: %w", err)
		}
		return nil
	})
}

// CreateRegistration creates an account, its profile and its initial session in
// one PostgreSQL transaction. The factory runs after user.ID is assigned so the
// signed token subject and token metadata refer to the persisted account.
func (r *UserRepository) CreateRegistration(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
	pairFactory TokenPairFactory,
) error {
	if user == nil {
		return fmt.Errorf("%w: user is nil", ErrInvalidArgument)
	}
	if profile == nil {
		return fmt.Errorf("%w: profile is nil", ErrInvalidArgument)
	}
	if pairFactory == nil {
		return fmt.Errorf("%w: token pair factory is nil", ErrInvalidArgument)
	}

	return r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Create(user).Error; err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		profile.UserID = user.ID
		if err := transaction.Create(profile).Error; err != nil {
			return fmt.Errorf("create profile: %w", err)
		}

		access, refresh, err := pairFactory(user)
		if err != nil {
			return fmt.Errorf("build initial token pair: %w", err)
		}
		if err := createTokenPairInTransaction(transaction, access, refresh); err != nil {
			return fmt.Errorf("create initial token pair: %w", err)
		}
		return nil
	})
}

// FindByLoginIdentifier finds a password-login user by login email or other email identity.
func (r *UserRepository) FindByLoginIdentifier(
	ctx context.Context,
	identifier string,
) (*model.User, error) {
	var user model.User
	database := r.database.WithContext(ctx).Preload("Profile").Preload("Identities")

	err := database.Where("login_email = ?", identifier).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("find user by login email: %w", err)
	}

	err = r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		Joins("JOIN identities ON identities.user_id = \"user\".id").
		Where("identities.provider = ? AND identities.provider_id = ?", model.LoginMethodOtherMail, identifier).
		First(&user).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by other email identity: %w", err)
}

// FindByID finds a user and its profile and identities by primary key.
func (r *UserRepository) FindByID(ctx context.Context, userID int64) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		First(&user, userID).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by ID: %w", err)
}

// FindByLoginEmail finds a user by login email only (excludes other-mail identities).
func (r *UserRepository) FindByLoginEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		Where("login_email = ?", email).
		First(&user).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by login email: %w", err)
}

// UpdatePasswordAndRevokeSessions replaces the password hash, increments
// token_version and revokes every live token of the user in one transaction,
// returning the access-token entries that still need blacklist delivery.
//
// The three steps must not be split: token_version alone only invalidates
// access tokens (the refresh flow does not compare it), so a partial failure
// would leave live refresh tokens able to mint fresh access tokens for an
// account whose owner was told every session had ended.
func (r *UserRepository) UpdatePasswordAndRevokeSessions(
	ctx context.Context,
	userID int64,
	passwordHash string,
	revokedAt time.Time,
) ([]model.BlacklistEntry, error) {
	var entries []model.BlacklistEntry
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Model(&model.User{}).
			Where("id = ?", userID).
			Update("password", passwordHash).Error; err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		if err := transaction.Model(&model.User{}).
			Where("id = ?", userID).
			UpdateColumn("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
			return fmt.Errorf("increment token version: %w", err)
		}
		revoked, revokeErr := revokeAllByUserInTransaction(transaction, userID, revokedAt)
		if revokeErr != nil {
			return revokeErr
		}
		entries = revoked
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("update password and revoke sessions: %w", err)
	}
	return entries, nil
}

// ExistsByLoginEmail reports whether a user with the given login email exists.
func (r *UserRepository) ExistsByLoginEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	if err := r.database.WithContext(ctx).Model(&model.User{}).Where("login_email = ?", email).Count(&count).Error; err != nil {
		return false, fmt.Errorf("count user by login email: %w", err)
	}
	return count > 0, nil
}

// ExistsByStudentID reports whether a user with the given student ID exists.
func (r *UserRepository) ExistsByStudentID(ctx context.Context, studentID string) (bool, error) {
	var count int64
	if err := r.database.WithContext(ctx).Model(&model.User{}).Where("student_id = ?", studentID).Count(&count).Error; err != nil {
		return false, fmt.Errorf("count user by student id: %w", err)
	}
	return count > 0, nil
}

// ExistsAsEmailAnywhere reports whether the email is already used as a login
// email or as an other_mail identity provider_id. Both columns are unique, so
// this is the single pre-flight guard against the same address living in both
// tables.
func (r *UserRepository) ExistsAsEmailAnywhere(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := r.database.WithContext(ctx).Raw(`
		SELECT EXISTS (
			SELECT 1 FROM "user" WHERE login_email = ?
			UNION
			SELECT 1 FROM identities WHERE provider = ? AND provider_id = ?
		)`, email, model.LoginMethodOtherMail, email).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("check email anywhere: %w", err)
	}
	return exists, nil
}

// ProfileUpdate carries the self-service field changes for one user. A nil
// pointer means "leave unchanged"; a non-nil pointer to the zero value means
// "write that value". The two are distinct because PUT /user/profile is a
// partial update and clearing a nullable profile field is a legitimate edit.
//
// Identity and permission columns (login_email, role, state, email_type) are
// deliberately absent: they are admin-only per PRD §4.9, and leaving them out of
// the struct makes that unreachable rather than merely unvalidated.
type ProfileUpdate struct {
	Name        *string
	PhoneNumber *string
	QQNumber    *string
	StudentID   *string
	College     *model.College
	Major       *string

	Nickname   *string
	Department *model.Department
	Intro      *string
	Email      *string
	BlogURL    *string
	GitHubURL  *string
}

// userColumns returns the "user" table assignments, empty when untouched.
func (u ProfileUpdate) userColumns() map[string]any {
	columns := make(map[string]any, 6)
	assign(columns, "name", u.Name)
	assign(columns, "phone_number", u.PhoneNumber)
	assign(columns, "qq_number", u.QQNumber)
	assign(columns, "student_id", u.StudentID)
	assign(columns, "major", u.Major)
	if u.College != nil {
		columns["college"] = *u.College
	}
	return columns
}

// profileColumns returns the profile table assignments, empty when untouched.
// A non-nil pointer to "" writes SQL NULL: the columns are nullable display
// fields, and the API expresses "clear my intro" as an empty string.
func (u ProfileUpdate) profileColumns() map[string]any {
	columns := make(map[string]any, 6)
	assignNullable(columns, "nickname", u.Nickname)
	assignNullable(columns, "intro", u.Intro)
	assignNullable(columns, "email", u.Email)
	assignNullable(columns, "blog_url", u.BlogURL)
	assignNullable(columns, "github_url", u.GitHubURL)
	if u.Department != nil {
		if *u.Department == "" {
			columns["department"] = nil
		} else {
			columns["department"] = *u.Department
		}
	}
	return columns
}

// Empty reports whether the update would touch no column at all.
func (u ProfileUpdate) Empty() bool {
	return len(u.userColumns()) == 0 && len(u.profileColumns()) == 0
}

func assign(columns map[string]any, name string, value *string) {
	if value != nil {
		columns[name] = *value
	}
}

func assignNullable(columns map[string]any, name string, value *string) {
	if value == nil {
		return
	}
	if *value == "" {
		columns[name] = nil
		return
	}
	columns[name] = *value
}

// UpdateProfile applies a partial self-service update across "user" and profile
// in one transaction and returns the reloaded aggregate.
//
// The profile row is upserted rather than updated: profile is created alongside
// the user at registration, but a row imported before V001's registration flow
// (or removed by hand) would otherwise make the display fields silently
// unwritable while the response still reported success.
func (r *UserRepository) UpdateProfile(
	ctx context.Context,
	userID int64,
	update ProfileUpdate,
) (*model.User, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("%w: user id must be positive", ErrInvalidArgument)
	}
	if update.Empty() {
		return nil, fmt.Errorf("%w: update has no fields", ErrInvalidArgument)
	}
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if userColumns := update.userColumns(); len(userColumns) > 0 {
			result := transaction.Model(&model.User{}).Where("id = ?", userID).Updates(userColumns)
			if result.Error != nil {
				return fmt.Errorf("update user profile fields: %w", result.Error)
			}
			if result.RowsAffected == 0 {
				return ErrNotFound
			}
		}
		profileColumns := update.profileColumns()
		if len(profileColumns) == 0 {
			return nil
		}
		result := transaction.Model(&model.Profile{}).Where("user_id = ?", userID).Updates(profileColumns)
		if result.Error != nil {
			return fmt.Errorf("update profile fields: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			return nil
		}
		// No profile row yet. Verify the user exists before inserting, so a bad ID
		// cannot create an orphan-shaped row and report success; the FK would reject
		// it anyway, but ErrNotFound is the honest answer.
		var owner model.User
		if err := transaction.Select("id").Where("id = ?", userID).First(&owner).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return fmt.Errorf("load profile owner: %w", err)
		}
		profileColumns["user_id"] = userID
		// ON CONFLICT rather than a bare INSERT: two concurrent first writes both
		// see RowsAffected == 0 and both insert, and the loser would violate
		// profile_user_id_key. That is a retryable race on the user's own row, but
		// the constraint name is unmapped upstream and would surface as a 40900
		// "conflicts with an existing account". Merging instead makes both callers
		// succeed with their own columns.
		if err := transaction.Model(&model.Profile{}).Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns(profileColumnNames(profileColumns)),
		}).Create(profileColumns).Error; err != nil {
			return fmt.Errorf("create profile for update: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("update profile: %w", err)
	}
	return r.FindByID(ctx, userID)
}

// profileColumnNames returns the assignable column names of a profile upsert,
// excluding user_id: it is the conflict target, so re-assigning it is redundant.
// Sorted so the generated statement is stable across runs.
func profileColumnNames(columns map[string]any) []string {
	names := make([]string, 0, len(columns))
	for name := range columns {
		if name == "user_id" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// PublicCard is the unauthenticated display-card projection of a user. It holds
// only the columns PRD §4.14 lists as public; nothing from "user" beyond the ID
// is included, so a query change cannot accidentally widen the public surface.
type PublicCard struct {
	ID         int64
	Nickname   *string
	Department *model.Department
	Intro      *string
	Avatar     *string
	BlogURL    *string
	GitHubURL  *string
}

// FindPublicCardByUserID returns the public card of a non-deleted user.
//
// Soft-deleted accounts are filtered in SQL rather than by the caller: /card/:id
// needs no authentication, so a missed check would publish the profile of an
// account the owner asked to have removed. A deleted user is reported as
// ErrNotFound, which is also what the contract documents (404).
func (r *UserRepository) FindPublicCardByUserID(ctx context.Context, userID int64) (*PublicCard, error) {
	if userID <= 0 {
		return nil, ErrNotFound
	}
	var card PublicCard
	err := r.database.WithContext(ctx).
		Model(&model.User{}).
		Select(`"user".id`, "profile.nickname", "profile.department", "profile.intro",
			"profile.avatar", "profile.blog_url", "profile.github_url").
		Joins(`LEFT JOIN profile ON profile.user_id = "user".id`).
		Where(`"user".id = ? AND "user".state <> ?`, userID, model.UserStateDeleted).
		Take(&card).Error
	if err == nil {
		return &card, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find public card by user ID: %w", err)
}

// FindAuthStateByID finds the minimal user state required to authenticate tokens.
func (r *UserRepository) FindAuthStateByID(ctx context.Context, userID int64) (*UserAuthState, error) {
	var state UserAuthState
	err := r.database.WithContext(ctx).
		Model(&model.User{}).
		Select("id", "state", "token_version").
		First(&state, userID).Error
	if err == nil {
		return &state, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user auth state by ID: %w", err)
}
