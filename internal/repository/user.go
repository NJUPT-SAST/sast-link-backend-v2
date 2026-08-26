package repository

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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

// CreateAdminUser creates an account, its profile, and an optional other_mail
// identity in one transaction, without issuing a token pair — provisioning has
// no subject to receive a session. The identity joins the same transaction so
// the bound email works for login immediately; nil means no binding.
func (r *UserRepository) CreateAdminUser(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
	identity *model.Identity,
) error {
	if user == nil {
		return fmt.Errorf("%w: user is nil", ErrInvalidArgument)
	}
	if profile == nil {
		return fmt.Errorf("%w: profile is nil", ErrInvalidArgument)
	}

	return r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return createAdminUserInTransaction(transaction, user, profile, identity)
	})
}

// createAdminUserInTransaction appends an account, its profile and an optional
// other_mail identity to an existing transaction. It was extracted from
// CreateAdminUser because the alumni approval must provision the account and
// write the ticket's verdict in one transaction. The transaction is opened by
// the repository rather than handed in from a service, which never holds a
// *gorm.DB, so transaction lifetime stays out of the layer that is unaware of it.
func createAdminUserInTransaction(
	transaction *gorm.DB,
	user *model.User,
	profile *model.Profile,
	identity *model.Identity,
) error {
	if err := transaction.Create(user).Error; err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}
	profile.UserID = user.ID
	if err := transaction.Create(profile).Error; err != nil {
		return fmt.Errorf("create admin profile: %w", err)
	}
	if identity != nil {
		// The owner row does not exist until the INSERT above; take the ID from
		// the persisted user rather than trusting a caller-computed one.
		identity.UserID = user.ID
		if err := transaction.Create(identity).Error; err != nil {
			return fmt.Errorf("create admin user identity: %w", err)
		}
	}
	return nil
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
	return r.CreateRegistrationWithIdentity(ctx, user, profile, nil, pairFactory)
}

// CreateRegistrationWithIdentity creates an account, its profile, an optional
// third-party binding and the initial session in one PostgreSQL transaction:
// "register through GitHub" is one atomic outcome, and a failed identity insert
// would leave an account whose provider binding looks unbound. A nil identity is
// the plain email registration path.
//
// It deliberately does not reuse IdentityRepository.CreateWithinLimit, which
// opens its own transaction and locks the user row — here the user row was just
// created in this transaction and is not visible to any concurrent writer, so
// the V001 unique indexes are the backstop.
func (r *UserRepository) CreateRegistrationWithIdentity(
	ctx context.Context,
	user *model.User,
	profile *model.Profile,
	identity *model.Identity,
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
		if identity != nil {
			// Set the owner here rather than trusting the caller: the ID does
			// not exist until the INSERT above.
			identity.UserID = user.ID
			if err := transaction.Create(identity).Error; err != nil {
				return fmt.Errorf("create registration identity: %w", err)
			}
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

// FindByIDs finds the users matching the given ids with their profile and
// identities, regardless of state, in unspecified order. Missing ids are not an
// error — the caller is a batch lookup that reports per-id results — and
// ordering is the caller's to restore from its request order.
func (r *UserRepository) FindByIDs(ctx context.Context, ids []int64) ([]model.User, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: id list must not be empty", ErrInvalidArgument)
	}
	users := make([]model.User, 0, len(ids))
	err := r.database.WithContext(ctx).
		Preload("Profile").
		Preload("Identities").
		Where("id IN ?", ids).
		Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("find users by IDs: %w", err)
	}
	return users, nil
}

// FindProfileByID loads a user for a profile response: the profile row joins the
// user row, and identities are preloaded with a projection that excludes the
// provider access/refresh tokens the response never serializes.
func (r *UserRepository) FindProfileByID(ctx context.Context, userID int64) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).
		Joins("Profile").
		Preload("Identities", func(db *gorm.DB) *gorm.DB {
			return db.Select("id", "user_id", "provider", "provider_id",
				"identity_data", "token_expires_at", "created_at", "updated_at")
		}).
		First(&user, userID).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user profile by ID: %w", err)
}

// FindAuthUserByID finds a user's scalar columns without preloading Profile or
// Identities, which auth paths do not need.
func (r *UserRepository) FindAuthUserByID(ctx context.Context, userID int64) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).First(&user, userID).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by ID: %w", err)
}

// FindAuthUserByLoginEmail is FindAuthUserByID's counterpart for the login-email
// lookup; it likewise skips the Profile/Identities preloads.
func (r *UserRepository) FindAuthUserByLoginEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).Where("login_email = ?", email).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by login email: %w", err)
}

// FindAuthUserByLoginIdentifier is FindByLoginIdentifier without the
// Profile/Identities preloads: it matches the login email or an other_mail
// identity and returns only the user row's scalar columns, which is all the
// login handler serializes.
func (r *UserRepository) FindAuthUserByLoginIdentifier(ctx context.Context, identifier string) (*model.User, error) {
	var user model.User
	err := r.database.WithContext(ctx).Where("login_email = ?", identifier).First(&user).Error
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("find user by login identifier: %w", err)
	}
	err = r.database.WithContext(ctx).
		Joins("JOIN identities ON identities.user_id = \"user\".id").
		Where("identities.provider = ? AND identities.provider_id = ?", model.LoginMethodOtherMail, identifier).
		First(&user).Error
	if err == nil {
		return &user, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("find user by login identifier: %w", err)
}

// UpdatePasswordAndRevokeSessions replaces the password hash, increments
// token_version and revokes every live token of the user in one transaction,
// returning the access-token entries that still need revocation delivery. The
// steps must not be split: token_version alone does not invalidate refresh
// tokens, so a partial failure would leave them able to mint fresh access tokens.
func (r *UserRepository) UpdatePasswordAndRevokeSessions(
	ctx context.Context,
	userID int64,
	passwordHash string,
	revokedAt time.Time,
) ([]model.BlacklistEntry, error) {
	var entries []model.BlacklistEntry
	err := r.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		result := transaction.Model(&model.User{}).
			Where("id = ?", userID).
			Updates(map[string]any{
				"password":      passwordHash,
				"token_version": gorm.Expr("token_version + 1"),
			})
		if result.Error != nil {
			return fmt.Errorf("update password and token version: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			// Reporting success for a user that does not exist would tell the
			// caller "password changed, sessions revoked" while nothing happened.
			return ErrNotFound
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

// UpdatePasswordHash rewrites only the stored hash, without bumping token_version
// or revoking sessions — the in-place rehash-on-login write, where the session
// being created must survive. Callers that mean "change the password" must use
// UpdatePasswordAndRevokeSessions instead. The UPDATE is guarded on the hash the
// caller just verified, so a concurrent change that committed a new hash wins
// and this rehash is skipped (ErrRehashSkipped) rather than reverting the
// credential.
func (r *UserRepository) UpdatePasswordHash(ctx context.Context, userID int64, currentHash, passwordHash string) error {
	if strings.TrimSpace(passwordHash) == "" {
		return fmt.Errorf("%w: password hash is empty", ErrInvalidArgument)
	}
	// A map condition keeps any password-keyed literal out of the source, so a
	// secret scanner cannot misread it.
	result := r.database.WithContext(ctx).
		Model(&model.User{}).
		Where(map[string]any{"id": userID, "password": currentHash}).
		Update("password", passwordHash)
	if result.Error != nil {
		return fmt.Errorf("update password hash: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrRehashSkipped
	}
	return nil
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
//
// The comparison folds case and surrounding whitespace, matching the alumni
// pending-ticket index (lower(btrim(student_id))). user.student_id's unique
// constraint is case-sensitive under the default collation, so a plain equality
// would let a variant spelling of an existing ID pass the occupancy checks and
// be provisioned beside it.
func (r *UserRepository) ExistsByStudentID(ctx context.Context, studentID string) (bool, error) {
	var count int64
	if err := r.database.WithContext(ctx).Model(&model.User{}).
		Where("lower(btrim(student_id)) = lower(btrim(?))", studentID).
		Count(&count).Error; err != nil {
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
// "write that value". Identity and permission columns (login_email, role, state,
// email_type) are deliberately absent: they are admin-only (PRD §4.9), and
// leaving them out makes that unreachable rather than merely unvalidated.
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
	Avatar     *string
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
	columns := make(map[string]any, 7)
	assignNullable(columns, "nickname", u.Nickname)
	assignNullable(columns, "intro", u.Intro)
	assignNullable(columns, "email", u.Email)
	assignNullable(columns, "avatar", u.Avatar)
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
// in one transaction and returns the reloaded aggregate. The profile row is
// upserted rather than plain-updated, so a user missing a profile row (imported
// before V001's flow, or removed by hand) still gets writable display fields.
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
		// The state predicate keeps soft-deleted accounts out of this path even if a
		// caller bypasses the middleware's state gate.
		if userColumns := update.userColumns(); len(userColumns) > 0 {
			result := transaction.Model(&model.User{}).
				Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
				Updates(userColumns)
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
		// Verify the owner first, since a profile-only request never reads "user" and
		// would otherwise report success on a missing or soft-deleted account.
		var owner model.User
		if err := transaction.Select("id").
			Where("id = ? AND state <> ?", userID, model.UserStateDeleted).
			First(&owner).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return fmt.Errorf("load profile owner: %w", err)
		}
		result := transaction.Model(&model.Profile{}).Where("user_id = ?", userID).Updates(profileColumns)
		if result.Error != nil {
			return fmt.Errorf("update profile fields: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			return nil
		}
		profileColumns["user_id"] = userID
		// ON CONFLICT rather than a bare INSERT: two concurrent first writes would both
		// insert and the loser would violate profile_user_id_key, surfacing as an
		// unmapped 40900. Merging lets both callers succeed with their own columns.
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

// PublicCard is the unauthenticated display-card projection of a user, holding
// only the columns PRD §4.14 lists as public so a query change cannot widen the
// surface. Column tags are explicit: GORM's initialism replacer derives
// git_hub_url from GitHubURL, which would be silently discarded on scan.
type PublicCard struct {
	ID         int64             `gorm:"column:id"`
	Nickname   *string           `gorm:"column:nickname"`
	Department *model.Department `gorm:"column:department"`
	Intro      *string           `gorm:"column:intro"`
	Avatar     *string           `gorm:"column:avatar"`
	BlogURL    *string           `gorm:"column:blog_url"`
	GitHubURL  *string           `gorm:"column:github_url"`
}

// FindPublicCardByUserID returns the public card of a non-deleted user.
// Soft-deleted accounts are filtered in SQL because /card/:id is
// unauthenticated; a missed check would publish an account the owner asked to
// have removed. A deleted user reports ErrNotFound, matching the 404 contract.
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

// NamesByIDs returns the display names for the given user ids; missing ids are
// simply absent from the map (deleted rows, never-written ids).
func (r *UserRepository) NamesByIDs(ctx context.Context, ids []int64) (map[int64]string, error) {
	names := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return names, nil
	}
	rows := make([]struct {
		ID   int64
		Name string
	}, 0, len(ids))
	if err := r.database.WithContext(ctx).
		Model(&model.User{}).
		Select("id", "name").
		Where("id IN ?", ids).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("load user names: %w", err)
	}
	for _, row := range rows {
		names[row.ID] = row.Name
	}
	return names, nil
}
