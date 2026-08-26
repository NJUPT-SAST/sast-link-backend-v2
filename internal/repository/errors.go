package repository

import "errors"

var (
	ErrNotFound        = errors.New("repository: not found")
	ErrInvalidArgument = errors.New("repository: invalid argument")
	// ErrLimitExceeded reports that a bounded-cardinality insert would exceed its cap.
	ErrLimitExceeded = errors.New("repository: limit exceeded")
	// ErrStateConflict reports that the row exists but its current state does not
	// allow the requested transition, e.g. restoring an account that is not
	// deleted. Kept distinct from ErrNotFound so the caller can report which
	// happened.
	ErrStateConflict = errors.New("repository: state conflict")
	// ErrLastAdmin reports that the write would leave the system with no active
	// administrator. Enforced inside the writing transaction, where a count over
	// other rows can be serialized.
	ErrLastAdmin = errors.New("repository: last active admin")
	// ErrLastLoginMethod reports that deleting the identity would leave the
	// account with no way to sign in. Decided under a lock on the user row so
	// concurrent unbinds cannot both pass a stale snapshot.
	ErrLastLoginMethod = errors.New("repository: identity is the last login method")
	// ErrRehashSkipped reports that a rehash-on-login write was skipped because
	// the stored hash changed between verification and write. Not an error
	// condition: the login already succeeded, the rehash just did not land.
	ErrRehashSkipped = errors.New("repository: rehash skipped, stored hash changed")
	// ErrStudentIDExists reports that a student ID already belongs to an account
	// under the folded comparison (lower(btrim)). Raised inside the alumni
	// approval transaction, where the pre-submission occupancy check may have
	// missed a case-differing variant of the same ID before a unique violation
	// could catch it — user.student_id is unique under the case-sensitive
	// default collation, so a ticket for B24040525 would otherwise provision
	// beside an existing b24040525.
	ErrStudentIDExists = errors.New("repository: student id already exists")
	// ErrIdentityLimitExceeded reports that an other_mail bind would exceed the
	// per-account cap of two. Checked in the writing transaction: the V001
	// check_other_mail_limit trigger raises an unnamed P0001 that no constraint
	// name can classify, so the bound-check must happen first, under the same
	// advisory lock that serializes the insert.
	ErrIdentityLimitExceeded = errors.New("repository: other_mail identity limit reached")
	// ErrAccountClosed reports that an account exists but its state is
	// is_deleted. Kept distinct from ErrStateConflict, which on this package's
	// review paths means "the ticket already carries a verdict" — collapsing
	// them would tell a reviewer that a recovery target was already reviewed.
	ErrAccountClosed = errors.New("repository: account is deleted")
	// ErrLoginEmailMismatch reports that a recovery ticket's login_email does not
	// match the login email registered on the account its student ID names. The
	// pre-submission check compares the same pair outside any transaction; this
	// is the same decision re-made against the locked row inside it.
	ErrLoginEmailMismatch = errors.New("repository: login email does not match the account")
	// ErrRecoverTargetMissing reports that a student ID which passed the
	// pre-submission existence check no longer resolves to an account inside the
	// approval transaction (removed concurrently, or imported data drift).
	ErrRecoverTargetMissing = errors.New("repository: no account for this student id")
)
