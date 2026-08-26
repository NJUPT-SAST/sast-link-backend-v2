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
)
