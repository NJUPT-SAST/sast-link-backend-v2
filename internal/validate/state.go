package validate

import (
	"strconv"
	"time"
	"unicode"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// state.go owns the derivation rule for user.state (njupter / on_sast /
// retired_sast), the single source of truth for the state machine. It is never
// copied into SQL, never duplicated in a repository or service package.
//
// The rule (agreed with the product owner, see .pi/PLAN.md):
//   - student_id's first two digits are always the enrollment year (guaranteed
//     format; the parse-failure branch below is a defensive fallback that real
//     data never reaches);
//   - an account whose enrollment year is 4+ academic years old is retired,
//     whatever its role;
//   - otherwise a lecturer/admin is on_sast and a freshman/member is njupter.
//
// is_deleted is deliberately out of scope: it is the manual DELETE channel and
// shadows every derivation.

// shanghaiFixedZone is the academic-year boundary timezone. The 9/1 switch is
// decided in China Standard Time (UTC+8): a school year rolls over at midnight
// Beijing time, not at the container's UTC midnight. Hardcoded so the rule does
// not depend on the host TZ or on a tzdata install (alpine ships one, but the
// local dev machines may not, and time.Local is UTC in a bare container).
var shanghaiFixedZone = time.FixedZone("CST", 8*3600)

// ErrUnparseableStudentID reports a student_id whose leading digits could not
// be read as an enrollment year. Reachable only for data that violates the
// guaranteed format; callers treat it as "leave the row alone" (the retention
// batch skips the row, write paths refuse the operation).
type ErrUnparseableStudentID struct{}

func (ErrUnparseableStudentID) Error() string {
	return "student_id: cannot parse enrollment year from leading digits"
}

// EnrollmentYear extracts the enrollment year from a student ID. The first two
// consecutive digits after any leading non-digit prefix are the year, mapped as
// 2000+n (B24040525 -> 24 -> 2024). A 2-digit mapping is century-agnostic at the
// 4-year threshold, so no 19xx/20xx disambiguation is attempted.
//
// A student ID with fewer than two leading digits cannot be read as an
// enrollment year: the caller must not guess.
func EnrollmentYear(studentID string) (int, error) {
	digits := ""
	for _, r := range studentID {
		if unicode.IsDigit(r) {
			digits += string(r)
		} else if digits != "" {
			break
		}
	}
	if len(digits) < 2 {
		return 0, ErrUnparseableStudentID{}
	}
	n, err := strconv.Atoi(digits[:2])
	if err != nil {
		return 0, ErrUnparseableStudentID{}
	}
	return 2000 + n, nil
}

// AcademicYear returns the academic year (as its starting calendar year) that
// contains now, in China Standard Time. The boundary is September 1st: a time on
// or after 9/1 belongs to the year that begins then (2026-09-01 -> 2026), a time
// before it belongs to the previous one (2026-08-31 -> 2025).
func AcademicYear(now time.Time) int {
	shanghai := now.In(shanghaiFixedZone)
	if shanghai.Month() >= time.September {
		return shanghai.Year()
	}
	return shanghai.Year() - 1
}

// DeriveState computes the state the account should hold at now, from the
// role and the enrollment year encoded in the student ID.
//
// It returns ErrUnparseableStudentID when the student ID cannot be read; the
// caller decides what that means (the retention batch skips the row, write
// paths treat the account as not derivable). An unrecognized role is treated
// like any non-staff account — the conservative fallback keeps a state value
// derivable rather than refusing the whole derivation.
func DeriveState(role model.UserRole, studentID string, now time.Time) (model.UserState, error) {
	enrollmentYear, err := EnrollmentYear(studentID)
	if err != nil {
		return "", err
	}
	if AcademicYear(now)-enrollmentYear >= retirementThresholdYears {
		return model.UserStateRetiredSAST, nil
	}
	switch role {
	case model.UserRoleLecturer, model.UserRoleAdmin:
		return model.UserStateOnSAST, nil
	default:
		return model.UserStateNJUPTer, nil
	}
}

// retirementThresholdYears is the number of academic years after which an
// account is treated as retired: enrollment year + 4 (a student who enrolled in
// 2022 academic year retires on 2026-09-01). The 4-year horizon also makes the
// 2-digit enrollment-year mapping safe — a year read as 2000+n is exactly
// retirement-threshold-distinct from its 1900+n reading.
const retirementThresholdYears = 4
