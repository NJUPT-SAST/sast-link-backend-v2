package validate

import (
	"testing"
	"time"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestEnrollmentYear(t *testing.T) {
	for _, tc := range []struct {
		name      string
		studentID string
		want      int
		wantErr   bool
	}{
		{"b-letter prefix, the SL format", "B24040525", 2024, false},
		{"lowercase prefix", "b24040525", 2024, false},
		{"bare year prefix", "24040525", 2024, false},
		{"old prefix", "B20040525", 2020, false},
		{"variable-width tail", "B2404042", 2024, false},
		{"no digits", "B", 0, true},
		{"single digit", "B2", 0, true},
		{"empty", "", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EnrollmentYear(tc.studentID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("EnrollmentYear(%q) = %d, nil; want error", tc.studentID, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("EnrollmentYear(%q) unexpected error: %v", tc.studentID, err)
			}
			if got != tc.want {
				t.Fatalf("EnrollmentYear(%q) = %d, want %d", tc.studentID, got, tc.want)
			}
		})
	}
}

func TestAcademicYear(t *testing.T) {
	shanghai := time.FixedZone("CST", 8*3600)
	for _, tc := range []struct {
		name string
		now  time.Time
		want int
	}{
		{"before 9/1", time.Date(2026, 8, 31, 23, 59, 59, 0, shanghai), 2025},
		{"late August in UTC - still 8/31 in CST", time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC), 2025},
		{"9/1 00:00 CST rollover", time.Date(2026, 9, 1, 0, 0, 0, 0, shanghai), 2026},
		{"just before clock rollover UTC", time.Date(2026, 8, 31, 15, 59, 59, 0, time.UTC), 2025},
		{"8/31 16:00 UTC is already 9/1 CST", time.Date(2026, 8, 31, 16, 0, 0, 0, time.UTC), 2026},
		{"mid academic year", time.Date(2026, 3, 1, 12, 0, 0, 0, shanghai), 2025},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AcademicYear(tc.now); got != tc.want {
				t.Fatalf("AcademicYear(%v) = %d, want %d", tc.now, got, tc.want)
			}
		})
	}
}

func TestDeriveState(t *testing.T) {
	// 2026-09-01 00:00 CST: the 2022 cohort crosses the retirement threshold.
	retirementBoundary := time.Date(2026, 9, 1, 0, 0, 0, 0, time.FixedZone("CST", 8*3600))
	beforeBoundary := retirementBoundary.Add(-time.Second)

	for _, tc := range []struct {
		name      string
		role      model.UserRole
		studentID string
		now       time.Time
		want      model.UserState
		wantErr   bool
	}{
		// Student roles with a recent enrollment year are njupter.
		{"freshman current year", model.UserRoleFreshman, "B26040525", retirementBoundary, model.UserStateNJUPTer, false},
		{"member current year", model.UserRoleMember, "B26040525", retirementBoundary, model.UserStateNJUPTer, false},
		// Staff roles with a recent enrollment year are on_sast.
		{"lecturer current year", model.UserRoleLecturer, "B26040525", retirementBoundary, model.UserStateOnSAST, false},
		{"admin current year", model.UserRoleAdmin, "B26040525", retirementBoundary, model.UserStateOnSAST, false},
		// Old enrollment years retire regardless of role.
		{"member 2022 cohort on boundary day", model.UserRoleMember, "B22040525", retirementBoundary, model.UserStateRetiredSAST, false},
		{"admin 2022 cohort on boundary day", model.UserRoleAdmin, "B22040525", retirementBoundary, model.UserStateRetiredSAST, false},
		{"member 2022 cohort just before boundary", model.UserRoleMember, "B22040525", beforeBoundary, model.UserStateNJUPTer, false},
		{"freshman 2022 cohort before boundary", model.UserRoleFreshman, "B22040525", beforeBoundary, model.UserStateNJUPTer, false},
		{"admin 2022 cohort before boundary", model.UserRoleAdmin, "B22040525", beforeBoundary, model.UserStateOnSAST, false},
		// 2021 cohort retired a full year earlier.
		{"member 2021 cohort", model.UserRoleMember, "B21040525", retirementBoundary, model.UserStateRetiredSAST, false},
		{"lecturer 2021 cohort", model.UserRoleLecturer, "B21040525", retirementBoundary, model.UserStateRetiredSAST, false},
		// Unknown role falls back to the student bucket (defensive; no error).
		{"unknown role current year", model.UserRole("sponsor"), "B26040525", retirementBoundary, model.UserStateNJUPTer, false},
		// Unparseable student ID: the defensive branch, no guessing.
		{"unparseable student id", model.UserRoleMember, "no-digits", retirementBoundary, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DeriveState(tc.role, tc.studentID, tc.now)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("DeriveState(%s, %q) = %s, nil; want error", tc.role, tc.studentID, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeriveState(%s, %q) unexpected error: %v", tc.role, tc.studentID, err)
			}
			if got != tc.want {
				t.Fatalf("DeriveState(%s, %q) = %s, want %s", tc.role, tc.studentID, got, tc.want)
			}
		})
	}
}
