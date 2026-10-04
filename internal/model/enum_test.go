package model_test

import (
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

// The enum guards exist so an out-of-range value is rejected as invalid input
// instead of reaching PostgreSQL, where it surfaces as an opaque
// "invalid input value for enum" error the client cannot act on.
func TestCollegeValid(t *testing.T) {
	valid := []model.College{
		model.CollegeBellHonors,
		model.CollegeComputerSoftwareCybersecurity,
		model.CollegePortland,
		model.CollegeEuropeCyprus,
		model.CollegeOther,
	}
	for _, college := range valid {
		if !college.Valid() {
			t.Errorf("College(%q).Valid() = false, want true", college)
		}
	}
	// "计算机学院" is the abbreviated name used in the API docs' examples but is not
	// a college_enum member; only the full label is.
	invalid := []model.College{"", "计算机学院", "Computer Science", "其他 "}
	for _, college := range invalid {
		if college.Valid() {
			t.Errorf("College(%q).Valid() = true, want false", college)
		}
	}
}

func TestDepartmentValid(t *testing.T) {
	for _, department := range []model.Department{
		model.DepartmentSoftware, model.DepartmentMedia, model.DepartmentElectronics,
		model.DepartmentOffice, model.DepartmentLiaison, model.DepartmentPublicity,
		model.DepartmentCompetition,
	} {
		if !department.Valid() {
			t.Errorf("Department(%q).Valid() = false, want true", department)
		}
	}
	// An empty Department means "unset" and is handled by the caller as a clear, so
	// it is deliberately not valid input here.
	for _, department := range []model.Department{"", "hardware", "Software", " media"} {
		if department.Valid() {
			t.Errorf("Department(%q).Valid() = true, want false", department)
		}
	}
}

// TestDepartmentsCatalogueMatchesValid pins the public catalogue to the enum:
// every listed key must be a Valid() member, no member may be missing from the
// list, and no key may appear twice. A drift in either direction breaks an
// integrator's label lookup or hides a department from GET /departments while
// the write paths still accept it.
func TestDepartmentsCatalogueMatchesValid(t *testing.T) {
	seen := make(map[model.Department]bool, len(model.Departments))
	for _, entry := range model.Departments {
		key := model.Department(entry.Key)
		if !key.Valid() {
			t.Errorf("model.Departments lists %q, which Department.Valid() rejects", entry.Key)
		}
		if seen[key] {
			t.Errorf("model.Departments lists %q twice", entry.Key)
		}
		seen[key] = true
		if entry.Label == "" {
			t.Errorf("model.Departments entry %q has an empty label", entry.Key)
		}
	}
	for _, department := range []model.Department{
		model.DepartmentSoftware, model.DepartmentMedia, model.DepartmentElectronics,
		model.DepartmentOffice, model.DepartmentLiaison, model.DepartmentPublicity,
		model.DepartmentCompetition,
	} {
		if !seen[department] {
			t.Errorf("department %q is Valid() but missing from model.Departments", department)
		}
	}
}
