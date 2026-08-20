package adminuser

import (
	"context"
	"reflect"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

// The flag is only manageable if an administrator can list the backlog. Without
// the filter the console could show a marker per row but never answer "which
// accounts still need fixing" without paging the whole table.
func TestListUsersPassesNeedsCompletionFilter(t *testing.T) {
	tests := []struct {
		name  string
		input *bool
	}{
		{name: "no filter", input: nil},
		{name: "backlog only", input: boolPointer(true)},
		{name: "healthy only", input: boolPointer(false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newHarness(t)
			if _, err := h.service.ListUsers(context.Background(), ListUsersInput{
				Page: 1, PageSize: 10, NeedsCompletion: test.input,
			}); err != nil {
				t.Fatalf("ListUsers: %v", err)
			}
			got := h.users.listedFilter.NeedsCompletion
			switch {
			case test.input == nil && got != nil:
				t.Fatalf("NeedsCompletion = %v, want nil so the default list is unfiltered", *got)
			case test.input != nil && got == nil:
				t.Fatal("NeedsCompletion = nil, want the requested value passed through")
			case test.input != nil && *got != *test.input:
				t.Fatalf("NeedsCompletion = %t, want %t", *got, *test.input)
			}
		})
	}
}

// The console reports the same field list the user's own completion page would,
// derived through internal/validate rather than re-implemented here. The row's
// generated flag and the derived list are reported side by side, so a drift
// between V010 and the Go rule shows up as a row marked incomplete with no fields
// named.
func TestListUsersReportsIncompleteFields(t *testing.T) {
	h := newHarness(t)
	h.users.listRows = []repository.AdminUserRow{
		{
			// The dominant legacy shape: name filled in with the student ID, blank
			// phone, qq and major.
			ID: 5, Name: "B24040525", StudentID: "B24040525",
			LoginEmail: "b24040525@njupt.edu.cn",
			Role:       model.UserRoleFreshman, State: model.UserStateNJUPTer,
			PhoneNumber: "", QQNumber: "", Major: "", ProfileNeedsCompletion: true,
		},
		{
			ID: 6, Name: "张三", StudentID: "B24040001",
			LoginEmail: "b24040001@njupt.edu.cn",
			Role:       model.UserRoleMember, State: model.UserStateOnSAST,
			PhoneNumber: "13800000000", QQNumber: "10001", Major: "软件工程", ProfileNeedsCompletion: false,
		},
	}
	h.users.listTotal = 2

	result, err := h.service.ListUsers(context.Background(), ListUsersInput{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if !result.Users[0].ProfileNeedsCompletion {
		t.Fatal("first row ProfileNeedsCompletion = false, want true")
	}
	want := []string{"name", "phone_number", "qq_number", "major"}
	if !reflect.DeepEqual(result.Users[0].IncompleteFields, want) {
		t.Fatalf("first row IncompleteFields = %v, want %v", result.Users[0].IncompleteFields, want)
	}
	if result.Users[1].ProfileNeedsCompletion {
		t.Fatal("second row ProfileNeedsCompletion = true, want false")
	}
	// Empty rather than nil: the JSON field is always an array.
	if got := result.Users[1].IncompleteFields; got == nil || len(got) != 0 {
		t.Fatalf("second row IncompleteFields = %#v, want an empty slice", got)
	}
}

func boolPointer(value bool) *bool {
	return &value
}
