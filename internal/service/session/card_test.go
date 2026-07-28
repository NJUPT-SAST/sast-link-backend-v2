package session

import (
	"context"
	"testing"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/errcode"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
)

func TestCardReturnsPublicFields(t *testing.T) {
	service := newRegisterService(t)
	users := service.Users.(*fakeUsers)
	users.byID[42].Profile.Intro = stringPtr("自我介绍")

	result, err := service.Card(context.Background(), CardInput{UserID: 42})
	if err != nil {
		t.Fatalf("Card returned error: %v", err)
	}
	if result.Card.ID != 42 {
		t.Fatalf("id = %d, want 42", result.Card.ID)
	}
	if got := result.Card.Nickname; got == nil || *got != "pt" {
		t.Fatalf("nickname = %v, want pt", got)
	}
	if got := result.Card.Department; got == nil || *got != string(model.DepartmentSoftware) {
		t.Fatalf("department = %v, want software", got)
	}
}

// The card needs no authentication, so a soft-deleted account must read as 404
// rather than publishing the profile of someone who asked to be removed.
func TestCardHidesDeletedUsers(t *testing.T) {
	service := newRegisterService(t)
	service.Users.(*fakeUsers).byID[42].State = model.UserStateDeleted

	_, err := service.Card(context.Background(), CardInput{UserID: 42})
	assertKind(t, err, KindNotFound, errcode.CodeUserNotFound)
}

func TestCardRejectsUnknownAndNonPositiveIDs(t *testing.T) {
	service := newRegisterService(t)
	for _, id := range []int64{0, -1, 4242} {
		_, err := service.Card(context.Background(), CardInput{UserID: id})
		assertKind(t, err, KindNotFound, errcode.CodeUserNotFound)
	}
}

// A user with no profile row still has a card; the display fields are simply null.
func TestCardToleratesMissingProfileRow(t *testing.T) {
	service := newRegisterService(t)
	service.Users.(*fakeUsers).byID[42].Profile = nil

	result, err := service.Card(context.Background(), CardInput{UserID: 42})
	if err != nil {
		t.Fatalf("Card returned error: %v", err)
	}
	if result.Card.Nickname != nil || result.Card.Department != nil {
		t.Fatalf("card = %+v, want null display fields", result.Card)
	}
}
