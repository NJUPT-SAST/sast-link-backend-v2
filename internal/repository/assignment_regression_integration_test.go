package repository_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestRegressionConcurrentFoldedAssignment(t *testing.T) {
	db := setupDatabase(t)
	users := repository.NewUser(db)
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, sid := range []string{"B24040525", "b24040525"} {
		go func(i int, sid string) {
			<-start
			u := testUser(fmt.Sprintf("race-%d@sast.fun", i))
			u.StudentID = sid
			results <- users.CreateWithProfile(context.Background(), u, &model.Profile{})
		}(i, sid)
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, repository.ErrStudentIDExists) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflict=%d", successes, conflicts)
	}
}

func TestRegressionSchoolPrefixAssignmentBothDirections(t *testing.T) {
	for _, studentFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("student_first=%v", studentFirst), func(t *testing.T) {
			db := setupDatabase(t)
			users := repository.NewUser(db)
			a := testUser("student@sast.fun")
			a.StudentID = "B24040525"
			b := testUser("b24040525@njupt.edu.cn")
			b.StudentID = "B24040526"
			if !studentFirst {
				a, b = b, a
			}
			if err := users.CreateAdminUser(context.Background(), a, &model.Profile{}, nil); err != nil {
				t.Fatal(err)
			}
			if err := users.CreateWithProfile(context.Background(), b, &model.Profile{}); !errors.Is(err, repository.ErrStudentIDExists) {
				t.Fatalf("conflicting assignment: %v", err)
			}
		})
	}
}

func TestRegressionAdminUpdatesSerializeIdentityAssignment(t *testing.T) {
	db := setupDatabase(t)
	users := repository.NewUser(db)
	a := createUserWithProfile(t, users, "update-a@sast.fun")
	b := createUserWithProfile(t, users, "update-b@sast.fun")
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, u := range []*model.User{a, b} {
		wg.Add(1)
		go func(i int, u *model.User) {
			defer wg.Done()
			<-start
			sid := []string{"B24040525", "b24040525"}[i]
			_, _, err := users.UpdateAdminUser(context.Background(), u.ID, repository.AdminUserUpdate{StudentID: &sid}, model.UserRoleAdmin, time.Now())
			results <- err
		}(i, u)
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, repository.ErrStudentIDExists) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("successful updates=%d", success)
	}
}

func TestRegressionStatsPinnedStaffState(t *testing.T) {
	db := setupDatabase(t)
	users := repository.NewUser(db)
	for i, role := range []model.UserRole{model.UserRoleAdmin, model.UserRoleLecturer} {
		u := testUser(fmt.Sprintf("pinned-%d@sast.fun", i))
		u.Role = role
		u.State = model.UserStateNJUPTer
		u.StateManual = true
		if err := users.CreateWithProfile(context.Background(), u, &model.Profile{}); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := users.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.IncompleteByState[model.UserStateNJUPTer] != 2 {
		t.Fatalf("state incomplete=%v", stats.IncompleteByState)
	}
	if stats.IncompleteByRole[model.UserRoleAdmin] != 0 || stats.IncompleteByRole[model.UserRoleLecturer] != 0 {
		t.Fatalf("role incomplete=%v", stats.IncompleteByRole)
	}
}

func TestRegressionRetentionAbovePostgresParameterLimit(t *testing.T) {
	db := setupDatabase(t).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)})
	// 32767 rows would generate 65536 bind parameters in the old single UPDATE.
	// Seed in bounded transactions: V005 takes an advisory lock per email;
	// one 32767-row INSERT itself exhausts PostgreSQL max_locks_per_transaction.
	for first := 1; first <= 32767; first += 500 {
		seedErr := db.Exec(`INSERT INTO "user" (name, student_id, login_email, password, role, state, college, phone_number, qq_number)
 SELECT 'Member '||n, 'B20'||lpad(n::text,6,'0'), 'retention-'||n||'@sast.fun', 'hash', 'member', 'njupter', '其他', '', ''
 FROM generate_series(?::int,?::int) n`, first, min(first+499, 32767)).Error
		if seedErr != nil {
			t.Fatal(seedErr)
		}
	}
	_, err := repository.NewRetention(db).RecomputeDerivedState(context.Background(), 0, time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC), 32767)
	if err != nil {
		t.Fatalf("chunked update: %v", err)
	}
	var count int64
	if err := db.Model(&model.User{}).Where("state = ?", model.UserStateNJUPTer).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unrecomputed rows=%d", count)
	}
}
