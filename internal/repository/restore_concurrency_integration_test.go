package repository_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/model"
	"github.com/NJUPT-SAST/sast-link-backend-v2/internal/repository"
)

func TestManagerRestoreSerializesTargetRoleChanges(t *testing.T) {
	database := setupDatabase(t)
	users := repository.NewUser(database)
	adminSeed(t, database, "restore-guard-admin@sast.fun", "管理员",
		model.UserRoleAdmin, model.UserStateOnSAST, nil)
	target := testUser("b24000001@njupt.edu.cn")
	target.StudentID = "B24000001"
	target.Role = model.UserRoleMember
	target.State = model.UserStateDeleted
	if err := users.CreateWithProfile(context.Background(), target, &model.Profile{}); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type restoreMarker struct{}
	marker := restoreMarker{}
	paused := make(chan int, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unpause := func() { releaseOnce.Do(func() { close(release) }) }
	defer unpause()
	// Pause the manager after its target read and role check, before UPDATE.
	// Only this request carries the marker; the administrator uses the real
	// repository methods without being intercepted by this callback.
	const callbackName = "test:pause_manager_restore"
	if err := database.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Context.Value(marker) != true {
			return
		}
		var pid int
		if err := tx.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
			_ = tx.AddError(err)
			return
		}
		paused <- pid
		select {
		case <-release:
		case <-ctx.Done():
			_ = tx.AddError(ctx.Err())
		}
	}); err != nil {
		t.Fatalf("register pause: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Callback().Update().Remove(callbackName); err != nil {
			t.Errorf("remove pause: %v", err)
		}
	})
	managerDone := make(chan error, 1)
	go func() {
		managerDone <- users.RestoreUser(context.WithValue(ctx, marker, true), target.ID,
			model.UserRoleManager, time.Now().UTC())
	}()
	var managerPID int
	select {
	case managerPID = <-paused:
	case err := <-managerDone:
		t.Fatalf("manager did not reach restore UPDATE: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	adminDone := make(chan error, 1)
	go func() {
		// Once the manager wins, the administrator sees an already-live row.
		if err := users.RestoreUser(ctx, target.ID, model.UserRoleAdmin, time.Now().UTC()); err != nil && !errors.Is(err, repository.ErrStateConflict) {
			adminDone <- err
			return
		}
		role := model.UserRoleAdmin
		if _, _, err := users.UpdateAdminUser(ctx, target.ID, repository.AdminUserUpdate{Role: &role},
			model.UserRoleAdmin, time.Now().UTC()); err != nil {
			adminDone <- err
			return
		}
		_, err := users.SoftDeleteAndRevokeSessions(ctx, target.ID, model.UserRoleAdmin, time.Now().UTC())
		adminDone <- err
	}()

	// Observe a real PostgreSQL lock wait, not a scheduling-dependent sleep.
	for {
		select {
		case err := <-adminDone:
			t.Fatalf("administrator changed the target while manager restore was paused: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}
		var blocked bool
		if err := database.WithContext(ctx).Raw(`SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity
			WHERE ? = ANY(pg_blocking_pids(pid)) AND wait_event_type = 'Lock'
		)`, managerPID).Scan(&blocked).Error; err != nil {
			t.Fatalf("observe restore lock: %v", err)
		}
		if blocked {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	unpause()
	if err := <-managerDone; err != nil {
		t.Fatalf("manager restore: %v", err)
	}
	if err := <-adminDone; err != nil {
		t.Fatalf("administrator transition: %v", err)
	}
	var stored model.User
	if err := database.First(&stored, target.ID).Error; err != nil {
		t.Fatalf("reload target: %v", err)
	}
	if stored.Role != model.UserRoleAdmin || stored.State != model.UserStateDeleted {
		t.Fatalf("target = %s/%s, want admin/is_deleted", stored.Role, stored.State)
	}
	if err := users.RestoreUser(ctx, target.ID, model.UserRoleManager, time.Now().UTC()); !errors.Is(err, repository.ErrAdminTarget) {
		t.Fatalf("manager restore of deleted admin: %v, want ErrAdminTarget", err)
	}
}
