package repository

import (
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
)

func TestUserRepository_ReserveStorage_RejectsNonPositiveSize(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	repo := NewUserRepository(db)
	user := &models.User{
		ID:           "user-reserve-test",
		Email:        "reserve@example.com",
		OpaqueRecord: []byte("opaque"),
		StorageQuota: 1024,
		StorageUsed:  0,
		CreatedAt:    time.Now(),
	}
	if err := repo.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	ok, err := repo.ReserveStorage(user.ID, 0)
	if err == nil {
		t.Fatal("expected error for zero-size reservation")
	}
	if ok {
		t.Fatal("expected reservation to fail for zero-size request")
	}

	ok, err = repo.ReserveStorage(user.ID, -1)
	if err == nil {
		t.Fatal("expected error for negative-size reservation")
	}
	if ok {
		t.Fatal("expected reservation to fail for negative-size request")
	}

	stored, err := repo.GetByID(user.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if stored.StorageUsed != 0 {
		t.Fatalf("expected storage_used_bytes=0, got %d", stored.StorageUsed)
	}
}
