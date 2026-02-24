package repository

import (
	"testing"
	"time"

	"github.com/SecuShare/SecuShare/backend/internal/models"
	"github.com/SecuShare/SecuShare/backend/pkg/testutil"
	"github.com/google/uuid"
)

func newSession(ip string) *models.GuestSession {
	return &models.GuestSession{
		ID:           uuid.New().String(),
		IPAddress:    &ip,
		StorageQuota: 10485760, // 10MB
		StorageUsed:  0,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}
}

func TestGuestSessionRepository_ReserveStorage_SharedIPQuota(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	repo := NewGuestSessionRepository(db)
	ip := "203.0.113.1"

	// Two sessions from the same IP share a 10MB quota.
	s1 := newSession(ip)
	s2 := newSession(ip)
	if err := repo.Create(s1); err != nil {
		t.Fatalf("create s1: %v", err)
	}
	if err := repo.Create(s2); err != nil {
		t.Fatalf("create s2: %v", err)
	}

	const mb5 = 5 * 1024 * 1024

	// s1 reserves 5MB — should succeed.
	ok, err := repo.ReserveStorage(s1.ID, mb5)
	if err != nil || !ok {
		t.Fatalf("expected reservation on s1 to succeed, got ok=%v err=%v", ok, err)
	}

	// s2 reserves another 5MB — total reaches 10MB, should succeed.
	ok, err = repo.ReserveStorage(s2.ID, mb5)
	if err != nil || !ok {
		t.Fatalf("expected reservation on s2 to succeed, got ok=%v err=%v", ok, err)
	}

	// Any further reservation from either session must be rejected.
	ok, err = repo.ReserveStorage(s1.ID, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected reservation to be rejected after IP quota exhausted")
	}
}

func TestGuestSessionRepository_ReserveStorage_IsolatedAcrossIPs(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	repo := NewGuestSessionRepository(db)

	sA := newSession("203.0.113.1")
	sB := newSession("203.0.113.2")
	if err := repo.Create(sA); err != nil {
		t.Fatalf("create sA: %v", err)
	}
	if err := repo.Create(sB); err != nil {
		t.Fatalf("create sB: %v", err)
	}

	// Exhaust IP A's quota entirely.
	ok, err := repo.ReserveStorage(sA.ID, 10485760)
	if err != nil || !ok {
		t.Fatalf("expected full reservation on sA to succeed, got ok=%v err=%v", ok, err)
	}

	// IP B is unaffected and can still reserve.
	ok, err = repo.ReserveStorage(sB.ID, 10485760)
	if err != nil || !ok {
		t.Fatalf("expected full reservation on sB to succeed, got ok=%v err=%v", ok, err)
	}
}

func TestGuestSessionRepository_GetIPStorageInfo(t *testing.T) {
	db, _, cleanup := testutil.SetupTest(t)
	defer cleanup()

	repo := NewGuestSessionRepository(db)
	ip := "203.0.113.5"

	s1 := newSession(ip)
	s2 := newSession(ip)
	if err := repo.Create(s1); err != nil {
		t.Fatalf("create s1: %v", err)
	}
	if err := repo.Create(s2); err != nil {
		t.Fatalf("create s2: %v", err)
	}

	const mb3 = 3 * 1024 * 1024
	const mb4 = 4 * 1024 * 1024

	repo.ReserveStorage(s1.ID, mb3)
	repo.ReserveStorage(s2.ID, mb4)

	info, err := repo.GetIPStorageInfo(s1.ID)
	if err != nil {
		t.Fatalf("GetIPStorageInfo: %v", err)
	}

	expected := int64(mb3 + mb4)
	if info.Used != expected {
		t.Errorf("expected Used=%d, got %d", expected, info.Used)
	}
	if info.Quota != 10485760 {
		t.Errorf("expected Quota=10485760, got %d", info.Quota)
	}
	if info.Free != info.Quota-info.Used {
		t.Errorf("Free mismatch: quota=%d used=%d free=%d", info.Quota, info.Used, info.Free)
	}
}
