package recovery

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestRecoveryThresholdSucceedsAtThreshold(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	pkg, err := Create("rpkg_test", "prod-eu1", "root", secret, 3, 5, time.Now())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	got, err := Recover(pkg.Metadata, pkg.Shares[:3])
	if err != nil {
		t.Fatalf("Recover returned error: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("secret mismatch")
	}
}

func TestRecoveryThresholdFailsBelowThreshold(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	pkg, err := Create("rpkg_test", "prod-eu1", "root", secret, 3, 5, time.Now())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	_, err = Recover(pkg.Metadata, pkg.Shares[:2])
	if !errors.Is(err, ErrThreshold) {
		t.Fatalf("Recover error = %v, want ErrThreshold", err)
	}
}

func TestRecoveryWrongShareRejected(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	pkg, err := Create("rpkg_test", "prod-eu1", "root", secret, 3, 5, time.Now())
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	other, err := Create("rpkg_other", "prod-eu1", "root", secret, 3, 5, time.Now())
	if err != nil {
		t.Fatalf("Create other returned error: %v", err)
	}
	_, err = Recover(pkg.Metadata, []string{pkg.Shares[0], pkg.Shares[1], other.Shares[2]})
	if err == nil {
		t.Fatal("Recover returned nil error for wrong share")
	}
}
