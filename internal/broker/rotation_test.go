package broker

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestRotationStartActivateTransitions(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	oldBlob := encryptOldRotationBlob(t, store, config)

	operation := startTestRotation(t, store, config, "rot_test", 2)
	if operation.FromVersion != 1 || operation.ToVersion != 2 || operation.Status != RotationStatusStarted {
		t.Fatalf("operation = %#v, want v1 -> v2 started", operation)
	}
	assertKeyStatus(t, store, config, 1, keyring.StatusActive)
	assertKeyStatus(t, store, config, 2, keyring.StatusPending)

	operation = activateTestRotation(t, store, "rot_test")
	if operation.Status != RotationStatusActivated {
		t.Fatalf("operation status = %q, want activated", operation.Status)
	}
	assertKeyStatus(t, store, config, 1, keyring.StatusDecryptOnly)
	assertKeyStatus(t, store, config, 2, keyring.StatusActive)
	assertActivatedRotationDecryptsOldBlob(t, store, config, oldBlob)

	replayed := activateTestRotation(t, store, "rot_test")
	if replayed.Status != RotationStatusActivated {
		t.Fatalf("replayed status = %q, want activated", replayed.Status)
	}
}

func TestRotationStartRejectsSecondStartedOperation(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	startTestRotation(t, store, config, "rot_first", 2)
	request := testRotationStartRequest(config, "rot_second", 3)
	if _, err := store.StartRotation(context.Background(), request); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("second StartRotation error = %v, want ErrRotationInProgress", err)
	}
}

func TestRotationActivateRejectsUnknownOperation(t *testing.T) {
	store := newTestStore(t, testConfig(t))
	_, err := store.ActivateRotation(context.Background(), "rot_missing", time.Now())
	if !errors.Is(err, ErrRotationNotFound) {
		t.Fatalf("ActivateRotation error = %v, want ErrRotationNotFound", err)
	}
}

func TestRotationVerificationsRecordAndRefresh(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	startTestRotation(t, store, config, "rot_test", 2)

	first, err := store.RecordRotationVerification(
		context.Background(),
		"rot_test",
		RotationVerificationOpenBAORoot,
		"HTTP 204",
		time.Unix(100, 0).UTC(),
	)
	if err != nil {
		t.Fatalf("RecordRotationVerification returned error: %v", err)
	}
	if first.Name != RotationVerificationOpenBAORoot || first.Detail != "HTTP 204" {
		t.Fatalf("verification = %#v, want openbao-root HTTP 204", first)
	}
	refreshed, err := store.RecordRotationVerification(
		context.Background(),
		"rot_test",
		RotationVerificationOpenBAORoot,
		"HTTP 200",
		time.Unix(200, 0).UTC(),
	)
	if err != nil {
		t.Fatalf("RecordRotationVerification refresh returned error: %v", err)
	}
	if !refreshed.VerifiedAt.Equal(time.Unix(200, 0).UTC()) {
		t.Fatalf("refreshed time = %s, want unix 200", refreshed.VerifiedAt)
	}
	verifications, err := store.RotationVerifications(context.Background(), "rot_test")
	if err != nil {
		t.Fatalf("RotationVerifications returned error: %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("verifications = %d, want 1", len(verifications))
	}
	if verifications[0].Detail != "HTTP 200" {
		t.Fatalf("verification detail = %q, want HTTP 200", verifications[0].Detail)
	}
}

func TestRotationVerificationRejectsUnknownOperation(t *testing.T) {
	store := newTestStore(t, testConfig(t))
	_, err := store.RecordRotationVerification(
		context.Background(),
		"rot_missing",
		RotationVerificationOpenBAORoot,
		"HTTP 204",
		time.Now(),
	)
	if !errors.Is(err, ErrRotationNotFound) {
		t.Fatalf("RecordRotationVerification error = %v, want ErrRotationNotFound", err)
	}
}

func assertKeyStatus(t *testing.T, store *SQLiteStore, config Config, version uint32, status keyring.Status) {
	t.Helper()
	got, err := store.KeyVersion(context.Background(), keyring.KeyRef{
		ClusterID: config.ClusterID,
		KeyID:     config.KeyID,
		Version:   version,
	})
	if err != nil {
		t.Fatalf("KeyVersion v%d returned error: %v", version, err)
	}
	if got.Status != status {
		t.Fatalf("key v%d status = %q, want %q", version, got.Status, status)
	}
}

func encryptOldRotationBlob(t *testing.T, store *SQLiteStore, config Config) *wrapping.BlobInfo {
	t.Helper()
	oldRing, err := store.LoadKeyring(context.Background(), config.ClusterID)
	if err != nil {
		t.Fatalf("LoadKeyring returned error: %v", err)
	}
	oldBlob, err := oldRing.Encrypt(context.Background(), []byte("old seal plaintext"), nil)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	return oldBlob
}

func startTestRotation(
	t *testing.T,
	store *SQLiteStore,
	config Config,
	operationID string,
	materialSeed byte,
) RotationOperation {
	t.Helper()
	operation, err := store.StartRotation(
		context.Background(),
		testRotationStartRequest(config, operationID, materialSeed),
	)
	if err != nil {
		t.Fatalf("StartRotation returned error: %v", err)
	}
	return operation
}

func testRotationStartRequest(config Config, operationID string, materialSeed byte) RotationStartRequest {
	return RotationStartRequest{
		OperationID: operationID,
		ClusterID:   config.ClusterID,
		KeyID:       config.KeyID,
		PolicyID:    config.Policy(),
		Material:    bytes.Repeat([]byte{materialSeed}, keyring.KeySize),
		CreatedAt:   time.Now(),
	}
}

func activateTestRotation(t *testing.T, store *SQLiteStore, operationID string) RotationOperation {
	t.Helper()
	operation, err := store.ActivateRotation(context.Background(), operationID, time.Now())
	if err != nil {
		t.Fatalf("ActivateRotation returned error: %v", err)
	}
	return operation
}

func assertActivatedRotationDecryptsOldBlob(
	t *testing.T,
	store *SQLiteStore,
	config Config,
	oldBlob *wrapping.BlobInfo,
) {
	t.Helper()
	newRing, err := store.LoadKeyring(context.Background(), config.ClusterID)
	if err != nil {
		t.Fatalf("LoadKeyring after activation returned error: %v", err)
	}
	active, err := newRing.Active(context.Background())
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if active.Ref.Version != 2 {
		t.Fatalf("active version = %d, want 2", active.Ref.Version)
	}
	plaintext, err := newRing.Decrypt(context.Background(), oldBlob, nil)
	if err != nil {
		t.Fatalf("Decrypt old blob returned error: %v", err)
	}
	if string(plaintext) != "old seal plaintext" {
		t.Fatalf("old plaintext = %q, want old seal plaintext", plaintext)
	}
}
