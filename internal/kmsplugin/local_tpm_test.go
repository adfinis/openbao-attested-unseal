package kmsplugin

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestWrapperLocalTPMEncryptDecryptWithSWTPM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("swtpm integration is not supported on Windows")
	}
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm is not installed")
	}
	socketPath, stop := startSWTPMForPlugin(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statePath := t.TempDir()
	ref := keyring.KeyRef{ClusterID: "prod-eu1", KeyID: "root", Version: 1}
	material := bytes.Repeat([]byte{0x42}, keyring.KeySize)
	if _, err := tpmlocal.StoreLocalKey(
		ctx,
		statePath,
		tpmlocal.Device{Path: socketPath},
		keyring.KeyVersion{
			Ref:       ref,
			Status:    keyring.StatusActive,
			Algorithm: keyring.AlgorithmAES256GCM,
			PolicyID:  "secureboot",
			Material:  material,
		},
		tpmlocal.PolicyModeTPMOnly,
		tpmlocal.PCRSelection{},
	); err != nil {
		t.Fatalf("StoreLocalKey returned error: %v", err)
	}

	wrapper := NewWrapper()
	if _, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		configKeyMode:       string(ModeLocalTPM),
		configKeyClusterID:  ref.ClusterID,
		configKeyKeyID:      ref.KeyID,
		configKeyKeyVersion: "1",
		configKeyPolicyID:   "secureboot",
		configKeyStatePath:  statePath,
		configKeyTPMDevice:  socketPath,
	})); err != nil {
		t.Fatalf("SetConfig returned error: %v", err)
	}
	if err := wrapper.Init(ctx); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}
	defer func() {
		_ = wrapper.Finalize(context.Background())
	}()

	blob, err := wrapper.Encrypt(ctx, []byte("seal plaintext"), wrapping.WithAad([]byte("aad")))
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	plaintext, err := wrapper.Decrypt(ctx, blob, wrapping.WithAad([]byte("aad")))
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if string(plaintext) != "seal plaintext" {
		t.Fatalf("plaintext = %q, want seal plaintext", plaintext)
	}
	keyID, err := wrapper.KeyId(ctx)
	if err != nil {
		t.Fatalf("KeyId returned error: %v", err)
	}
	if keyID != ref.String() {
		t.Fatalf("KeyId = %q, want %q", keyID, ref.String())
	}
}

func startSWTPMForPlugin(t *testing.T) (string, func()) {
	t.Helper()
	baseDir, err := os.MkdirTemp("/tmp", "bao-swtpm-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(baseDir)
	})
	stateDir := filepath.Join(baseDir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	socketPath := filepath.Join(baseDir, "swtpm.sock")
	ctrlPath := filepath.Join(baseDir, "swtpm.ctrl")
	logPath := filepath.Join(baseDir, "swtpm.log")
	//nolint:gosec // Test harness starts the local swtpm binary with controlled temporary paths.
	cmd := exec.Command(
		"swtpm",
		"socket",
		"--tpm2",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=unixio,path="+ctrlPath,
		"--server", "type=unixio,path="+socketPath,
		"--flags", "not-need-init,startup-clear",
		"--log", "file="+logPath+",level=1",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("swtpm socket was not created; log path: %s", logPath)
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop := func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}
	return socketPath, stop
}
