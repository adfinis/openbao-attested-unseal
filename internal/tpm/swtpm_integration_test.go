package tpm

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSWTPMQuoteAndSealUnseal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("swtpm integration is not supported on Windows")
	}
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm is not installed")
	}
	socketPath, stop := startSWTPM(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rwc, err := (Device{Path: socketPath}).Open(ctx)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer func() {
		_ = rwc.Close()
	}()

	ak, err := CreateAK(rwc)
	if err != nil {
		t.Fatalf("CreateAK returned error: %v", err)
	}
	defer func() {
		_ = ak.Flush(rwc)
	}()
	nonce := []byte("broker nonce from swtpm test")
	selection := PCRSelection{Hash: HashSHA256, PCRs: []int{7}}
	evidence, err := CollectQuote(rwc, ak, "chal_swtpm", nonce, selection, "swtpm")
	if err != nil {
		t.Fatalf("CollectQuote returned error: %v", err)
	}
	claims, err := VerifyQuote(evidence, nonce)
	if err != nil {
		t.Fatalf("VerifyQuote returned error: %v", err)
	}
	if claims.AKPublicHash != PublicDigest(evidence.AKPublic) {
		t.Fatalf("AK hash = %q, want %q", claims.AKPublicHash, PublicDigest(evidence.AKPublic))
	}

	plaintext := bytes.Repeat([]byte{0xa5}, 32)
	sealed, err := SealKey(rwc, plaintext, PolicyModeTPMOnly, PCRSelection{})
	if err != nil {
		t.Fatalf("SealKey returned error: %v", err)
	}
	unsealed, err := UnsealKey(rwc, sealed)
	if err != nil {
		t.Fatalf("UnsealKey returned error: %v", err)
	}
	if !bytes.Equal(unsealed, plaintext) {
		t.Fatalf("unsealed = %x, want %x", unsealed, plaintext)
	}
}

func startSWTPM(t *testing.T) (string, func()) {
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
