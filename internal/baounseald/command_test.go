package baounseald

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

func TestConfigValidate(t *testing.T) {
	configPath := writeConfig(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(
		version.Info{Version: "test", Commit: "abc", BuildDate: "now", Dirty: "false"},
		[]string{"config", "validate", "-config", configPath},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "broker config is valid") {
		t.Fatalf("stdout = %q, want valid config message", stdout.String())
	}
}

func TestConfigValidateRejectsMissingPath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(
		version.Info{Version: "test"},
		[]string{"config", "validate"},
		&stdout,
		&stderr,
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitUsage)
	}
}

func TestDebugSchema(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(
		version.Info{Version: "test"},
		[]string{"debug", "schema"},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "CREATE TABLE IF NOT EXISTS challenges") {
		t.Fatalf("schema output missing challenges table")
	}
}

func writeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "broker.json")
	key := bytes.Repeat([]byte{1}, keyring.KeySize)
	raw := `{
  "listen_address": "127.0.0.1:0",
  "allow_plaintext_for_tests": true,
  "sqlite_path": "` + filepath.Join(dir, "broker.db") + `",
  "audit_file_path": "` + filepath.Join(dir, "audit.jsonl") + `",
  "otel_exporter": "none",
  "keyring_protection_profile": "development",
  "cluster_id": "prod-eu1",
  "key_id": "root",
  "policy_id": "development",
  "development_subject": "node-a",
  "development_wrapping_key_b64": "` + base64.StdEncoding.EncodeToString(key) + `",
  "challenge_ttl_seconds": 60
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}
