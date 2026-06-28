package command

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dc-tec/openbao-attested-unseal/internal/cli"
	"github.com/dc-tec/openbao-attested-unseal/internal/version"
)

func TestExecuteVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(
		Metadata{Name: "bao-unsealctl", Summary: "test command"},
		version.Info{Version: "1.2.3", Commit: "abc", BuildDate: "now", Dirty: "false"},
		[]string{"version"},
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "version: 1.2.3") {
		t.Fatalf("version output missing version: %q", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(
		Metadata{Name: "bao-unsealctl", Summary: "test command"},
		version.Info{Version: "1.2.3", Commit: "abc", BuildDate: "now", Dirty: "false"},
		[]string{"unknown"},
		&stdout,
		&stderr,
	)
	if err == nil {
		t.Fatal("Execute returned nil error")
	}
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitUsage)
	}
}
