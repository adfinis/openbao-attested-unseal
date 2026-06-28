// Package command provides the shared scaffold command behavior.
package command

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dc-tec/openbao-attested-unseal/internal/cli"
	"github.com/dc-tec/openbao-attested-unseal/internal/version"
)

// Metadata describes one command binary.
type Metadata struct {
	Name    string
	Summary string
}

// Execute runs the shared scaffold command surface.
func Execute(meta Metadata, info version.Info, args []string, stdout io.Writer, stderr io.Writer) error {
	if err := validateMetadata(meta); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if stdout == nil {
		return cli.WithExitCode(cli.ExitUsage, errors.New("stdout writer is required"))
	}
	if stderr == nil {
		return cli.WithExitCode(cli.ExitUsage, errors.New("stderr writer is required"))
	}

	if len(args) == 0 {
		printUsage(stdout, meta)
		return nil
	}

	switch args[0] {
	case "-h", "--help", "help":
		printUsage(stdout, meta)
		return nil
	case "version":
		printVersion(stdout, info)
		return nil
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown command %q", args[0]))
	}
}

func validateMetadata(meta Metadata) error {
	if strings.TrimSpace(meta.Name) == "" {
		return errors.New("command name is required")
	}
	if strings.TrimSpace(meta.Summary) == "" {
		return errors.New("command summary is required")
	}
	return nil
}

func printUsage(out io.Writer, meta Metadata) {
	_, _ = fmt.Fprintf(out, "%s\n\n", meta.Summary)
	_, _ = fmt.Fprintf(out, "Usage:\n")
	_, _ = fmt.Fprintf(out, "  %s help\n", meta.Name)
	_, _ = fmt.Fprintf(out, "  %s version\n", meta.Name)
}

func printVersion(out io.Writer, info version.Info) {
	_, _ = fmt.Fprintf(out, "version: %s\n", info.Version)
	_, _ = fmt.Fprintf(out, "commit: %s\n", info.Commit)
	_, _ = fmt.Fprintf(out, "buildDate: %s\n", info.BuildDate)
	_, _ = fmt.Fprintf(out, "dirty: %s\n", info.Dirty)
}
