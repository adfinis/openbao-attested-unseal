// Package baounseald implements the bao-unseald command surface.
package baounseald

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dc-tec/openbao-attested-unseal/internal/broker"
	"github.com/dc-tec/openbao-attested-unseal/internal/cli"
	"github.com/dc-tec/openbao-attested-unseal/internal/version"
)

// Execute runs bao-unseald.
func Execute(info version.Info, args []string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil || stderr == nil {
		return cli.WithExitCode(cli.ExitUsage, errors.New("stdout and stderr writers are required"))
	}
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	switch args[0] {
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	case "version":
		printVersion(stdout, info)
		return nil
	case "serve":
		return serve(args[1:], stderr)
	case "config":
		return configCommand(args[1:], stdout)
	case "debug":
		return debugCommand(args[1:], stdout)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown command %q", args[0]))
	}
}

func serve(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "Path to broker JSON config.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if strings.TrimSpace(*configPath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-config is required"))
	}
	config, err := broker.LoadConfig(*configPath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := broker.ListenAndServe(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	return nil
}

func configCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected config validate"))
	}
	flags := flag.NewFlagSet("config validate", flag.ContinueOnError)
	configPath := flags.String("config", "", "Path to broker JSON config.")
	if err := flags.Parse(args[1:]); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if strings.TrimSpace(*configPath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-config is required"))
	}
	if _, err := broker.LoadConfig(*configPath); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	_, _ = fmt.Fprintln(stdout, "broker config is valid")
	return nil
}

func debugCommand(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "schema" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected debug schema"))
	}
	_, _ = fmt.Fprint(stdout, broker.SchemaSQL())
	return nil
}

func printUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, "Internal-network attested unseal broker daemon.")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Usage:")
	_, _ = fmt.Fprintln(out, "  bao-unseald help")
	_, _ = fmt.Fprintln(out, "  bao-unseald version")
	_, _ = fmt.Fprintln(out, "  bao-unseald serve -config broker.json")
	_, _ = fmt.Fprintln(out, "  bao-unseald config validate -config broker.json")
	_, _ = fmt.Fprintln(out, "  bao-unseald debug schema")
}

func printVersion(out io.Writer, info version.Info) {
	_, _ = fmt.Fprintf(out, "version: %s\n", info.Version)
	_, _ = fmt.Fprintf(out, "commit: %s\n", info.Commit)
	_, _ = fmt.Fprintf(out, "buildDate: %s\n", info.BuildDate)
	_, _ = fmt.Fprintf(out, "dirty: %s\n", info.Dirty)
}
