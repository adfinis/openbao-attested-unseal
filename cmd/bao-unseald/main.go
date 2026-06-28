// Package main provides the attested unseal broker daemon scaffold.
package main

import (
	"fmt"
	"os"

	"github.com/dc-tec/openbao-attested-unseal/internal/cli"
	"github.com/dc-tec/openbao-attested-unseal/internal/command"
	"github.com/dc-tec/openbao-attested-unseal/internal/version"
)

func main() {
	err := command.Execute(
		command.Metadata{
			Name:    "bao-unseald",
			Summary: "Internal-network attested unseal broker daemon.",
		},
		version.BuildInfo(),
		os.Args[1:],
		os.Stdout,
		os.Stderr,
	)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ProcessExitCode(err))
	}
}
