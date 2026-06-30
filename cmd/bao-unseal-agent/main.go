// Package main provides the node-local attested unseal evidence agent.
package main

import (
	"fmt"
	"os"

	"github.com/adfinis/openbao-attested-unseal/internal/baounsealagent"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

func main() {
	err := baounsealagent.Execute(
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
