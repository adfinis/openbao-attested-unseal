// Package main provides the attested unseal operator CLI scaffold.
package main

import (
	"fmt"
	"os"

	"github.com/adfinis/openbao-attested-unseal/internal/baounsealctl"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

func main() {
	err := baounsealctl.Execute(
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
