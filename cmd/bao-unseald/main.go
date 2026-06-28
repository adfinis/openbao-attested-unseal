// Package main provides the attested unseal broker daemon scaffold.
package main

import (
	"fmt"
	"os"

	"github.com/adfinis/openbao-attested-unseal/internal/baounseald"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

func main() {
	err := baounseald.Execute(
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
