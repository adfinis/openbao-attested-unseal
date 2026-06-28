// Package main provides the OpenBao KMS plugin binary scaffold.
package main

import (
	"fmt"
	"os"

	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/command"
	"github.com/adfinis/openbao-attested-unseal/internal/kmsplugin"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

func main() {
	if kmsplugin.ShouldServePlugin() {
		kmsplugin.ServePlugin()
		return
	}

	err := command.Execute(
		command.Metadata{
			Name:    "bao-kms-unseal",
			Summary: "OpenBao KMS plugin entrypoint for attested unseal.",
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
