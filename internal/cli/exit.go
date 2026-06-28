// Package cli contains shared command-line exit-code helpers.
package cli

import (
	"errors"
	"fmt"
)

// ExitCode is a stable process exit code for operator automation.
type ExitCode int

const (
	// ExitOK indicates success.
	ExitOK ExitCode = 0
	// ExitError indicates an unclassified command error.
	ExitError ExitCode = 1
	// ExitUsage indicates invalid command-line usage.
	ExitUsage ExitCode = 2
	// ExitConfig indicates invalid or unreadable local configuration.
	ExitConfig ExitCode = 3
	// ExitCheckFailed indicates one or more diagnostic checks failed.
	ExitCheckFailed ExitCode = 4
	// ExitRuntime indicates the runtime failed.
	ExitRuntime ExitCode = 5
)

// ExitErrorWithCode wraps an error with a stable process exit code.
type ExitErrorWithCode struct {
	Code ExitCode
	Err  error
}

// Error returns the wrapped error message.
func (e ExitErrorWithCode) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e ExitErrorWithCode) Unwrap() error {
	return e.Err
}

// WithExitCode attaches a stable exit code to err.
func WithExitCode(code ExitCode, err error) error {
	if err == nil {
		return nil
	}
	return ExitErrorWithCode{Code: code, Err: err}
}

// ProcessExitCode returns the process exit code for err.
func ProcessExitCode(err error) int {
	if err == nil {
		return int(ExitOK)
	}
	var coded ExitErrorWithCode
	if errors.As(err, &coded) {
		return int(coded.Code)
	}
	return int(ExitError)
}
