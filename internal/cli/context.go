package cli

import "context"

// ProcessContext is the explicit root context for short-lived CLI operations.
func ProcessContext() context.Context {
	return context.Background()
}
