package config

import (
	"os"
	"strings"
)

// EnvOrDefault returns a trimmed environment value or fallback when unset.
func EnvOrDefault(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
