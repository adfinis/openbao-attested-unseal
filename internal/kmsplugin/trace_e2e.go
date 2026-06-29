//go:build e2e

package kmsplugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const wrapperTracePathEnv = "OPENBAO_ATTESTED_UNSEAL_TRACE_FILE"

type wrapperTraceRecord struct {
	TimeUTC string `json:"time_utc"`
	wrapperTraceEvent
}

func traceWrapperEvent(event wrapperTraceEvent) {
	path := strings.TrimSpace(os.Getenv(wrapperTracePathEnv))
	if path == "" {
		return
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return
		}
	}
	// #nosec G304 -- e2e trace path is test supplied and contains only operation metadata.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() {
		_ = file.Close()
	}()
	record := wrapperTraceRecord{
		TimeUTC:           time.Now().UTC().Format(time.RFC3339Nano),
		wrapperTraceEvent: event,
	}
	_ = json.NewEncoder(file).Encode(record)
}
