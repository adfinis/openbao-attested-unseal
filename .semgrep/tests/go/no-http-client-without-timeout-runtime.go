package semgreptest

import (
	"net/http"
	"time"
)

func unbounded() *http.Client {
	// ruleid: no-http-client-without-timeout-runtime
	return &http.Client{}
}

func bounded() *http.Client {
	// ok: no-http-client-without-timeout-runtime
	return &http.Client{Timeout: 2 * time.Second}
}
