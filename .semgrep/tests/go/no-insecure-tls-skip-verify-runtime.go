package semgreptest

import "crypto/tls"

func insecure() *tls.Config {
	// ruleid: no-insecure-tls-skip-verify-runtime
	return &tls.Config{InsecureSkipVerify: true}
}

func secure() *tls.Config {
	// ok: no-insecure-tls-skip-verify-runtime
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
