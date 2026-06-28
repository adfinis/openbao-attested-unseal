package semgreptest

import "log/slog"

func bad(logger *slog.Logger, token string) {
	// ruleid: no-sensitive-log-fields-runtime
	logger.Info("auth", "token", token)
}

func ok(logger *slog.Logger, keyHash string) {
	// ok: no-sensitive-log-fields-runtime
	logger.Info("decrypt", "key_id_hash", keyHash)
}
