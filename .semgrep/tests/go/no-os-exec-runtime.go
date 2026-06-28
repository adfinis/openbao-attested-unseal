package semgreptest

import (
	"context"
	"os/exec"
)

func spawn() {
	// ruleid: no-os-exec-runtime
	_ = exec.Command("sh", "-c", "true")
}

func spawnContext(ctx context.Context) {
	// ruleid: no-os-exec-runtime
	_ = exec.CommandContext(ctx, "sh", "-c", "true")
}
