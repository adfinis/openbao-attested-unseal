package version

import "testing"

func TestBuildInfoDefaults(t *testing.T) {
	info := BuildInfo()
	if info.Version == "" {
		t.Fatal("version must not be empty")
	}
	if info.Commit == "" {
		t.Fatal("commit must not be empty")
	}
	if info.BuildDate == "" {
		t.Fatal("build date must not be empty")
	}
	if info.Dirty == "" {
		t.Fatal("dirty must not be empty")
	}
}
