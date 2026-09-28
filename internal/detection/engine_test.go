package detection

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnExecutableIncludesSymlinks(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "yara")
	other := filepath.Join(dir, "other")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(helper, []byte("helper"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("other"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(helper, alias); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(helper)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{helperFiles: []os.FileInfo{info}}
	if !engine.isOwnExecutable(alias) || engine.isOwnExecutable(other) {
		t.Fatal("YARA helper exclusion failed")
	}
}
