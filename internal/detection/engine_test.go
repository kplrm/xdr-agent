package detection

import (
	"os"
	"path/filepath"
	"testing"

	"xdr-agent/internal/events"
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

func TestYARAScanFilterKeepsChangesAndSkipsReads(t *testing.T) {
	for _, test := range []struct {
		typeName string
		category string
		want     bool
	}{
		{"file.access", "file", false},
		{"file.modified", "file", true},
		{"process.start", "process", true},
		{"process.end", "process", false},
	} {
		event := events.Event{Kind: "event", Category: test.category, Type: test.typeName, Module: "telemetry.file"}
		if got := shouldScanEvent(event); got != test.want {
			t.Errorf("scan %s: got %t, want %t", test.typeName, got, test.want)
		}
	}
}
