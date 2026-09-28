package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPermissionResponse(t *testing.T) {
	for _, deny := range []bool{false, true} {
		response := permissionResponse(42, deny)
		want := uint32(unix.FAN_ALLOW)
		if deny {
			want = unix.FAN_DENY
		}
		if binary.NativeEndian.Uint32(response[:4]) != 42 || binary.NativeEndian.Uint32(response[4:]) != want {
			t.Fatal("incorrect kernel response")
		}
	}
}
func TestParseExecutionRequests(t *testing.T) {
	data := make([]byte, 24)
	binary.NativeEndian.PutUint32(data[:4], 24)
	data[4] = unix.FANOTIFY_METADATA_VERSION
	binary.NativeEndian.PutUint64(data[8:16], unix.FAN_OPEN_EXEC_PERM)
	binary.NativeEndian.PutUint32(data[16:20], 42)
	binary.NativeEndian.PutUint32(data[20:24], 123)
	requests, err := parseExecRequests(data)
	if err != nil || len(requests) != 1 || requests[0].fd != 42 || requests[0].pid != 123 {
		t.Fatalf("%v %v", requests, err)
	}
	if _, err := parseExecRequests(data[:12]); err == nil {
		t.Fatal("accepted truncated event")
	}
	binary.NativeEndian.PutUint64(data[8:16], unix.FAN_Q_OVERFLOW)
	binary.NativeEndian.PutUint32(data[16:20], 0xffffffff)
	if _, err := parseExecRequests(data); err == nil {
		t.Fatal("lost overflow warning")
	}
}

func TestQueuedExecutionDecisionExpiresOpen(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "pending-*")
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	called := false
	var reported error
	ctx, cancel := context.WithCancel(context.Background())
	guard := &ExecGuard{fd: int(writer.Fd()), cancel: cancel, scan: func(context.Context, *os.File, int) (bool, error) {
		called = true
		return true, nil
	}, report: func(err error) { reported = err }}
	guard.decide(ctx, execRequest{fd: int(file.Fd()), pid: 123, deadline: time.Now().Add(-time.Second)})
	response := make([]byte, 8)
	if _, err := io.ReadFull(reader, response); err != nil {
		t.Fatal(err)
	}
	if called || reported == nil || ctx.Err() == nil || binary.NativeEndian.Uint32(response[4:]) != unix.FAN_ALLOW {
		t.Fatalf("expired request: scan=%t report=%v response=%v", called, reported, response)
	}
}

func TestExecutionWatchCapAndRefresh(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	marked := make(map[string]os.FileInfo)
	for i := 0; i < maxExecutionDirectoryWatches-1; i++ {
		marked[strconv.Itoa(i)] = nil
	}
	calls := 0
	var markedPaths []string
	mark := func(path string) error {
		calls++
		markedPaths = append(markedPaths, path)
		return nil
	}
	added, err := walkExecutionRoot(root, marked, mark)
	if !errors.Is(err, errExecutionWatchLimit) || added != 1 || calls != 1 || len(marked) != maxExecutionDirectoryWatches {
		t.Fatalf("cap: added=%d calls=%d total=%d err=%v", added, calls, len(marked), err)
	}
	if _, exists := marked[filepath.Join(root, "a")]; exists {
		t.Fatal("marked directory beyond cap")
	}
	fresh := make(map[string]os.FileInfo)
	added, err = walkExecutionRoot(root, fresh, mark)
	if err != nil || added != 3 {
		t.Fatalf("initial walk: added=%d err=%v", added, err)
	}
	added, err = walkExecutionRoot(root, fresh, mark)
	if err != nil || added != 0 || calls != 4 {
		t.Fatalf("refresh remarked existing directories: added=%d calls=%d err=%v", added, calls, err)
	}
	if err := os.Remove(filepath.Join(root, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "a"), 0700); err != nil {
		t.Fatal(err)
	}
	before := len(markedPaths)
	added, err = walkExecutionRoot(root, fresh, mark)
	if err != nil || added == 0 {
		t.Fatalf("replaced directory was not remarked: added=%d err=%v", added, err)
	}
	replacedWasMarked := false
	for _, path := range markedPaths[before:] {
		if path == filepath.Join(root, "a") {
			replacedWasMarked = true
		}
	}
	if !replacedWasMarked {
		t.Fatal("replacement inode did not receive a new watch")
	}
}

func TestExecutionPreflightRejectsOversizedTree(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := preflightExecutionRoots([]string{root}, 2); !errors.Is(err, errExecutionWatchLimit) {
		t.Fatalf("oversized tree was accepted: %v", err)
	}
	if err := preflightExecutionRoots([]string{root}, 3); err != nil {
		t.Fatalf("three-directory tree was rejected: %v", err)
	}
}

func TestIncompleteExecutionWatchSetupFails(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	marked := make(map[string]os.FileInfo)
	for i := 0; i < maxExecutionDirectoryWatches-1; i++ {
		marked[strconv.Itoa(i)] = nil
	}
	guard := &ExecGuard{paths: []string{root}, marked: marked}
	calls := 0
	err := guard.markDirectoriesWith(func(string) error { calls++; return nil })
	if !errors.Is(err, errExecutionWatchLimit) || calls != 1 {
		t.Fatalf("incomplete watch setup stayed active: calls=%d err=%v", calls, err)
	}
}
