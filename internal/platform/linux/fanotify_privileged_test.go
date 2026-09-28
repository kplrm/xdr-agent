package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run with XDR_REQUIRE_FANOTIFY=1 inside a disposable privileged container.
func TestExecGuardPrivilegedAllowAndDeny(t *testing.T) {
	root := t.TempDir()
	executable := copyExecutionFixture(t, root)
	var deny atomic.Bool
	var decisions atomic.Int32
	guard, err := NewExecGuard([]string{root}, nil, func(_ context.Context, _ *os.File, _ int) (bool, error) {
		decisions.Add(1)
		return deny.Load(), nil
	}, func(err error) { t.Logf("fanotify: %v", err) })
	if err != nil {
		if os.Getenv("XDR_REQUIRE_FANOTIFY") != "1" && errors.Is(err, unix.EPERM) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	run := func() error {
		deadline, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		return exec.CommandContext(deadline, executable).Run()
	}
	if err := run(); err != nil {
		t.Fatalf("clean executable blocked or stalled: %v", err)
	}
	deny.Store(true)
	if err := run(); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("matched executable was not denied promptly: %v", err)
	}
	if decisions.Load() < 2 {
		t.Fatalf("fanotify decisions = %d, want at least two", decisions.Load())
	}
}

func copyExecutionFixture(t *testing.T, root string) string {
	t.Helper()
	fixture := os.Getenv("XDR_EXEC_FIXTURE")
	if fixture == "" {
		fixture = "/bin/true"
	}
	content, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "true")
	if err := os.WriteFile(executable, content, 0755); err != nil {
		t.Fatal(err)
	}
	return executable
}

// A slow scanner must release the pending launch promptly and disable blocking.
func TestExecGuardPrivilegedSlowScanFailsOpen(t *testing.T) {
	root := t.TempDir()
	executable := copyExecutionFixture(t, root)
	var scanned atomic.Int32
	guard, err := NewExecGuard([]string{root}, nil, func(ctx context.Context, _ *os.File, _ int) (bool, error) {
		scanned.Add(1)
		<-ctx.Done()
		return false, ctx.Err()
	}, func(err error) { t.Logf("fanotify: %v", err) })
	if err != nil {
		if os.Getenv("XDR_REQUIRE_FANOTIFY") != "1" && errors.Is(err, unix.EPERM) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	deadline, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	started := time.Now()
	if err := exec.CommandContext(deadline, executable).Run(); err != nil {
		t.Fatalf("slow scan stalled a clean executable: %v", err)
	}
	if scanned.Load() == 0 || time.Since(started) > 1500*time.Millisecond {
		t.Fatalf("slow scan was not bounded: scans=%d elapsed=%s", scanned.Load(), time.Since(started))
	}
}

// An oversized tree must be rejected before it can block any host launch.
func TestExecGuardPrivilegedOversizedTreeFailsOpen(t *testing.T) {
	root := t.TempDir()
	executable := copyExecutionFixture(t, root)
	for i := 0; i < maxExecutionDirectoryWatches; i++ {
		if err := os.Mkdir(filepath.Join(root, fmt.Sprintf("d-%04d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	guard, err := NewExecGuard([]string{root}, nil, func(context.Context, *os.File, int) (bool, error) {
		t.Fatal("scanner ran after oversized watch set was rejected")
		return false, nil
	}, func(err error) { t.Logf("fanotify: %v", err) })
	if err != nil {
		if os.Getenv("XDR_REQUIRE_FANOTIFY") != "1" && errors.Is(err, unix.EPERM) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	if err := guard.Start(context.Background()); !errors.Is(err, errExecutionWatchLimit) {
		t.Fatalf("oversized watch tree was accepted: %v", err)
	}
	deadline, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := exec.CommandContext(deadline, executable).Run(); err != nil {
		t.Fatalf("execution remained blocked after oversized watch rejection: %v", err)
	}
}

// The YARA child must bypass its own permission guard or scans recurse.
func TestExecGuardPrivilegedHelperDoesNotRecurse(t *testing.T) {
	root := t.TempDir()
	executable := copyExecutionFixture(t, root)
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "yara-helper")
	if err := os.WriteFile(helper, content, 0755); err != nil {
		t.Fatal(err)
	}
	var scans atomic.Int32
	guard, err := NewExecGuard([]string{root}, []string{helper}, func(ctx context.Context, _ *os.File, _ int) (bool, error) {
		scans.Add(1)
		return false, exec.CommandContext(ctx, helper).Run()
	}, func(err error) { t.Logf("fanotify: %v", err) })
	if err != nil {
		if os.Getenv("XDR_REQUIRE_FANOTIFY") != "1" && errors.Is(err, unix.EPERM) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	deadline, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if err := exec.CommandContext(deadline, executable).Run(); err != nil {
		t.Fatalf("helper recursion stalled execution: %v", err)
	}
	if scans.Load() != 1 {
		t.Fatalf("helper triggered %d scans, want one", scans.Load())
	}
}
