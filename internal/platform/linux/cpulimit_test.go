package linux

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLimitCPUsIncludesChildProcesses(t *testing.T) {
	const helper = "XDR_CPU_LIMIT_TEST"
	switch os.Getenv(helper) {
	case "child":
		var affinity unix.CPUSet
		if err := unix.SchedGetaffinity(0, &affinity); err != nil || affinity.Count() != 1 {
			t.Fatalf("child affinity = %d CPUs, error = %v", affinity.Count(), err)
		}
	case "parent":
		count, err := LimitCPUs(1)
		if err != nil || count != 1 {
			t.Fatalf("LimitCPUs(1) = %d, %v", count, err)
		}
		var affinity unix.CPUSet
		if err := unix.SchedGetaffinity(0, &affinity); err != nil || affinity.Count() != 1 {
			t.Fatalf("agent affinity = %d CPUs, error = %v", affinity.Count(), err)
		}
		if ok, err := allThreadsLimited(&affinity); err != nil || !ok {
			t.Fatalf("agent threads not limited: %v", err)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestLimitCPUsIncludesChildProcesses$")
		child.Env = append(os.Environ(), helper+"=child")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("child did not inherit CPU limit: %v\n%s", err, output)
		}
	default:
		parent := exec.Command(os.Args[0], "-test.run=^TestLimitCPUsIncludesChildProcesses$")
		parent.Env = append(os.Environ(), helper+"=parent")
		if output, err := parent.CombinedOutput(); err != nil {
			t.Fatalf("CPU limit helper failed: %v\n%s", err, output)
		}
	}
}

func TestZeroKeepsInheritedAffinity(t *testing.T) {
	var before, after unix.CPUSet
	if err := unix.SchedGetaffinity(0, &before); err != nil {
		t.Fatal(err)
	}
	if count, err := LimitCPUs(0); err != nil || count != 0 {
		t.Fatalf("LimitCPUs(0) = %d, %v", count, err)
	}
	if err := unix.SchedGetaffinity(0, &after); err != nil || before != after {
		t.Fatalf("zero changed inherited affinity: %v", err)
	}
	if _, err := LimitCPUs(-1); err == nil {
		t.Fatal("negative max_cpu_cores accepted")
	}
}
