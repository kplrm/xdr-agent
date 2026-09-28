package linux

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LimitCPUs pins all agent threads to at most max logical CPUs. Child processes,
// including YARA, inherit the affinity mask. Zero keeps the inherited limit.
func LimitCPUs(max int) (int, error) {
	if max < 0 {
		return 0, fmt.Errorf("max_cpu_cores must be >= 0")
	}
	if max == 0 {
		return 0, nil
	}

	var allowed, chosen unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		return 0, fmt.Errorf("read CPU affinity: %w", err)
	}
	for cpu := 0; cpu < int(unsafe.Sizeof(allowed))*8 && chosen.Count() < max; cpu++ {
		if allowed.IsSet(cpu) {
			chosen.Set(cpu)
		}
	}
	count := chosen.Count()
	if count == 0 {
		return 0, fmt.Errorf("no available CPUs in inherited affinity mask")
	}

	// Affinity is per thread. Repeat if the Go runtime creates a thread while
	// applying the mask; future threads inherit it from already limited threads.
	for attempt := 0; attempt < 5; attempt++ {
		tasks, err := os.ReadDir("/proc/self/task")
		if err != nil {
			return 0, fmt.Errorf("list agent threads: %w", err)
		}
		for _, task := range tasks {
			tid, err := strconv.Atoi(task.Name())
			if err != nil {
				return 0, fmt.Errorf("invalid thread ID %q: %w", task.Name(), err)
			}
			if err := unix.SchedSetaffinity(tid, &chosen); err != nil && err != unix.ESRCH {
				return 0, fmt.Errorf("limit thread %d: %w", tid, err)
			}
		}
		verified, err := allThreadsLimited(&chosen)
		if err != nil {
			return 0, err
		}
		if verified {
			runtime.GOMAXPROCS(count)
			return count, nil
		}
	}
	return 0, fmt.Errorf("agent threads changed while applying CPU affinity")
}

func allThreadsLimited(chosen *unix.CPUSet) (bool, error) {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return false, fmt.Errorf("list agent threads: %w", err)
	}
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil {
			return false, fmt.Errorf("invalid thread ID %q: %w", task.Name(), err)
		}
		var actual unix.CPUSet
		if err := unix.SchedGetaffinity(tid, &actual); err != nil {
			if err == unix.ESRCH {
				continue
			}
			return false, fmt.Errorf("verify thread %d: %w", tid, err)
		}
		if actual != *chosen {
			return false, nil
		}
	}
	return true, nil
}
