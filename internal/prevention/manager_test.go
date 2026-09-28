package prevention

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"xdr-agent/internal/telemetry/process"
)

func TestKillOnlyMatchedProcessInstance(t *testing.T) {
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	pid := child.Process.Pid
	info, err := process.ReadProcessInfo("/proc", pid)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Stat("/proc/" + fmt.Sprint(pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	stat := executable.Sys().(*syscall.Stat_t)
	payload := map[string]interface{}{"process.pid": pid, "process.start_time": info.StartTime + 1, "file.device": stat.Dev, "file.inode": stat.Ino, "file.size": executable.Size(), "file.mtime_ns": executable.ModTime().UnixNano()}
	if err := killMatchedProcess(payload); err == nil {
		t.Fatal("accepted reused process identity")
	}
	payload["process.start_time"] = info.StartTime
	payload["file.inode"] = stat.Ino + 1
	if err := killMatchedProcess(payload); err == nil {
		t.Fatal("accepted replaced executable")
	}
	payload["file.inode"] = stat.Ino
	if err := killMatchedProcess(payload); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("matched subprocess was not terminated")
	}
}
