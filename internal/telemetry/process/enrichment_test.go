package process

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectContainerIDFullValue(t *testing.T) {
	id := strings.Repeat("0123456789abcdef", 4)
	for _, test := range []struct {
		name, cgroup, want string
	}{
		{"docker", "12:memory:/docker/" + id, id},
		{"docker child", "0::/docker/" + id + "/child", id},
		{"docker scope", "0::/system.slice/docker-" + id + ".scope", id},
		{"containerd scope", "0::/kubepods.slice/cri-containerd-" + id + ".scope", id},
		{"kubernetes cgroupfs", "0::/kubepods/burstable/pod-uid/" + id, id},
		{"podman scope", "0::/machine.slice/libpod-" + id + ".scope", id},
		{"podman child", "0::/libpod-" + id + "/child", id},
		{"host", "0::/system.slice/xdr-agent.service", ""},
		{"short component", "0::/docker/1234", ""},
		{"nonhex docker", "0::/docker/" + strings.Repeat("z", 64), ""},
		{"nonhex scope", "0::/system.slice/docker-" + strings.Repeat("z", 64) + ".scope", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(test.cgroup+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if got := detectContainerID(dir); got != test.want {
				t.Fatalf("container ID = %q, want %q", got, test.want)
			}
		})
	}
}
