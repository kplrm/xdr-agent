package file

import "testing"

// Startup must not hash whole binary or package-management directories.
func TestDefaultFIMPathsAvoidLargeHostTrees(t *testing.T) {
	unsafe := map[string]bool{"/usr/bin": true, "/usr/sbin": true, "/usr/local/bin": true, "/usr/local/sbin": true, "/bin": true, "/sbin": true, "/var/lib/dpkg/info": true}
	for _, path := range DefaultLinuxCriticalPaths() {
		if unsafe[path.Path] {
			t.Fatalf("high-volume FIM baseline path: %s", path.Path)
		}
	}
}
