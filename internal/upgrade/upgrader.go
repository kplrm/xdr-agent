// Package upgrade handles self-upgrading the xdr-agent binary from a GitHub
// release.  It detects the host OS family (Debian/Ubuntu vs RHEL/CentOS) and
// architecture, downloads the appropriate package, installs it with the
// system package manager, and restarts the systemd service.
package upgrade

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	githubReleaseBase = "https://github.com/kplrm/xdr-agent/releases/download"
	serviceUnit       = "xdr-agent"
)

// osFamilyDebian reports whether the host is Debian/Ubuntu.  It falls back to
// false (RPM) when /etc/os-release is unreadable or the ID_LIKE field is absent.
func osFamilyDebian() bool {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}
	content := strings.ToLower(string(data))
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "id=") || strings.HasPrefix(line, "id_like=") {
			if strings.Contains(line, "debian") || strings.Contains(line, "ubuntu") {
				return true
			}
		}
	}
	return false
}

// packageURL returns the GitHub download URL for the given version, OS family,
// and CPU architecture.
func packageURL(version string, debian bool) (string, error) {
	arch := runtime.GOARCH // "amd64" or "arm64"

	if debian {
		// e.g. xdr-agent_0.3.2_amd64.deb
		return fmt.Sprintf(
			"%s/v%s/xdr-agent_%s_%s.deb",
			githubReleaseBase, version, version, arch,
		), nil
	}

	// RPM uses different arch names
	rpmArch := arch
	switch arch {
	case "amd64":
		rpmArch = "x86_64"
	case "arm64":
		rpmArch = "aarch64"
	}

	if rpmArch == "aarch64" {
		// ARM64 RPM was built in a QEMU almalinux:9 container
		return fmt.Sprintf(
			"%s/v%s/xdr-agent-%s-1.el9.%s.rpm",
			githubReleaseBase, version, version, rpmArch,
		), nil
	}
	// x86_64 RPM
	return fmt.Sprintf(
		"%s/v%s/xdr-agent-%s-1.%s.rpm",
		githubReleaseBase, version, version, rpmArch,
	), nil
}

// download fetches a URL into a temporary file and returns its path.
func download(ctx context.Context, url, suffix string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "xdr-agent-upgrader")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "xdr-agent-upgrade-*"+suffix)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}

	return tmp.Name(), nil
}

// installDebian installs a .deb package with dpkg.
func installDebian(ctx context.Context, pkgPath string) error {
	cmd := exec.CommandContext(ctx, "dpkg", "-i", pkgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dpkg -i: %w", err)
	}
	return nil
}

// installRPM installs a .rpm package with rpm.
func installRPM(ctx context.Context, pkgPath string) error {
	cmd := exec.CommandContext(ctx, "rpm", "-Uvh", "--force", pkgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rpm -Uvh: %w", err)
	}
	return nil
}

// restartService asks systemd to restart the xdr-agent unit.  The agent
// process will be replaced, so this call usually does not return on success.
func restartService() error {
	cmd := exec.Command("systemctl", "restart", serviceUnit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Perform upgrades the agent to the specified version.  It:
//  1. Resolves the correct GitHub release URL for this host OS / arch.
//  2. Downloads the package to a temp file.
//  3. Installs it with dpkg or rpm.
//  4. Restarts the systemd service (this replaces the current process).
//
// If any step fails the function returns an error and the agent continues
// running on the current version.
func Perform(ctx context.Context, version string) error {
	debian := osFamilyDebian()
	url, err := packageURL(version, debian)
	if err != nil {
		return fmt.Errorf("resolve package URL: %w", err)
	}

	suffix := ".rpm"
	if debian {
		suffix = ".deb"
	}

	log.Printf("upgrade: downloading %s", url)
	pkgPath, err := download(ctx, url, suffix)
	if err != nil {
		return fmt.Errorf("download package: %w", err)
	}
	defer os.Remove(pkgPath)

	// Ensure the file has the correct extension for the package manager
	namedPath := filepath.Join(os.TempDir(), "xdr-agent-update"+suffix)
	if err := os.Rename(pkgPath, namedPath); err != nil {
		namedPath = pkgPath // fall back to temp name
	}
	defer os.Remove(namedPath)

	log.Printf("upgrade: installing %s", namedPath)
	if debian {
		if err := installDebian(ctx, namedPath); err != nil {
			return fmt.Errorf("install deb: %w", err)
		}
	} else {
		if err := installRPM(ctx, namedPath); err != nil {
			return fmt.Errorf("install rpm: %w", err)
		}
	}

	log.Printf("upgrade: restarting %s service", serviceUnit)
	if err := restartService(); err != nil {
		// Non-fatal: the new binary is installed; systemd should restart us on
		// the next watchdog cycle even if this call fails.
		log.Printf("upgrade: systemctl restart failed (non-fatal): %v", err)
	}

	return nil
}
