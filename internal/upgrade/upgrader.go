// Package upgrade handles self-upgrading the xdr-agent binary from a GitHub
// release on Debian-based hosts. It detects the architecture, downloads the
// appropriate Debian package, and launches the install
// in an isolated transient systemd unit so the package manager survives the
// service restart triggered by the package scripts.
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
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	githubReleaseBase = "https://github.com/kplrm/xdr-agent/releases/download"
	serviceUnit       = "xdr-agent"

	// cacheDir lives outside /tmp so it is reachable even when the service
	// runs with PrivateTmp=true and the install happens in a separate unit.
	cacheDir = "/var/cache/xdr-agent"
)

// osFamilyDebian reports whether the host belongs to the supported Debian family.
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

// packageURL returns the Debian download URL for a supported version and architecture.
func packageURL(version, arch string) (string, error) {
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`).MatchString(version) {
		return "", fmt.Errorf("invalid release version")
	}
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}
	return fmt.Sprintf(
		"%s/v%s/xdr-agent_%s_%s.deb",
		githubReleaseBase, version, version, arch,
	), nil
}

// download fetches a URL into a temporary file inside dir and returns its
// path.  Using a caller-specified directory (rather than the default temp dir)
// avoids issues with PrivateTmp=true when the install runs in a separate unit.
func download(ctx context.Context, url, dir, suffix string) (string, error) {
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

	tmp, err := os.CreateTemp(dir, "xdr-agent-upgrade-*"+suffix)
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

// launchInstall starts the package-manager install in an isolated transient
// systemd unit (via systemd-run).  Because the transient unit has its own
// cgroup, it is NOT killed when the xdr-agent.service cgroup is terminated
// by the package's prerm/preinst scripts calling "systemctl stop xdr-agent".
//
// The command is launched with --no-block so this function returns
// immediately.  The package's postinst script is responsible for re-enabling
// and starting the service once the install completes.
func launchInstall(pkgPath string) error {
	// Clear any leftover failed transient unit from a previous attempt.
	_ = exec.Command("systemctl", "reset-failed", "xdr-agent-upgrade.service").Run()

	installCmd := fmt.Sprintf("dpkg -i '%s' && rm -f '%s'", pkgPath, pkgPath)

	cmd := exec.Command(
		"systemd-run",
		"--unit=xdr-agent-upgrade",
		"--description=XDR Agent Self-Upgrade",
		"--no-block",
		"/bin/bash", "-c", installCmd,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemd-run: %w", err)
	}
	return nil
}

// Perform upgrades the agent to the specified version.  It:
//  1. Resolves the correct GitHub release URL for this host OS / arch.
//  2. Downloads the package to /var/cache/xdr-agent/ (outside PrivateTmp).
//  3. Launches the install in an isolated transient systemd unit so the
//     package manager survives the service stop triggered by prerm.
//  4. Returns immediately — the package's postinst re-enables and starts
//     the service once the install finishes.
//
// If any step fails the function returns an error and the agent continues
// running on the current version.
func Perform(ctx context.Context, version string) error {
	if !osFamilyDebian() {
		return fmt.Errorf("self-upgrade requires a Debian-based system")
	}
	url, err := packageURL(version, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("resolve package URL: %w", err)
	}

	// Ensure cache directory exists.
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	// Cancel download with the service; the actual install has its own unit.
	dlCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	log.Printf("upgrade: downloading %s", url)
	pkgPath, err := download(dlCtx, url, cacheDir, ".deb")
	if err != nil {
		return fmt.Errorf("download package: %w", err)
	}

	// Give the file a predictable name so the transient unit command is
	// easy to inspect in journal logs.
	namedPath := filepath.Join(cacheDir, "xdr-agent-update.deb")
	if err := os.Rename(pkgPath, namedPath); err != nil {
		namedPath = pkgPath // fall back to random temp name
	}

	log.Printf("upgrade: launching install %s via transient systemd unit", namedPath)
	if err := launchInstall(namedPath); err != nil {
		os.Remove(namedPath)
		return fmt.Errorf("launch install: %w", err)
	}

	log.Printf("upgrade: transient unit xdr-agent-upgrade started; agent will be restarted by package scripts")
	return nil
}
