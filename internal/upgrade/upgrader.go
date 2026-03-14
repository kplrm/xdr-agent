// Package upgrade handles self-upgrading the xdr-agent binary from a GitHub
// release.  It detects the host OS family (Debian/Ubuntu vs RHEL/CentOS) and
// architecture, downloads the appropriate package, and launches the install
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
func launchInstall(pkgPath string, debian bool) error {
	// Clear any leftover failed transient unit from a previous attempt.
	_ = exec.Command("systemctl", "reset-failed", "xdr-agent-upgrade.service").Run()

	var installCmd string
	if debian {
		installCmd = fmt.Sprintf("dpkg -i '%s' && rm -f '%s'", pkgPath, pkgPath)
	} else {
		installCmd = fmt.Sprintf("rpm -Uvh --force '%s' && rm -f '%s'", pkgPath, pkgPath)
	}

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
	debian := osFamilyDebian()
	url, err := packageURL(version, debian)
	if err != nil {
		return fmt.Errorf("resolve package URL: %w", err)
	}

	suffix := ".rpm"
	if debian {
		suffix = ".deb"
	}

	// Ensure cache directory exists.
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	// Download with an independent context so a cancelled parent ctx does
	// not abort the HTTP transfer.
	dlCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Printf("upgrade: downloading %s", url)
	pkgPath, err := download(dlCtx, url, cacheDir, suffix)
	if err != nil {
		return fmt.Errorf("download package: %w", err)
	}

	// Give the file a predictable name so the transient unit command is
	// easy to inspect in journal logs.
	namedPath := filepath.Join(cacheDir, "xdr-agent-update"+suffix)
	if err := os.Rename(pkgPath, namedPath); err != nil {
		namedPath = pkgPath // fall back to random temp name
	}

	log.Printf("upgrade: launching install %s via transient systemd unit", namedPath)
	if err := launchInstall(namedPath, debian); err != nil {
		os.Remove(namedPath)
		return fmt.Errorf("launch install: %w", err)
	}

	log.Printf("upgrade: transient unit xdr-agent-upgrade started; agent will be restarted by package scripts")
	return nil
}
