package file

// paths.go defines the default set of filesystem paths that the FIM collector
// monitors on Linux.
//
// DefaultLinuxCriticalPaths() detects the running distribution at runtime and
// returns the combined set of shared + distro-specific paths, so the same
// binary works correctly on both Debian/Ubuntu and RedHat/CentOS/Fedora without
// producing noisy "no such file" log messages for inapplicable paths.
//
// Paths that do not exist at scan time are silently skipped — non-existence is
// not an error for optional distro-specific entries.

import (
	"bufio"
	"os"
	"strings"
)

// WatchPath describes a single path to monitor and whether to watch it
// recursively (subdirectory contents included).
type WatchPath struct {
	// Path is an absolute filesystem path to a file or directory.
	Path string

	// Recursive causes all files inside the directory (and subdirectories)
	// to be monitored. Ignored when Path is a regular file.
	Recursive bool
}

// Distro identifies the Linux distribution family.
type Distro int

const (
	DistroUnknown Distro = iota
	DistroDebian         // Debian, Ubuntu, Linux Mint, Pop!_OS, …
	DistroRHEL           // RHEL, CentOS, Fedora, Rocky, AlmaLinux, …
)

// DetectDistro reads /etc/os-release (or fallback indicator files) and
// returns the distribution family.  Falls back to DistroUnknown if the
// distribution cannot be determined.
func DetectDistro() Distro {
	// Primary: /etc/os-release (systemd standard, present on all modern distros)
	if d := distroFromOSRelease("/etc/os-release"); d != DistroUnknown {
		return d
	}
	// Fallback indicator files
	if fileExists("/etc/debian_version") {
		return DistroDebian
	}
	if fileExists("/etc/redhat-release") || fileExists("/etc/centos-release") || fileExists("/etc/fedora-release") {
		return DistroRHEL
	}
	return DistroUnknown
}

func distroFromOSRelease(path string) Distro {
	f, err := os.Open(path)
	if err != nil {
		return DistroUnknown
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Check both ID= and ID_LIKE= so derivatives are matched correctly.
		if !strings.HasPrefix(line, "ID=") && !strings.HasPrefix(line, "ID_LIKE=") {
			continue
		}
		val := strings.ToLower(strings.Trim(strings.SplitN(line, "=", 2)[1], `"' `))
		// Debian family
		if containsAny(val, "debian", "ubuntu", "mint", "pop", "elementary", "kali", "parrot", "deepin", "raspbian") {
			return DistroDebian
		}
		// RHEL family
		if containsAny(val, "rhel", "centos", "fedora", "rocky", "alma", "oracle", "amzn", "scientific") {
			return DistroRHEL
		}
	}
	return DistroUnknown
}

// DefaultLinuxCriticalPaths returns the FIM watch-list appropriate for the
// running distribution.  Detects the distro once at call time; the result is
// stable for the lifetime of the process.
func DefaultLinuxCriticalPaths() []WatchPath {
	shared := sharedCriticalPaths()
	switch DetectDistro() {
	case DistroDebian:
		return append(shared, debianCriticalPaths()...)
	case DistroRHEL:
		return append(shared, rhelCriticalPaths()...)
	default:
		// Unknown distro: return both sets; non-existent paths are skipped silently.
		return append(shared, append(debianCriticalPaths(), rhelCriticalPaths()...)...)
	}
}

// sharedCriticalPaths returns paths that exist on every supported Linux distro.
func sharedCriticalPaths() []WatchPath {
	return []WatchPath{
		// ── Authentication & authorisation ─────────────────────────────────
		// T1003, T1078 — credential access, valid accounts
		{Path: "/etc/passwd", Recursive: false},
		{Path: "/etc/shadow", Recursive: false},
		{Path: "/etc/group", Recursive: false},
		{Path: "/etc/gshadow", Recursive: false},
		{Path: "/etc/security/opasswd", Recursive: false},

		// ── Sudo / privilege escalation ────────────────────────────────────
		// T1548.003
		{Path: "/etc/sudoers", Recursive: false},
		{Path: "/etc/sudoers.d", Recursive: true},

		// ── PAM stack ──────────────────────────────────────────────────────
		// T1556 — modify authentication process
		{Path: "/etc/pam.d", Recursive: true},
		{Path: "/etc/security", Recursive: true},

		// ── SSH ─────────────────────────────────────────────────────────────
		// T1563, T1098
		{Path: "/etc/ssh", Recursive: true},
		{Path: "/root/.ssh", Recursive: true},

		// ── Scheduled tasks / cron (persistence) ───────────────────────────
		// T1053
		{Path: "/etc/crontab", Recursive: false},
		{Path: "/etc/cron.d", Recursive: true},
		{Path: "/etc/cron.daily", Recursive: true},
		{Path: "/etc/cron.hourly", Recursive: true},
		{Path: "/etc/cron.weekly", Recursive: true},
		{Path: "/etc/cron.monthly", Recursive: true},

		// ── Systemd services (persistence) ─────────────────────────────────
		// T1543.002
		{Path: "/etc/systemd/system", Recursive: true},
		{Path: "/usr/lib/systemd/system", Recursive: false},

		// ── Dynamic linker ──────────────────────────────────────────────────
		// T1574.006 — LD_PRELOAD hijacking
		{Path: "/etc/ld.so.conf", Recursive: false},
		{Path: "/etc/ld.so.conf.d", Recursive: true},

		// ── Shell init files (persistence) ─────────────────────────────────
		// T1546.004
		{Path: "/etc/profile", Recursive: false},
		{Path: "/etc/profile.d", Recursive: true},
		{Path: "/etc/environment", Recursive: false},
		{Path: "/root/.bashrc", Recursive: false},
		{Path: "/root/.profile", Recursive: false},

		// ── Critical system binaries ────────────────────────────────────────
		// T1574.007 — flat watch only (recursive too expensive)
		{Path: "/usr/bin", Recursive: false},
		{Path: "/usr/sbin", Recursive: false},
		{Path: "/usr/local/bin", Recursive: false},
		{Path: "/usr/local/sbin", Recursive: false},

		// ── Boot loader ─────────────────────────────────────────────────────
		// T1542.001
		{Path: "/boot/grub", Recursive: false},
		{Path: "/etc/default/grub", Recursive: false},

		// ── Kernel modules ──────────────────────────────────────────────────
		// T1547.006
		{Path: "/etc/modprobe.d", Recursive: true},
		{Path: "/etc/modules-load.d", Recursive: true},

		// ── Network configuration ───────────────────────────────────────────
		// T1565.003 — DNS hijacking, routing manipulation
		{Path: "/etc/hosts", Recursive: false},
		{Path: "/etc/hostname", Recursive: false},
		{Path: "/etc/resolv.conf", Recursive: false},
		{Path: "/etc/nsswitch.conf", Recursive: false},
		{Path: "/etc/hosts.allow", Recursive: false},
		{Path: "/etc/hosts.deny", Recursive: false},

		// ── Filesystem / mount configuration ───────────────────────────────
		{Path: "/etc/fstab", Recursive: false},
	}
}

// debianCriticalPaths returns paths specific to Debian, Ubuntu, and derivatives.
func debianCriticalPaths() []WatchPath {
	return []WatchPath{
		// ── PAM modules ─────────────────────────────────────────────────────
		{Path: "/lib/x86_64-linux-gnu/security", Recursive: false},
		{Path: "/lib/aarch64-linux-gnu/security", Recursive: false}, // ARM64

		// ── Legacy symlink binary directories (Debian/Ubuntu) ───────────────
		{Path: "/bin", Recursive: false},
		{Path: "/sbin", Recursive: false},

		// ── systemd lib location (Debian/Ubuntu) ────────────────────────────
		{Path: "/lib/systemd/system", Recursive: false},

		// ── Shell init files ────────────────────────────────────────────────
		{Path: "/etc/bash.bashrc", Recursive: false},
		{Path: "/root/.bash_login", Recursive: false},

		// ── Dynamic linker preload — high-severity indicator if created ──────
		// /etc/ld.so.preload doesn't exist by default; its creation is suspicious
		{Path: "/etc/ld.so.preload", Recursive: false},

		// ── Boot loader (GRUB on Debian/Ubuntu) ─────────────────────────────
		{Path: "/boot/grub/grub.cfg", Recursive: false},

		// ── APT package manager (supply chain) ──────────────────────────────
		// T1195
		{Path: "/etc/apt/sources.list", Recursive: false},
		{Path: "/etc/apt/sources.list.d", Recursive: true},
		{Path: "/etc/apt/apt.conf.d", Recursive: true},
		{Path: "/etc/apt/trusted.gpg.d", Recursive: true},
		{Path: "/usr/share/keyrings", Recursive: false},

		// ── Cron (Debian/Ubuntu location) ───────────────────────────────────
		{Path: "/var/spool/cron/crontabs", Recursive: true},

		// ── AppArmor profiles (Debian/Ubuntu MAC) ───────────────────────────
		{Path: "/etc/apparmor.d", Recursive: true},

		// ── dpkg integrity ───────────────────────────────────────────────────
		{Path: "/var/lib/dpkg/info", Recursive: false},
	}
}

// rhelCriticalPaths returns paths specific to RHEL, CentOS, Fedora, and derivatives.
func rhelCriticalPaths() []WatchPath {
	return []WatchPath{
		// ── PAM modules ─────────────────────────────────────────────────────
		{Path: "/lib64/security", Recursive: false},

		// ── Shell init files ────────────────────────────────────────────────
		{Path: "/etc/bashrc", Recursive: false},
		{Path: "/root/.bash_profile", Recursive: false},
		{Path: "/root/.bash_login", Recursive: false},

		// ── Dynamic linker preload ───────────────────────────────────────────
		{Path: "/etc/ld.so.preload", Recursive: false},

		// ── Boot loader (GRUB2 on RHEL) ─────────────────────────────────────
		{Path: "/boot/grub2", Recursive: false},
		{Path: "/boot/grub2/grub.cfg", Recursive: false},

		// ── Cron (RHEL location) ─────────────────────────────────────────────
		{Path: "/var/spool/cron", Recursive: true},

		// ── SELinux policy ───────────────────────────────────────────────────
		{Path: "/etc/selinux/config", Recursive: false},
		{Path: "/etc/selinux", Recursive: false},

		// ── YUM/DNF package manager (supply chain) ───────────────────────────
		// T1195
		{Path: "/etc/yum.repos.d", Recursive: true},
		{Path: "/etc/yum.conf", Recursive: false},
		{Path: "/etc/dnf/dnf.conf", Recursive: false},
		{Path: "/etc/dnf/plugins", Recursive: true},
		{Path: "/etc/pki/rpm-gpg", Recursive: false},

		// ── Kernel modules (RHEL path) ───────────────────────────────────────
		{Path: "/etc/modules", Recursive: false},
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
