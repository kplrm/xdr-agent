package file

// paths.go defines the default set of filesystem paths that the FIM collector
// monitors on Linux.
//
// DefaultLinuxCriticalPaths returns shared and Debian/Ubuntu paths.
//
// Paths that do not exist at scan time are silently skipped — non-existence is
// not an error for optional distro-specific entries.

// WatchPath describes a single path to monitor and whether to watch it
// recursively (subdirectory contents included).
type WatchPath struct {
	// Path is an absolute filesystem path to a file or directory.
	Path string

	// Recursive causes all files inside the directory (and subdirectories)
	// to be monitored. Ignored when Path is a regular file.
	Recursive bool
}

// DefaultLinuxCriticalPaths returns the default Debian/Ubuntu FIM watch-list.
func DefaultLinuxCriticalPaths() []WatchPath {
	return append(sharedCriticalPaths(), debianCriticalPaths()...)
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
	}
}
