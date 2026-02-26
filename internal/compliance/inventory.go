package compliance

// Inventory maintains a software inventory of all installed packages.
// This is essential for vulnerability detection and compliance reporting.

// TODO: Implement software inventory
// - Enumerate packages from:
//   * dpkg (Debian/Ubuntu): dpkg-query -W -f '${Package}\t${Version}\n'
//   * rpm (RHEL/CentOS): rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'
//   * apk (Alpine): apk list -I
//   * snap: snap list
//   * pip: pip list --format json
//   * npm: npm list -g --json (if applicable)
// - Report: package name, version, source, install date
// - Detect: packages installed outside package manager (manual installs)
// - Ship inventory to control plane for fleet-wide visibility
