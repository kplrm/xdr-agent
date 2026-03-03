// Package script provides script content capture for interpreter process start
// events.
//
// When a newly observed process has an interpreter (bash, sh, python, perl,
// ruby, node, …) as its executable, the first N bytes of the script file
// (the first non-flag positional argument) are read and included in the
// process.start event payload as process.script.content.
//
// This enables detection of obfuscated shell scripts, encoded payloads, and
// attacker tools delivered as interpreted scripts — without requiring an eBPF
// tracepoint (MITRE T1059).
//
// ECS fields populated:
//   - process.script.content  — first N bytes of the script (configurable, default 4 KiB)
//   - process.script.length   — actual file size in bytes (before truncation)
//   - process.script.path     — resolved path of the script file
package script

import (
	"os"
	"path/filepath"
	"strings"
)

// interpreters is the set of binary names that are considered interpreters.
// Matched against the basename of process.executable.
var interpreters = map[string]bool{
	"sh":          true,
	"bash":        true,
	"dash":        true,
	"zsh":         true,
	"ksh":         true,
	"fish":        true,
	"python":      true,
	"python2":     true,
	"python3":     true,
	"perl":        true,
	"perl5":       true,
	"ruby":        true,
	"node":        true,
	"nodejs":      true,
	"php":         true,
	"php7":        true,
	"php8":        true,
	"lua":         true,
	"tclsh":       true,
	"expect":      true,
	"awk":         true,
	"gawk":        true,
	"nawk":        true,
	"mawk":        true,
	"osascript":   true,
	"Rscript":     true,
	"groovy":      true,
	"jrunscript":  true,
}

// IsInterpreter returns true if the executable basename is a known interpreter.
func IsInterpreter(executable string) bool {
	base := filepath.Base(executable)
	// Strip version suffixes like python3.11, ruby3.0, php8.2
	for name := range interpreters {
		if base == name || strings.HasPrefix(base, name+".") {
			return true
		}
	}
	return false
}

// CaptureContent reads the first maxBytes bytes of the script file
// identified from args (the first non-flag argument after the interpreter).
// Returns a payload map suitable for inclusion as process.script in an ECS event,
// or nil if the script path cannot be determined or read.
//
// Parameter maxBytes must be > 0; values > 65536 are silently capped at 65536.
func CaptureContent(executable string, args []string, maxBytes int) map[string]interface{} {
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	if maxBytes > 65536 {
		maxBytes = 65536
	}

	scriptPath := resolveScriptPath(args)
	if scriptPath == "" {
		return nil
	}

	// Require an absolute or resolvable path; skip stdin/socket args.
	if !filepath.IsAbs(scriptPath) {
		// Best-effort: treat as relative to root (won't work, but avoids
		// path traversal via user-supplied args).
		scriptPath = filepath.Clean("/" + scriptPath)
	}

	info, err := os.Stat(scriptPath)
	if err != nil || info.IsDir() {
		return nil
	}

	fh, err := os.Open(scriptPath)
	if err != nil {
		return nil
	}
	defer fh.Close()

	buf := make([]byte, maxBytes)
	n, _ := fh.Read(buf)
	if n == 0 {
		return nil
	}

	return map[string]interface{}{
		"path":    scriptPath,
		"content": string(buf[:n]),
		"length":  info.Size(),
	}
}

// resolveScriptPath extracts the script file path from args.
// It skips the interpreter itself (args[0]) and any flags ("-e", "--", etc.)
// and returns the first positional argument that looks like a file path.
func resolveScriptPath(args []string) string {
	// args[0] is the interpreter name; start scanning from args[1].
	if len(args) < 2 {
		return ""
	}
	for _, arg := range args[1:] {
		if arg == "" {
			continue
		}
		// Skip interpreter flags like -e, -c, -u, --norc, etc.
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Skip stdin placeholder
		if arg == "-" || arg == "/dev/stdin" {
			return ""
		}
		return arg
	}
	return ""
}
