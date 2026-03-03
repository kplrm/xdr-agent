// script.go — bridge between the process collector and the script capture package.
//
// captureScriptPayload is called by emitEvent for process.start events
// where the executable is a known interpreter.  It returns the map[string]interface{}
// expected by the "process.script" ECS field, or nil if no script was identified.
package process

import "xdr-agent/internal/telemetry/script"

// captureScriptPayload returns script content metadata for an interpreter
// process, or nil when the process is not an interpreter or the script cannot
// be read.
//
// Parameters:
//   - executable: process.executable (absolute path to the interpreter binary)
//   - args:       process.args (command-line arguments including interpreter)
//   - maxBytes:   maximum bytes to capture from the script file (default 4096)
func captureScriptPayload(executable string, args []string, maxBytes int) map[string]interface{} {
	if !script.IsInterpreter(executable) {
		return nil
	}
	return script.CaptureContent(executable, args, maxBytes)
}
