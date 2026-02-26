package eventschema

// ProcessEvent contains process-specific event fields.
type ProcessEvent struct {
	PID         int      `json:"process.pid"`
	PPID        int      `json:"process.parent.pid"`
	Name        string   `json:"process.name"`
	Executable  string   `json:"process.executable"`
	CommandLine string   `json:"process.command_line"`
	Args        []string `json:"process.args"`
	WorkingDir  string   `json:"process.working_directory"`
	User        string   `json:"user.name"`
	UserID      int      `json:"user.id"`
	GroupID     int      `json:"group.id"`
	Hash        string   `json:"process.hash.sha256"`
	ParentName  string   `json:"process.parent.name"`
	ParentExe   string   `json:"process.parent.executable"`
}
