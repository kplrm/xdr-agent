package eventschema

// FileEvent contains file-specific event fields.
type FileEvent struct {
	Path        string `json:"file.path"`
	Name        string `json:"file.name"`
	Extension   string `json:"file.extension"`
	Size        int64  `json:"file.size"`
	Hash        string `json:"file.hash.sha256"`
	Owner       string `json:"file.owner"`
	Group       string `json:"file.group"`
	Permissions string `json:"file.mode"`
	MimeType    string `json:"file.mime_type,omitempty"`
}
