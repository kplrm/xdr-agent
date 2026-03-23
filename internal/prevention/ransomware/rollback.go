package ransomware

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type JournalEntry struct {
	ProcessID    int       `json:"process_id"`
	ProcessName  string    `json:"process_name"`
	Path         string    `json:"path"`
	BackupPath   string    `json:"backup_path"`
	OriginalHash string    `json:"original_hash"`
	CreatedAt    time.Time `json:"created_at"`
	Confirmed    bool      `json:"confirmed"`
}

type Rollback struct {
	rootDir string
}

func NewRollback(rootDir string) *Rollback {
	return &Rollback{rootDir: rootDir}
}

func (r *Rollback) TrackModifiedFile(processID int, processName, path, originalHash string) (JournalEntry, error) {
	if err := os.MkdirAll(r.rootDir, 0o750); err != nil {
		return JournalEntry{}, fmt.Errorf("create rollback dir: %w", err)
	}

	backupPath := filepath.Join(r.rootDir, time.Now().UTC().Format("20060102150405")+"_"+filepath.Base(path))
	if err := copyFile(path, backupPath); err != nil {
		return JournalEntry{}, err
	}

	entry := JournalEntry{
		ProcessID:    processID,
		ProcessName:  processName,
		Path:         path,
		BackupPath:   backupPath,
		OriginalHash: originalHash,
		CreatedAt:    time.Now().UTC(),
	}
	if err := r.appendEntry(entry); err != nil {
		return JournalEntry{}, err
	}
	return entry, nil
}

func (r *Rollback) ConfirmAndRestore() ([]JournalEntry, error) {
	entries, err := r.readEntries()
	if err != nil {
		return nil, err
	}

	restored := make([]JournalEntry, 0, len(entries))
	for i := range entries {
		if err := copyFile(entries[i].BackupPath, entries[i].Path); err != nil {
			continue
		}
		entries[i].Confirmed = true
		restored = append(restored, entries[i])
	}
	if err := r.writeEntries(entries); err != nil {
		return restored, err
	}
	return restored, nil
}

func (r *Rollback) appendEntry(entry JournalEntry) error {
	entries, err := r.readEntries()
	if err != nil {
		return err
	}
	entries = append(entries, entry)
	return r.writeEntries(entries)
}

func (r *Rollback) readEntries() ([]JournalEntry, error) {
	path := filepath.Join(r.rootDir, "rollback_journal.json")
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []JournalEntry{}, nil
		}
		return nil, err
	}
	var entries []JournalEntry
	if err := json.Unmarshal(content, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r *Rollback) writeEntries(entries []JournalEntry) error {
	path := filepath.Join(r.rootDir, "rollback_journal.json")
	content, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	return os.WriteFile(path, content, 0o640)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
