package authentication

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"xdr-agent/internal/capability"
	"xdr-agent/internal/events"
)

const maxLine = 256 * 1024

// Collector tails only new records; it retains the old descriptor until rotation drains.
type Collector struct {
	pipeline                *events.Pipeline
	agentID, hostname, path string
	mu                      sync.Mutex
	health                  capability.HealthStatus
	cancel                  context.CancelFunc
	workers                 sync.WaitGroup
	file                    *os.File
	offset                  int64
	pending                 []byte
	discard                 bool
	journalCursor           string
	journalCommand          func(context.Context, ...string) *exec.Cmd
}

func NewCollector(pipeline *events.Pipeline, agentID, hostname string) *Collector {
	return &Collector{pipeline: pipeline, agentID: agentID, hostname: hostname, path: "/var/log/auth.log", health: capability.HealthStopped}
}

func (c *Collector) Name() string { return "telemetry.authentication" }
func (c *Collector) Init(_ capability.Dependencies) error {
	c.setHealth(capability.HealthStarting)
	return nil
}
func (c *Collector) Health() capability.HealthStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}
func (c *Collector) setHealth(health capability.HealthStatus) {
	c.mu.Lock()
	c.health = health
	c.mu.Unlock()
}

func (c *Collector) Start(ctx context.Context) error {
	// Missing/temporarily unreadable files are retried; they must not disable collection permanently.
	c.setHealth(capability.HealthDegraded)
	if err := c.open(true); err == nil {
		c.setHealth(capability.HealthRunning)
	} else {
		log.Printf("authentication: cannot tail %s; trying system journal: %v", c.path, err)
	}
	child, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		defer func() {
			if c.file != nil {
				_ = c.file.Close()
			}
			c.setHealth(capability.HealthStopped)
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		lastJournalError := ""
		for {
			if c.file == nil {
				// Once journal collection has a cursor, keep that source until restart.
				// Switching to a file mid-stream could replay the same authentication records.
				if c.journalCursor == "" {
					_ = c.open(false)
				}
				if c.file == nil {
					err := c.followJournal(child)
					if child.Err() != nil {
						return
					}
					c.setHealth(capability.HealthDegraded)
					if message := err.Error(); message != lastJournalError {
						log.Printf("authentication: journal unavailable; retrying: %s", message)
						lastJournalError = message
					}
				}
			}
			select {
			case <-child.Done():
				return
			case <-ticker.C:
				if c.file == nil {
					continue
				}
				if c.poll() != nil {
					c.setHealth(capability.HealthDegraded)
				} else {
					c.setHealth(capability.HealthRunning)
				}
			}
		}
	}()
	return nil
}

func (c *Collector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	c.workers.Wait()
	c.setHealth(capability.HealthStopped)
	return nil
}

func (c *Collector) open(initial bool) error {
	file, err := os.Open(c.path)
	if err != nil {
		return err
	}
	c.offset, c.pending, c.discard = 0, nil, false
	if initial {
		c.offset, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			_ = file.Close()
			return err
		}
		if c.offset > 0 {
			var last [1]byte
			if _, err := file.ReadAt(last[:], c.offset-1); err == nil {
				c.discard = last[0] != '\n'
			}
		}
	}
	c.file = file
	return nil
}

func (c *Collector) poll() error {
	if c.file == nil {
		if err := c.open(false); err != nil {
			return err
		}
	}
	info, err := c.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() < c.offset {
		if _, err := c.file.Seek(0, io.SeekStart); err != nil {
			return err
		}
		c.offset, c.pending, c.discard = 0, nil, false
	}
	var buffer [32 * 1024]byte
	// Bound each poll so a busy log cannot delay shutdown or grow memory without limit.
	for read := 0; read < 1024*1024; {
		n, err := c.file.Read(buffer[:])
		c.offset += int64(n)
		read += n
		c.consume(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
	}
	current, err := os.Stat(c.path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, current) {
		// Drain the renamed file before switching to the replacement's beginning.
		latest, err := c.file.Stat()
		if err != nil {
			return err
		}
		if c.offset < latest.Size() {
			return nil
		}
		_ = c.file.Close()
		c.file = nil
		return c.open(false)
	}
	return nil
}

func (c *Collector) consume(data []byte) {
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		part := data
		if end >= 0 {
			part = data[:end]
		}
		if !c.discard {
			if len(c.pending)+len(part) > maxLine {
				c.pending, c.discard = nil, true
			} else {
				c.pending = append(c.pending, part...)
			}
		}
		if end < 0 {
			return
		}
		if !c.discard && len(c.pending) > 0 {
			line := string(bytes.TrimSuffix(c.pending, []byte{'\r'}))
			if event, keep := parse(line, time.Now(), c.agentID, c.hostname, c.path); keep {
				c.pipeline.Emit(event)
			}
		}
		c.pending, c.discard = nil, false
		data = data[end+1:]
	}
}
