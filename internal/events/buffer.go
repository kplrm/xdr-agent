package events

import "sync"

// Buffer provides in-memory event buffering for batch shipping to the control plane.
// Events are accumulated and flushed periodically by the event shipper.
// When the buffer is full, the oldest event is dropped (ring buffer behavior).
type Buffer struct {
	mu     sync.Mutex
	events []Event
	max    int
}

// NewBuffer creates a new event buffer with the given max capacity.
func NewBuffer(maxSize int) *Buffer {
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &Buffer{
		events: make([]Event, 0, maxSize),
		max:    maxSize,
	}
}

// Add appends an event to the buffer. If the buffer is full, the oldest event is dropped.
func (b *Buffer) Add(event Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) >= b.max {
		b.events = b.events[1:]
	}
	b.events = append(b.events, event)
}

// Flush returns all buffered events and clears the buffer.
// Returns nil if the buffer is empty.
func (b *Buffer) Flush() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) == 0 {
		return nil
	}

	flushed := b.events
	b.events = make([]Event, 0, b.max)
	return flushed
}

// Len returns the current number of buffered events.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}
