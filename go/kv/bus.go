package kv

import (
	"context"
	"sync"
)

// Bus is a lightweight publish/subscribe channel for small control messages (e.g. session revocations),
// fanned out to every subscriber across processes. Like Store, the interface lives here (no driver) and the
// Postgres backend (LISTEN/NOTIFY) lives in kv/postgres. Delivery is best-effort: a slow or briefly
// disconnected subscriber may miss a message, so callers must not rely on the bus alone for correctness
// (pair it with a durable backstop).
type Bus interface {
	// Publish sends payload to every subscriber of channel, including in other processes.
	Publish(ctx context.Context, channel, payload string) error
	// Subscribe returns a stream of payloads published to channel until ctx is cancelled (then it is closed).
	Subscribe(ctx context.Context, channel string) (<-chan string, error)
	// Close releases resources.
	Close() error
}

// memBus is an in-process Bus for single-instance deployments and tests.
type memBus struct {
	mu     sync.Mutex
	subs   map[string][]chan string
	closed bool
}

// NewMemBus returns an in-process Bus.
func NewMemBus() Bus { return &memBus{subs: make(map[string][]chan string)} }

func (b *memBus) Publish(ctx context.Context, channel, payload string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	for _, ch := range b.subs[channel] {
		select {
		case ch <- payload:
		default: // drop for a slow subscriber — best-effort
		}
	}
	return nil
}

func (b *memBus) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	ch := make(chan string, 64)
	b.subs[channel] = append(b.subs[channel], ch)
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.subs[channel]
		for i, c := range subs {
			if c == ch {
				b.subs[channel] = append(subs[:i], subs[i+1:]...)
				close(ch)
				break
			}
		}
	}()
	return ch, nil
}

func (b *memBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}
