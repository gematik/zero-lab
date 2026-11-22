// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Package revoked is a set of revoked identifiers, such as session IDs, that several processes share over a
// kv.Store and a kv.Bus. A revocation is published on the bus for instant fan-out and stored under its ID, from
// which a process that starts loads the earlier ones and every process reconciles periodically, catching what the
// best-effort bus dropped. Lookups read the local set alone, so no request waits on the store.
//
// Only keys are read, never values: a sealed store (kv.NewSealed) leaves keys in clear, so a process can follow
// the revocations without the store's key ring, and records written before the store was sealed still count.
package revoked

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// DefaultReconcileEvery is how often the stored revocations are read again when Config leaves it zero. It bounds
// the window in which a dropped bus message lets a revoked identifier through.
const DefaultReconcileEvery = 30 * time.Second

// ErrStale is returned by Revoked for an identifier the set does not hold when the stored revocations were not
// read within Config.MaxStale, or not yet: the set cannot tell whether another process revoked it.
var ErrStale = errors.New("revoked: the stored revocations were not read recently enough to tell")

// Config is what a Set shares its revocations over.
type Config struct {
	// Store holds one key per revocation, Prefix followed by the identifier, which expires when the
	// revocation does.
	Store kv.Store
	// Bus carries each new revocation's identifier on Channel.
	Bus kv.Bus
	// Prefix and Channel are what every process sharing the revocations agrees on.
	Prefix  string
	Channel string
	// TTL is how long a revocation learned from another process holds here: neither the bus message nor the
	// stored key carries its time, so it is the longest any revoked identifier stays valid otherwise.
	TTL time.Duration
	// ReconcileEvery is how often the stored revocations are read again; zero means DefaultReconcileEvery.
	ReconcileEvery time.Duration
	// MaxStale is how old the last successful read of the stored revocations may be before Revoked answers
	// ErrStale for an identifier it does not hold; zero means three times ReconcileEvery, so one failed
	// reconcile is tolerated and a store that stays unreachable is not.
	MaxStale time.Duration
	// Logger receives what goes wrong while following; nil logs nothing.
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Set is a set of revoked identifiers shared with other processes. It is safe for concurrent use.
type Set struct {
	store          kv.Store
	bus            kv.Bus
	prefix         string
	channel        string
	ttl            time.Duration
	reconcileEvery time.Duration
	maxStale       time.Duration
	log            *slog.Logger
	now            func() time.Time

	mu    sync.Mutex
	until map[string]time.Time
	// synced is when the stored revocations were last read in full; zero before the first read.
	synced time.Time
}

// New returns an empty Set over cfg. It fails without a store, a bus, a prefix, a channel or a positive TTL.
func New(cfg Config) (*Set, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("revoked: no store")
	case cfg.Bus == nil:
		return nil, errors.New("revoked: no bus")
	case cfg.Prefix == "":
		return nil, errors.New("revoked: no key prefix")
	case cfg.Channel == "":
		return nil, errors.New("revoked: no bus channel")
	case cfg.TTL <= 0:
		return nil, errors.New("revoked: TTL must be positive")
	}
	s := &Set{
		store:          cfg.Store,
		bus:            cfg.Bus,
		prefix:         cfg.Prefix,
		channel:        cfg.Channel,
		ttl:            cfg.TTL,
		reconcileEvery: cfg.ReconcileEvery,
		maxStale:       cfg.MaxStale,
		log:            cfg.Logger,
		now:            cfg.Now,
		until:          make(map[string]time.Time),
	}
	if s.reconcileEvery <= 0 {
		s.reconcileEvery = DefaultReconcileEvery
	}
	if s.maxStale <= 0 {
		s.maxStale = 3 * s.reconcileEvery
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Revoke records id as revoked until the given time, here at once and for the other processes in the store and
// on the bus. The revocation holds here whatever fails after; the error says what did not reach the others,
// without the identifier, which may be a secret's hash.
func (s *Set) Revoke(ctx context.Context, id string, until time.Time) error {
	if id == "" {
		return nil
	}
	s.hold(id, until)
	ttl := until.Sub(s.now())
	if ttl <= 0 {
		return nil
	}
	var errs []error
	if err := s.store.Set(ctx, s.prefix+id, []byte{'1'}, ttl); err != nil {
		errs = append(errs, fmt.Errorf("revocation not stored, other processes miss it until it is: %w", err))
	}
	if err := s.bus.Publish(ctx, s.channel, id); err != nil {
		errs = append(errs, fmt.Errorf("revocation not published, other processes catch it on reconcile: %w", err))
	}
	return errors.Join(errs...)
}

// Revoked reports whether id is revoked. A revocation this set holds is certain; that id is not revoked is
// only as good as the last read of the stored revocations, so without a recent one it returns ErrStale, and
// the caller denies (server rule 16).
func (s *Set) Revoked(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if until, ok := s.until[id]; ok {
		if !now.After(until) {
			return true, nil
		}
		delete(s.until, id)
	}
	if s.synced.IsZero() || now.Sub(s.synced) > s.maxStale {
		return false, ErrStale
	}
	return false, nil
}

// Follow applies the revocations of the other processes: those stored before the call by the time it returns,
// and those made later until ctx ends. It subscribes before it reads the store, so a revocation made in
// between arrives on the bus. An error means it cannot follow, and the host does not serve.
func (s *Set) Follow(ctx context.Context) error {
	ch, err := s.bus.Subscribe(ctx, s.channel)
	if err != nil {
		return fmt.Errorf("subscribe to revocations: %w", err)
	}
	if err := s.Reconcile(ctx); err != nil {
		return err
	}
	go s.follow(ctx, ch)
	return nil
}

func (s *Set) follow(ctx context.Context, ch <-chan string) {
	t := time.NewTicker(s.reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id, ok := <-ch:
			if !ok {
				if ctx.Err() == nil {
					s.log.Warn("revocation bus closed, relying on the periodic reconcile")
				}
				ch = nil
				continue
			}
			s.learn(id)
		case <-t.C:
			if err := s.Reconcile(ctx); err != nil {
				s.log.Warn("revocation reconcile failed", "error", err)
			}
		}
	}
}

// Reconcile reads the stored revocations into the local set and drops the expired ones. It recovers each
// identifier from its key.
func (s *Set) Reconcile(ctx context.Context) error {
	keys, err := s.store.Keys(ctx, s.prefix)
	if err != nil {
		return fmt.Errorf("load the stored revocations: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, until := range s.until {
		if now.After(until) {
			delete(s.until, id)
		}
	}
	for _, k := range keys {
		if id := strings.TrimPrefix(k, s.prefix); id != "" {
			s.holdLocked(id, now.Add(s.ttl))
		}
	}
	s.synced = now
	return nil
}

func (s *Set) learn(id string) {
	if id == "" {
		return
	}
	s.hold(id, s.now().Add(s.ttl))
}

func (s *Set) hold(id string, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.holdLocked(id, until)
}

func (s *Set) holdLocked(id string, until time.Time) {
	if until.After(s.until[id]) {
		s.until[id] = until
	}
}
