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

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/pep/proxy"
)

const (
	// revokeChannel is the kv.Bus channel session revocations are published on.
	revokeChannel = "pep_revoked"
	// revokedPrefix namespaces the stored revocations in kv (one key per revoked sid).
	revokedPrefix = "pep:revoked:"
	// reconcileEvery is how often a replica re-reads the stored revocations, bounding the window in which a
	// dropped NOTIFY could let a revoked snapshot through.
	reconcileEvery = 30 * time.Second
)

// kvRevocations implements proxy.Revocations across replicas: each revocation is published on a kv.Bus (instant
// fan-out) and stored under its sid in a kv.Store, from which a fresh replica loads them and every replica
// reconciles periodically, catching what the best-effort bus dropped. Reads come from the local set alone.
type kvRevocations struct {
	local *proxy.MemoryRevocations
	bus   kv.Bus
	store kv.Store
	// ttl is how long a revocation learned from another replica holds: neither the bus message nor the stored
	// key carries its time, and a snapshot lives no longer than this.
	ttl time.Duration
	now func() time.Time
}

var _ proxy.Revocations = (*kvRevocations)(nil)

func newKVRevocations(bus kv.Bus, store kv.Store, ttl time.Duration) *kvRevocations {
	return &kvRevocations{local: proxy.NewMemoryRevocations(nil), bus: bus, store: store, ttl: ttl, now: time.Now}
}

// Revoke implements proxy.Revocations. The revocation holds here at once, whatever fails after; the error says
// what did not reach the other replicas, without the sid.
func (r *kvRevocations) Revoke(ctx context.Context, sid string, until time.Time) error {
	if sid == "" {
		return nil
	}
	_ = r.local.Revoke(ctx, sid, until)
	ttl := until.Sub(r.now())
	if ttl <= 0 {
		return nil
	}
	var errs []error
	if err := r.store.Set(ctx, revokedPrefix+sid, []byte{'1'}, ttl); err != nil {
		errs = append(errs, fmt.Errorf("revocation not stored, other replicas miss it until it is: %w", err))
	}
	if err := r.bus.Publish(ctx, revokeChannel, sid); err != nil {
		errs = append(errs, fmt.Errorf("revocation not published, other replicas catch it on reconcile: %w", err))
	}
	return errors.Join(errs...)
}

// Revoked implements proxy.Revocations.
func (r *kvRevocations) Revoked(ctx context.Context, sid string) (bool, error) {
	return r.local.Revoked(ctx, sid)
}

// Follow implements proxy.Revocations. It subscribes before it loads the stored revocations, so that one made
// in between arrives on the bus.
func (r *kvRevocations) Follow(ctx context.Context) error {
	ch, err := r.bus.Subscribe(ctx, revokeChannel)
	if err != nil {
		return fmt.Errorf("subscribe to revocations: %w", err)
	}
	if err := r.reconcile(ctx); err != nil {
		return err
	}
	go r.follow(ctx, ch)
	return nil
}

func (r *kvRevocations) follow(ctx context.Context, ch <-chan string) {
	t := time.NewTicker(reconcileEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case sid, ok := <-ch:
			if !ok {
				slog.Warn("revocation bus closed, relying on the periodic reconcile")
				ch = nil
				continue
			}
			r.learn(ctx, sid)
		case <-t.C:
			if err := r.reconcile(ctx); err != nil {
				slog.Warn("revocation reconcile failed", "error", err)
			}
		}
	}
}

func (r *kvRevocations) learn(ctx context.Context, sid string) {
	_ = r.local.Revoke(ctx, sid, r.now().Add(r.ttl))
}

// reconcile loads the stored revocations into the local set. It reads keys only, so it recovers the sid from
// the key, which a sealed store leaves in clear, and counts records from before the store was sealed.
func (r *kvRevocations) reconcile(ctx context.Context) error {
	keys, err := r.store.Keys(ctx, revokedPrefix)
	if err != nil {
		return fmt.Errorf("load the stored revocations: %w", err)
	}
	for _, k := range keys {
		r.learn(ctx, strings.TrimPrefix(k, revokedPrefix))
	}
	return nil
}
