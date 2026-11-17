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

package zaddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/gematik/zero-lab/go/dpop"
)

const (
	// storageReplaysPrefix is the storage path the replays live under, one key per proof.
	storageReplaysPrefix = "zaddy/dpop_replays"
	// storageReplaysLockPrefix names the lock of one record; it holds no "/", which file storage would refuse.
	storageReplaysLockPrefix = "zaddy_dpop_replay_"
	// storageReplaysClockSkew outlasts the difference between the replicas' clocks: a replica behind the one
	// that recorded a proof still accepts it for that much longer, and the record must still be there.
	storageReplaysClockSkew = time.Minute
	// storageReplaysTimeout bounds one check: a storage that stalls, or a lock held by a replica that died,
	// refuses the proof instead of holding the request.
	storageReplaysTimeout = 5 * time.Second
	// storageReplaysSweepInterval and storageReplaysSweepLimit bound the work of removing expired records that
	// no proof touches again: at most that many records per interval and replica.
	storageReplaysSweepInterval = time.Minute
	storageReplaysSweepLimit    = 1000
)

// storageReplays are [dpop.Replays] in Caddy's storage (RFC 9449 Section 11.1), shared by every replica
// configured with the same storage, as a Caddy cluster shares its certificates and locks. A record is checked
// and written under the storage's lock of that record, so two replicas cannot both accept one proof. Keys are
// SHA-256 hashes of the proof identifier, never peer input; a record holds its expiry and nothing else.
type storageReplays struct {
	storage certmagic.Storage
	now     func() time.Time
	logger  *slog.Logger
}

var _ dpop.Replays = (*storageReplays)(nil)

// newStorageReplays returns replays in storage, expiring records by now (nil: the system clock) and logging the
// sweep's trouble to logger (nil: discarded).
func newStorageReplays(storage certmagic.Storage, now func() time.Time, logger *slog.Logger) *storageReplays {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &storageReplays{storage: storage, now: now, logger: logger}
}

// Seen records id until the given time and reports whether it was recorded and unexpired. Any storage error,
// including a lock not obtained in time and a record that does not parse, is returned, and the proof refused.
func (r *storageReplays) Seen(ctx context.Context, id string, until time.Time) (bool, error) {
	sum := sha256.Sum256([]byte(id))
	name := hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(ctx, storageReplaysTimeout)
	defer cancel()
	seen, err := r.locked(ctx, name, func(ctx context.Context, key string) (bool, error) {
		expiry, found, err := r.load(ctx, key)
		if err != nil {
			return false, err
		}
		if found && r.now().Before(expiry) {
			return true, nil
		}
		if err := r.storage.Store(ctx, key, formatReplayExpiry(until.Add(storageReplaysClockSkew))); err != nil {
			return false, fmt.Errorf("store: %w", err)
		}
		return false, nil
	})
	if err != nil {
		return false, fmt.Errorf("zaddy: DPoP replays in storage: %w", err)
	}
	return seen, nil
}

// locked runs fn on the record of name while holding its lock. An error to release the lock is an error of the
// call: the storage is not in the state the caller relies on.
func (r *storageReplays) locked(ctx context.Context, name string, fn func(context.Context, string) (bool, error)) (bool, error) {
	lock := storageReplaysLockPrefix + name
	if err := r.storage.Lock(ctx, lock); err != nil {
		return false, fmt.Errorf("lock: %w", err)
	}
	result, err := fn(ctx, path.Join(storageReplaysPrefix, name))
	// The lock is released even when ctx has expired, so a slow check does not leave it to go stale.
	unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storageReplaysTimeout)
	defer cancel()
	if uerr := r.storage.Unlock(unlockCtx, lock); uerr != nil {
		return false, errors.Join(err, fmt.Errorf("unlock: %w", uerr))
	}
	return result, err
}

// load returns the expiry of the record at key, and whether there is one.
func (r *storageReplays) load(ctx context.Context, key string) (time.Time, bool, error) {
	value, err := r.storage.Load(ctx, key)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("load: %w", err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil {
		return time.Time{}, false, errors.New("load: record does not hold an expiry")
	}
	return expiry, true, nil
}

func formatReplayExpiry(t time.Time) []byte {
	return []byte(t.UTC().Format(time.RFC3339Nano))
}

// sweep removes up to storageReplaysSweepLimit expired records, each under its lock, and returns how many it
// removed. Keys that are not a record of storageReplays are left alone.
func (r *storageReplays) sweep(ctx context.Context) (int, error) {
	keys, err := r.storage.List(ctx, storageReplaysPrefix, false)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("zaddy: DPoP replays in storage: list: %w", err)
	}
	removed, examined := 0, 0
	var errs []error
	for _, key := range keys {
		if examined == storageReplaysSweepLimit || ctx.Err() != nil {
			break
		}
		name := path.Base(key)
		if !isReplayName(name) {
			continue
		}
		examined++
		gone, err := r.locked(ctx, name, func(ctx context.Context, key string) (bool, error) {
			expiry, found, err := r.load(ctx, key)
			if err != nil || !found || r.now().Before(expiry) {
				return false, err
			}
			return true, r.storage.Delete(ctx, key)
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if gone {
			removed++
		}
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("zaddy: DPoP replays in storage: sweep: %d records failed, first: %w", len(errs), errs[0])
	}
	return removed, nil
}

// run sweeps every storageReplaysSweepInterval until ctx is done.
func (r *storageReplays) run(ctx context.Context) {
	ticker := time.NewTicker(storageReplaysSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(ctx, storageReplaysSweepInterval)
			if _, err := r.sweep(sweepCtx); err != nil {
				r.logger.Warn("Sweeping expired DPoP replays failed", "error", err)
			}
			cancel()
		}
	}
}

// isReplayName reports whether name is a hex SHA-256 as Seen derives it.
func isReplayName(name string) bool {
	if len(name) != 2*sha256.Size {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil
}
