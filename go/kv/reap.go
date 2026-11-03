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

package kv

import (
	"context"
	"log/slog"
	"time"
)

// Reap removes expired entries from store every interval until ctx ends, and logs failures: a store that
// cannot be cleaned now may well be cleaned next time. Without it, expired rows stay in a persistent store,
// where reads ignore but never delete them.
func Reap(ctx context.Context, store Store, interval time.Duration) {
	if interval <= 0 {
		slog.Error("kv: not reaping expired entries: the interval must be positive", "interval", interval)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reapOnce(ctx, store, interval)
		}
	}
}

func reapOnce(ctx context.Context, store Store, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	removed, err := store.Cleanup(ctx)
	if err != nil {
		slog.Error("kv: removing expired entries failed", "error", err)
		return
	}
	slog.Debug("kv: removed expired entries", "removed", removed)
}
