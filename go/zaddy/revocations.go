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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/kv/revoked"
	"github.com/gematik/zero-lab/go/pep"
)

const (
	// revocationTTL is how long a revocation that came over the bus holds before a read of the store renews
	// it: zero-pep-proxy's default snapshot lifetime. The store holds each revocation as long as zero-pep-proxy
	// asked, and every reconcile reads it again until then, so this matters only between two reads.
	revocationTTL = 8 * time.Hour
	// revocationsOpenTimeout bounds connecting to the revocations' database at start.
	revocationsOpenTimeout = 30 * time.Second
)

// openRevocationsFunc connects to the store and bus zero-pep-proxy shares its session revocations over.
type openRevocationsFunc func(ctx context.Context, dsn string) (kv.Store, kv.Bus, error)

// openPostgresRevocations opens the Postgres kv store and its LISTEN/NOTIFY bus at dsn, as zero-pep-proxy does.
// The store is not sealed: only its keys are read, which a sealed store leaves in clear, so zaddy needs no
// share of zero-pep-proxy's store keys.
func openPostgresRevocations(ctx context.Context, dsn string) (kv.Store, kv.Bus, error) {
	// revocations_database_url is one URL with the user and the password in it; the store takes them apart.
	address, user, password, err := postgres.SplitURL(dsn)
	if err != nil {
		return nil, nil, err
	}
	store, err := postgres.Open(ctx, address, user, password, postgres.WithMigrate())
	if err != nil {
		return nil, nil, err
	}
	bus, err := postgres.OpenBus(ctx, address, user, password)
	if err != nil {
		return nil, nil, errors.Join(err, store.Close())
	}
	return store, bus, nil
}

// followRevocations opens the session revocations zero-pep-proxy writes and follows them until Stop. Without
// revocations_database_url it returns nil, and a session_cookie enforcer denies every request; provisioning
// refuses such a policy before it gets here.
func (a *App) followRevocations() (pep.SessionRevocations, error) {
	if a.RevocationsDatabaseURL == "" {
		return nil, nil
	}
	open := a.openRevocations
	if open == nil {
		open = openPostgresRevocations
	}
	openCtx, cancel := context.WithTimeout(context.Background(), revocationsOpenTimeout)
	defer cancel()
	store, bus, err := open(openCtx, a.RevocationsDatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	closeAll := func() error { return errors.Join(bus.Close(), store.Close()) }
	set, err := revoked.New(revoked.Config{
		Store:   store,
		Bus:     bus,
		Prefix:  pep.SessionRevocationsKeyPrefix,
		Channel: pep.SessionRevocationsChannel,
		TTL:     revocationTTL,
		Logger:  a.logger,
	})
	if err != nil {
		return nil, errors.Join(err, closeAll())
	}
	ctx, stop := context.WithCancel(context.Background())
	if err := set.Follow(ctx); err != nil {
		stop()
		return nil, errors.Join(err, closeAll())
	}
	a.stopRevocations = func() {
		stop()
		if err := closeAll(); err != nil {
			a.logger.Warn("closing the session revocations", "error", err)
		}
	}
	a.logger.Info("following the session revocations of zero-pep-proxy")
	return set, nil
}

// requireRevocations refuses a policy with a session_cookie enforcer when the app has no revocations configured
// (server rule 17): it would deny every request, and a configuration that cannot work is refused at start rather
// than found in production.
func requireRevocations(enforcer pep.Enforcer, app *App) error {
	if app.RevocationsDatabaseURL != "" || !usesSessionCookie(enforcer) {
		return nil
	}
	return errors.New("enforcer SessionCookie needs revocations_database_url in the global pep block: without zero-pep-proxy's revocations a signed-out session would pass until its snapshot expires")
}

// usesSessionCookie reports whether enforcer is or holds a session cookie enforcer.
func usesSessionCookie(enforcer pep.Enforcer) bool {
	if enforcer == nil {
		return false
	}
	if holder, ok := enforcer.(*pep.EnforcerHolder); ok {
		return holder != nil && usesSessionCookie(holder.Enforcer)
	}
	if enforcer.Type() == pep.EnforcerTypeSessionCookie {
		return true
	}
	composite, ok := enforcer.(interface{ Enforcers() []pep.Enforcer })
	if !ok {
		return false
	}
	return slices.ContainsFunc(composite.Enforcers(), usesSessionCookie)
}
