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

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/jackc/pgx/v5"
)

const busReconnectDelay = 2 * time.Second

// pgBus is a kv.Bus over PostgreSQL LISTEN/NOTIFY. Publish runs pg_notify on a small connection pool; each
// Subscribe holds a dedicated pgx connection that LISTENs and reconnects on drop. Delivery is best-effort
// (a reconnect gap can miss a NOTIFY), so it is paired with the durable revoked-set backstop (Stage 3).
type pgBus struct {
	dsn string
	db  *sql.DB // publish path (pg_notify)
}

// OpenBus connects to Postgres at dsn for publishing notifications; subscribers dial their own listener
// connection. Returns a kv.Bus.
func OpenBus(ctx context.Context, dsn string) (kv.Bus, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres bus: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/postgres bus: ping: %w", err)
	}
	db.SetMaxOpenConns(2)
	return &pgBus{dsn: dsn, db: db}, nil
}

func (b *pgBus) Publish(ctx context.Context, channel, payload string) error {
	if _, err := b.db.ExecContext(ctx, "select pg_notify($1, $2)", channel, payload); err != nil {
		return fmt.Errorf("kv/postgres bus: notify %q: %w", channel, err)
	}
	return nil
}

func (b *pgBus) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	out := make(chan string, 64)
	go b.listen(ctx, channel, out)
	return out, nil
}

// listen holds a dedicated connection LISTENing on channel and forwards notifications to out, reconnecting
// on any connection error until ctx is cancelled.
func (b *pgBus) listen(ctx context.Context, channel string, out chan<- string) {
	defer close(out)
	listenSQL := "LISTEN " + pgx.Identifier{channel}.Sanitize()
	for ctx.Err() == nil {
		if err := b.listenOnce(ctx, listenSQL, out); err != nil && ctx.Err() == nil {
			slog.Warn("kv/postgres bus: listener disconnected, reconnecting", "channel", channel, "error", err)
			select {
			case <-ctx.Done():
			case <-time.After(busReconnectDelay):
			}
		}
	}
}

func (b *pgBus) listenOnce(ctx context.Context, listenSQL string, out chan<- string) error {
	conn, err := pgx.Connect(ctx, b.dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, listenSQL); err != nil {
		return err
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		select {
		case out <- n.Payload:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (b *pgBus) Close() error {
	return b.db.Close()
}
