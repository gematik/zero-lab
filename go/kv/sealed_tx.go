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
	"errors"
	"time"
)

// ErrSealedEvent is what a transaction of a sealed store returns for an event: the store seals records,
// and an event it passed on would reach the database in the clear. Events of a sealed store are published
// through a sealed feed.
var ErrSealedEvent = errors.New("kv: a sealed store publishes no events: they would not be sealed")

// Tx implements [Transactor] over the store below: what a transaction reads is opened and what it writes
// is sealed, record by record, as outside a transaction. It needs an inner [Transactor].
func (s *sealedStore) Tx(ctx context.Context, fn func(tx Tx) error) error {
	inner, ok := s.inner.(Transactor)
	if !ok {
		return ErrNotTransactor
	}
	return inner.Tx(ctx, func(tx Tx) error { return fn(&sealedTx{s: s, tx: tx}) })
}

type sealedTx struct {
	s  *sealedStore
	tx Tx
}

func (t *sealedTx) Get(ctx context.Context, key string) ([]byte, bool, error) {
	record, found, err := t.tx.Get(ctx, key)
	if err != nil || !found {
		return nil, false, err
	}
	return t.s.open(key, record)
}

func (t *sealedTx) Take(ctx context.Context, key string) ([]byte, bool, error) {
	record, found, err := t.tx.Take(ctx, key)
	if err != nil || !found {
		return nil, false, err
	}
	return t.s.open(key, record)
}

func (t *sealedTx) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	record, err := t.s.seal(key, value, ttl)
	if err != nil {
		return err
	}
	return t.tx.Set(ctx, key, record, ttl)
}

func (t *sealedTx) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	record, err := t.s.seal(key, value, ttl)
	if err != nil {
		return false, err
	}
	return t.tx.SetIfAbsent(ctx, key, record, ttl)
}

func (t *sealedTx) Delete(ctx context.Context, key string) error { return t.tx.Delete(ctx, key) }

func (t *sealedTx) Publish(context.Context, string, []byte, time.Duration) error {
	return ErrSealedEvent
}
