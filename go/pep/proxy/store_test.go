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

package proxy

import (
	"context"
	"encoding/json/v2"
	"sync"
	"time"
)

// memorySessions is a SessionStore in the memory of the test. Records are copied in and out, as a store does.
type memorySessions struct {
	mu      sync.Mutex
	records map[string]memoryRecord
	states  map[string]memoryRecord
}

type memoryRecord struct {
	value   []byte
	expires time.Time
}

func newMemorySessions() *memorySessions {
	return &memorySessions{records: map[string]memoryRecord{}, states: map[string]memoryRecord{}}
}

func (m *memorySessions) Save(_ context.Context, s *Session, ttl time.Duration) error {
	record, err := json.Marshal(s)
	if err != nil {
		return err
	}
	id, err := json.Marshal(s.ID)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[s.ID] = memoryRecord{value: record, expires: time.Now().Add(ttl)}
	if s.State != "" {
		m.states[s.State] = memoryRecord{value: id, expires: time.Now().Add(LoginStateTTL)}
	}
	return nil
}

func (m *memorySessions) get(table map[string]memoryRecord, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := table[key]
	if !ok || time.Now().After(r.expires) {
		return nil, false
	}
	return r.value, true
}

func (m *memorySessions) Load(_ context.Context, id string) (*Session, error) {
	data, ok := m.get(m.records, id)
	if !ok {
		return nil, ErrSessionNotFound
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (m *memorySessions) TakeSessionID(_ context.Context, state string) (string, error) {
	m.mu.Lock()
	r, ok := m.states[state]
	delete(m.states, state)
	m.mu.Unlock()
	if !ok || time.Now().After(r.expires) {
		return "", ErrSessionNotFound
	}
	data := r.value
	var id string
	err := json.Unmarshal(data, &id)
	return id, err
}

func (m *memorySessions) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, id)
	return nil
}

func (m *memorySessions) DeleteState(_ context.Context, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, state)
	return nil
}

// put stores a raw record under id, as a rogue storage admin would.
func (m *memorySessions) put(id string, record []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[id] = memoryRecord{value: record, expires: time.Now().Add(time.Hour)}
}

func (m *memorySessions) holds(id string) bool {
	_, ok := m.get(m.records, id)
	return ok
}

// testConfig is a Config with in-memory state, for one replica.
func testConfig(backend Backend) Config {
	return Config{Backend: backend, Sessions: newMemorySessions(), Revocations: NewMemoryRevocations(nil), CookieName: "TEST-SID"}
}
