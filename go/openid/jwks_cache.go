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

package openid

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// jwksTTL is how long a key set is used before it is fetched again. A rotation in between is picked up by the
	// unknown kid, a removal of a key only by this refresh.
	jwksTTL = time.Hour
	// jwksMinFetchInterval is the least time between two fetches, successful or not, and what bounds the requests
	// an attacker can cause at the issuer with random kids.
	jwksMinFetchInterval = time.Minute
	// jwksMaxStale is how long past jwksTTL the last good set stands in while the issuer does not answer. A key the
	// issuer withdrew stays trusted that long, so it is hours for an outage, not days.
	jwksMaxStale = 6 * time.Hour
	// jwksMaxSize bounds a response: real sets have a few keys of some KiB.
	jwksMaxSize = 1 << 20
	// jwksFetchTimeout bounds a fetch even for a client and context without a deadline, since other logins wait on it.
	jwksFetchTimeout = 30 * time.Second
)

// keySetCache holds the JWKS of an issuer. A refresh that fails keeps the last good set until it is jwksTTL +
// jwksMaxStale old, and from then on nothing verifies until the issuer answers again.
type keySetCache struct {
	uri        string
	httpClient *http.Client
	now        func() time.Time

	// fetching is held during a fetch, as a channel so that a waiting caller still honours its context.
	fetching chan struct{}

	mu          sync.Mutex
	keys        *jose.JSONWebKeySet
	fetchedAt   time.Time
	lastAttempt time.Time
	lastErr     error
}

func newKeySetCache(uri string, httpClient *http.Client) *keySetCache {
	return &keySetCache{
		uri:        uri,
		httpClient: httpClient,
		now:        time.Now,
		fetching:   make(chan struct{}, 1),
	}
}

// keySet returns the set to look up kid in; an empty kid asks for no particular key. The set need not hold kid: the
// verification refuses a token whose key stays unknown.
func (c *keySetCache) keySet(ctx context.Context, kid string) (*jose.JSONWebKeySet, error) {
	if keys, ok := c.fresh(kid); ok {
		return keys, nil
	}

	select {
	case c.fetching <- struct{}{}:
		defer func() { <-c.fetching }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// The fetch this caller waited for may have brought what it needs.
	if keys, ok := c.fresh(kid); ok {
		return keys, nil
	}
	if c.mayFetch() {
		c.fetch(ctx)
	}
	return c.usable()
}

func (c *keySetCache) fresh(kid string) (*jose.JSONWebKeySet, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil || !c.now().Before(c.fetchedAt.Add(jwksTTL)) {
		return nil, false
	}
	if kid != "" && len(c.keys.Key(kid)) == 0 {
		return nil, false
	}
	return c.keys, true
}

func (c *keySetCache) mayFetch() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAttempt.IsZero() || !c.now().Before(c.lastAttempt.Add(jwksMinFetchInterval))
}

func (c *keySetCache) usable() (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		return nil, fmt.Errorf("no key set from %s: %w", c.uri, c.failure())
	}
	if !c.now().Before(c.fetchedAt.Add(jwksTTL + jwksMaxStale)) {
		return nil, fmt.Errorf("key set from %s is too old to rely on: %w", c.uri, c.failure())
	}
	return c.keys, nil
}

func (c *keySetCache) failure() error {
	if c.lastErr != nil {
		return c.lastErr
	}
	return errors.New("nothing fetched yet")
}

func (c *keySetCache) fetch(ctx context.Context) {
	c.mu.Lock()
	previousAttempt := c.lastAttempt
	c.lastAttempt = c.now()
	c.mu.Unlock()

	keys, err := c.download(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastErr = err
		// A caller that gave up says nothing about the issuer and must not use up the fetch of the next one.
		if ctx.Err() != nil {
			c.lastAttempt = previousAttempt
		}
		return
	}
	c.keys, c.fetchedAt, c.lastErr = keys, c.now(), nil
}

func (c *keySetCache) download(ctx context.Context) (*jose.JSONWebKeySet, error) {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > jwksMaxSize {
		return nil, fmt.Errorf("response exceeds %d bytes", jwksMaxSize)
	}
	keys, err := ParseKeySet(body)
	if err != nil {
		return nil, err
	}
	// An issuer never withdraws all its keys in one go; taking this for a set would stop every login at once.
	if len(keys.Keys) == 0 {
		return nil, errors.New("key set is empty")
	}
	return keys, nil
}
