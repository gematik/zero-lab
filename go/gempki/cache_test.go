package gempki_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoCache_AlwaysMisses(t *testing.T) {
	t.Parallel()

	c := gempki.NoCache()
	ctx := t.Context()

	require.NoError(t, c.Put(ctx, "k", &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Hour))
	got, hit, err := c.Get(ctx, "k")
	require.NoError(t, err)
	assert.False(t, hit)
	assert.Nil(t, got)
}

func TestInMemoryCache_HitAndMiss(t *testing.T) {
	t.Parallel()

	c := gempki.NewInMemoryCache(10)
	ctx := t.Context()

	want := &gempki.RevocationResult{
		Status: gempki.RevocationStatusGood,
		Source: gempki.RevocationSourceOCSP,
	}
	require.NoError(t, c.Put(ctx, "k1", want, time.Hour))

	got, hit, err := c.Get(ctx, "k1")
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Same(t, want, got)

	_, hit, err = c.Get(ctx, "missing")
	require.NoError(t, err)
	assert.False(t, hit)
}

func TestInMemoryCache_Expiry(t *testing.T) {
	t.Parallel()

	c := gempki.NewInMemoryCache(10)
	ctx := t.Context()

	require.NoError(t, c.Put(ctx, "k", &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Nanosecond))

	// A nanosecond TTL has effectively already elapsed by the time we read.
	time.Sleep(time.Millisecond)
	_, hit, err := c.Get(ctx, "k")
	require.NoError(t, err)
	assert.False(t, hit, "expired entry must report as miss")
}

func TestInMemoryCache_Eviction_AtCapacity(t *testing.T) {
	t.Parallel()

	c := gempki.NewInMemoryCache(2)
	ctx := t.Context()

	require.NoError(t, c.Put(ctx, "a", &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Hour))
	require.NoError(t, c.Put(ctx, "b", &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Hour))
	require.NoError(t, c.Put(ctx, "c", &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Hour))

	assert.Equal(t, 2, c.Len(), "capacity must be respected")
	// "a" was inserted first; it should be the one evicted.
	_, hit, err := c.Get(ctx, "a")
	require.NoError(t, err)
	assert.False(t, hit, "oldest entry must be evicted when at capacity")
}

func TestInMemoryCache_RejectsBadInputs(t *testing.T) {
	t.Parallel()

	c := gempki.NewInMemoryCache(2)
	ctx := t.Context()

	assert.Error(t, c.Put(ctx, "k", &gempki.RevocationResult{}, 0),
		"non-positive TTL must be rejected")
	assert.Error(t, c.Put(ctx, "k", nil, time.Hour),
		"nil RevocationResult must be rejected")
}

func TestInMemoryCache_ZeroCapacityClampsToOne(t *testing.T) {
	t.Parallel()

	c := gempki.NewInMemoryCache(0)
	ctx := t.Context()
	require.NoError(t, c.Put(ctx, "k", &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Hour))
	assert.Equal(t, 1, c.Len())
}

func TestInMemoryCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	c := gempki.NewInMemoryCache(100)
	ctx := context.Background()
	const goroutines = 16
	const opsPerG = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			for i := range opsPerG {
				key := byteKey(g, i)
				_ = c.Put(ctx, key, &gempki.RevocationResult{Status: gempki.RevocationStatusGood}, time.Hour)
				_, _, _ = c.Get(ctx, key)
			}
		}(g)
	}
	wg.Wait()
	// We don't assert exact size — eviction and goroutine interleaving make
	// that unstable. What matters is that no race or panic occurred; the race
	// detector (go test -race) is the real check here.
}

func byteKey(g, i int) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[g&0xf], hex[(g>>4)&0xf], hex[i&0xf], hex[(i>>4)&0xf]})
}
