package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

var cacheBucket = []byte("cache")

// boltCache implements kon.Cache using bbolt with a time-based TTL.
type boltCache struct {
	db  *bbolt.DB
	ttl time.Duration
}

// cacheDir returns the directory for the cache database.
func cacheDir() (string, error) {
	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "telematik", "kon"), nil
}

// cachePath returns the full path to the cache database file.
func cachePath() (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cache.db"), nil
}

// openBoltCache opens (or creates) a bbolt database at the XDG cache path.
// The TTL controls how long entries remain valid.
func openBoltCache(ttl time.Duration) (*boltCache, error) {
	path, err := cachePath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(cacheBucket)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}

	return &boltCache{db: db, ttl: ttl}, nil
}

// clearCache removes the cache database file from disk.
func clearCache() error {
	path, err := cachePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintf(os.Stderr, "Cache cleared: %s\n", path)
	return nil
}

func (c *boltCache) Get(key string) ([]byte, bool) {
	var result []byte
	c.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(cacheBucket)
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		// First 8 bytes are the Unix timestamp (seconds)
		if len(v) < 8 {
			return nil
		}
		ts := int64(binary.LittleEndian.Uint64(v[:8]))
		if time.Since(time.Unix(ts, 0)) > c.ttl {
			return nil
		}
		result = make([]byte, len(v)-8)
		copy(result, v[8:])
		return nil
	})
	if result == nil {
		return nil, false
	}
	return result, true
}

func (c *boltCache) Set(key string, value []byte) {
	c.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(cacheBucket)
		buf := make([]byte, 8+len(value))
		binary.LittleEndian.PutUint64(buf[:8], uint64(time.Now().Unix()))
		copy(buf[8:], value)
		return b.Put([]byte(key), buf)
	})
}

func (c *boltCache) Close() error {
	return c.db.Close()
}
