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

package bundlefile

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// captured is when spec/tsl-detached/testdata was fetched.
var captured = time.Date(2026, 11, 1, 16, 47, 42, 0, time.UTC)

const (
	refList  = "../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref"
	refRoots = "../../../rust/ti-pki/src/roots-nonprod.json"
	// marker stands for content of the file; an error that holds it would carry the file into a log.
	marker = "FILE-CONTENT-7f3a"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// bundleJSON is the captured reference material as `ti pki trust export` writes it, fetched at fetchedAt.
func bundleJSON(t *testing.T, fetchedAt time.Time) []byte {
	t.Helper()
	anchor := sha256.Sum256(tipki.AnchorNonProd)
	b64 := func(path string) string { return base64.StdEncoding.EncodeToString(readFile(t, path)) }
	meta := map[string]any{"fetched_at": fetchedAt.Unix(), "source": "file"}
	data, err := json.Marshal(map[string]any{
		"format_version": 2, "label": "test", "anchor_sha256": hex.EncodeToString(anchor[:]),
		"roots": b64(refRoots), "roots_meta": meta,
		"tsl": b64(refList + ".xml"), "tsl_meta": meta,
		"tsl_sig": b64(refList + ".sig"), "tsl_sig_meta": meta,
		"tsl_ocsp": b64(refList + ".ocsp"), "tsl_ocsp_meta": meta,
	}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func gzipped(t testing.TB, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// writeAtomically replaces path as a producer does, so a reader never sees half a file.
func writeAtomically(t *testing.T, path string, data []byte) {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

type answering tipki.RevocationStatus

func (a answering) Check(context.Context, *x509.Certificate, *x509.Certificate, *tipki.TrustStore) (*tipki.RevocationResult, error) {
	return &tipki.RevocationResult{Status: tipki.RevocationStatus(a), RevokedAt: captured.Add(-time.Hour)}, nil
}

// clock is a time the test moves while the background loop reads it.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock(at time.Time) *clock { return &clock{now: at} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = at
}

func config(path string, at *clock) Config {
	return Config{
		Path:          path,
		Anchor:        tipki.AnchorNonProd,
		SignerAnchors: [][]byte{tipki.TSLSignerAnchorNonProd},
		Checker:       answering(tipki.RevocationGood),
		Clock:         at.Now,
	}
}

// loaded is a Trust over a bundle fetched at captured, judged at captured.
func loaded(t *testing.T) (*Trust, string, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	writeAtomically(t, path, bundleJSON(t, captured))
	at := newClock(captured)
	trust, err := New(t.Context(), config(path, at))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trust.Close)
	return trust, path, at
}

func current(t *testing.T, trust *Trust) *tipki.TrustStore {
	t.Helper()
	store, err := trust.Current()
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// keeps asserts that a reload failed and left the store in use, also in the TLS source.
func keeps(t *testing.T, trust *Trust, before *tipki.TrustStore, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("the reload succeeded")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("the error quotes the file: %v", err)
	}
	if got := current(t, trust); got != before {
		t.Error("the store in use was replaced")
	}
	if trust.Source().Store() != before {
		t.Error("the TLS source no longer holds the store in use")
	}
}

func TestServerRule8_TheMountedBundleIsTheVerifiedList(t *testing.T) {
	trust, _, _ := loaded(t)
	store := current(t, trust)
	if store.TSL.TSL.SequenceNumber == 0 || len(store.Roots) == 0 || len(store.Intermediates) == 0 {
		t.Errorf("sequence %d, %d roots, %d CAs", store.TSL.TSL.SequenceNumber, len(store.Roots), len(store.Intermediates))
	}
	if !bytes.Equal(store.Roots[0].Raw, tipki.AnchorNonProd) {
		t.Error("the walk does not start at the configured anchor")
	}
	if trust.Source().Store() != store {
		t.Error("the TLS source does not hold the store")
	}
}

func TestServerRule8_ANewValidBundleReplacesTheOneInUse(t *testing.T) {
	trust, path, at := loaded(t)
	before := current(t, trust)
	at.set(captured.Add(time.Hour))
	writeAtomically(t, path, bundleJSON(t, captured.Add(30*time.Minute)))
	if err := trust.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := current(t, trust)
	if after == before {
		t.Fatal("the new bundle was not taken")
	}
	if trust.Source().Store() != after {
		t.Error("the TLS source was not swapped")
	}
	// It stands from the new bundle's fetched_at, past where the old one would have expired.
	at.set(captured.Add(tipki.MaxBundleAge + time.Minute))
	if _, err := trust.Current(); err != nil {
		t.Errorf("the new bundle's age: %v", err)
	}
}

func TestServerRule8_TheSameBundleIsNotLoadedAgain(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	writeAtomically(t, path, bundleJSON(t, captured))
	if err := trust.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if current(t, trust) != before {
		t.Error("identical content replaced the store, and with it the verdicts the TLS source reuses")
	}
}

// A ConfigMap volume updates by repointing ..data; the file the path names keeps its modification time and size.
func TestServerRule8_AConfigMapSymlinkSwapIsSeen(t *testing.T) {
	dir := t.TempDir()
	stamp := captured.Add(-time.Hour)
	version := func(name string, data []byte) {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, name, "bundle.json")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	first, second := bundleJSON(t, captured), bundleJSON(t, captured.Add(time.Minute))
	if len(first) != len(second) {
		t.Fatal("the two bundles should have the same size")
	}
	version("..2026_11_01_a", first)
	if err := os.Symlink("..2026_11_01_a", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.json")
	if err := os.Symlink(filepath.Join("..data", "bundle.json"), path); err != nil {
		t.Fatal(err)
	}
	at := newClock(captured.Add(time.Hour))
	trust, err := New(t.Context(), config(path, at))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trust.Close)
	before := current(t, trust)

	version("..2026_11_01_b", second)
	if err := os.Symlink("..2026_11_01_b", filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := trust.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	if current(t, trust) == before {
		t.Error("the swapped bundle was not taken")
	}
}

func TestServerRule8_TheBackgroundReadPicksUpAChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	writeAtomically(t, path, bundleJSON(t, captured))
	at := newClock(captured.Add(time.Hour))
	cfg := config(path, at)
	cfg.Interval = 10 * time.Millisecond
	trust, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trust.Close)
	before := trust.Source().Store()
	writeAtomically(t, path, bundleJSON(t, captured.Add(time.Minute)))
	deadline := time.Now().Add(10 * time.Second)
	for trust.Source().Store() == before {
		if time.Now().After(deadline) {
			t.Fatal("the change was not read")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestServerRule16_AnInvalidBundleKeepsTheOneInUse(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	tampered := bytes.Replace(bundleJSON(t, captured.Add(time.Minute)), []byte(`"label":"test"`), []byte(`"label":"`+marker+`"`), 1)
	list := base64.StdEncoding.EncodeToString(readFile(t, refList+".xml"))
	flipped := base64.StdEncoding.EncodeToString(readFile(t, "../../../spec/tsl-detached/testdata/derived/ref-tampered.xml"))
	for name, data := range map[string][]byte{
		"not a bundle":      []byte(`{"` + marker + `":1}`),
		"not JSON":          []byte(marker),
		"a tampered list":   bytes.Replace(tampered, []byte(list), []byte(flipped), 1),
		"a truncated gzip":  gzipped(t, tampered)[:100],
		"an empty file":     nil,
		"a bundle too old":  bundleJSON(t, captured.Add(-tipki.MaxBundleAge)),
		"gzip of not JSON":  gzipped(t, []byte(marker)),
		"two gzip members":  append(gzipped(t, tampered), gzipped(t, tampered)...),
		"gzip and trailing": append(gzipped(t, tampered), marker...),
	} {
		t.Run(name, func(t *testing.T) {
			writeAtomically(t, path, data)
			keeps(t, trust, before, trust.Reload(t.Context()))
		})
	}
}

func TestServerRule16_AMissingBundleKeepsTheOneInUse(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	keeps(t, trust, before, trust.Reload(t.Context()))
}

func TestServerRule16_AnOlderBundleKeepsTheOneInUse(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	writeAtomically(t, path, bundleJSON(t, captured.Add(-time.Minute)))
	err := trust.Reload(t.Context())
	keeps(t, trust, before, err)
	if !strings.Contains(err.Error(), "fetched_at") {
		t.Errorf("err = %v", err)
	}
}

func TestTSLSIG053AnOlderListKeepsTheOneInUse(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	trust.mu.Lock()
	trust.state = &tipki.TSLState{ID: "a later list", SequenceNumber: before.TSL.TSL.SequenceNumber + 1}
	trust.mu.Unlock()
	writeAtomically(t, path, bundleJSON(t, captured.Add(time.Minute)))
	err := trust.Reload(t.Context())
	keeps(t, trust, before, err)
	if !strings.Contains(err.Error(), "TSLSIG-053") {
		t.Errorf("err = %v", err)
	}
}

func TestServerRule16_ARevokedSignerKeepsTheOneInUse(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	trust.checker = answering(tipki.RevocationRevoked)
	var stripped map[string]any
	if err := json.Unmarshal(bundleJSON(t, captured.Add(time.Minute)), &stripped); err != nil {
		t.Fatal(err)
	}
	delete(stripped, "tsl_ocsp")
	delete(stripped, "tsl_ocsp_meta")
	data, err := json.Marshal(stripped, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	writeAtomically(t, path, data)
	keeps(t, trust, before, trust.Reload(t.Context()))
	trust.checker = nil
	keeps(t, trust, before, trust.Reload(t.Context()))
}

func TestServerRule16_NoValidBundleNoStart(t *testing.T) {
	dir := t.TempDir()
	at := newClock(captured)
	if _, err := New(t.Context(), config(filepath.Join(dir, "none.json"), at)); err == nil {
		t.Error("started without a file")
	}
	path := filepath.Join(dir, "bundle.json")
	writeAtomically(t, path, []byte("{}"))
	if _, err := New(t.Context(), config(path, at)); err == nil {
		t.Error("started with an invalid bundle")
	}
	writeAtomically(t, path, bundleJSON(t, captured))
	for name, cfg := range map[string]func(*Config){
		"no path":               func(c *Config) { c.Path = "" },
		"no anchor":             func(c *Config) { c.Anchor = nil },
		"no signer anchors":     func(c *Config) { c.SignerAnchors = nil },
		"production anchors":    func(c *Config) { c.Anchor, c.SignerAnchors = tipki.AnchorProd, [][]byte{tipki.TSLSignerAnchorProd} },
		"a negative interval":   func(c *Config) { c.Interval = -time.Second },
		"a bundle at its limit": func(*Config) { at.set(captured.Add(tipki.MaxBundleAge)) },
	} {
		at.set(captured)
		c := config(path, at)
		cfg(&c)
		if _, err := New(t.Context(), c); err == nil {
			t.Errorf("started with %s", name)
		}
	}
}

func TestBUNDLE003TheStoreInUseStandsOnlyUntilItsAgeLimit(t *testing.T) {
	trust, path, at := loaded(t)
	writeAtomically(t, path, []byte("{}"))
	if err := trust.Reload(t.Context()); err == nil {
		t.Fatal("an invalid bundle loaded")
	}
	at.set(captured.Add(tipki.MaxBundleAge))
	if _, err := trust.Current(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a bundle at the age limit: %v", err)
	}
	trust.publish()
	if trust.Source().Store() != nil {
		t.Error("the TLS source still holds a bundle at the age limit")
	}
}

func TestServerRule16_TheListsNextUpdateEndsTheStore(t *testing.T) {
	trust, path, at := loaded(t)
	next := current(t, trust).TSL.TSL.NextUpdate
	if next.IsZero() {
		t.Fatal("the captured list has no NextUpdate")
	}
	// A bundle fetched just before NextUpdate is young enough; only the list's own validity ends it.
	at.set(next.Add(-time.Minute))
	writeAtomically(t, path, bundleJSON(t, at.Now()))
	if err := trust.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	at.set(next)
	if _, err := trust.Current(); err == nil || !strings.Contains(err.Error(), "NextUpdate") {
		t.Errorf("a list at its NextUpdate: %v", err)
	}
	trust.publish()
	if trust.Source().Store() != nil {
		t.Error("the TLS source still holds a list at its NextUpdate")
	}
}

func TestGzipABundleMayBeGzipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json.gz")
	plain := bundleJSON(t, captured)
	compressed := gzipped(t, plain)
	if len(compressed) >= 1<<20 || len(compressed) >= len(plain) {
		t.Errorf("gzipped: %d bytes of %d", len(compressed), len(plain))
	}
	writeAtomically(t, path, compressed)
	trust, err := New(t.Context(), config(path, newClock(captured)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trust.Close)
	current(t, trust)
}

func TestGzipADecompressionBombIsBounded(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	bomb := gzipped(t, make([]byte, maxBundleBytes+1))
	if len(bomb) > 1<<16 {
		t.Fatalf("the bomb is %d bytes", len(bomb))
	}
	writeAtomically(t, path, bomb)
	err := trust.Reload(t.Context())
	keeps(t, trust, before, err)
	if !strings.Contains(err.Error(), "decompresses to more than") {
		t.Errorf("err = %v", err)
	}
	if _, err := decode(gzipped(t, make([]byte, maxBundleBytes))); err != nil {
		t.Errorf("at the bound: %v", err)
	}
}

func TestGzipAFileLargerThanTheBoundIsNotRead(t *testing.T) {
	trust, path, _ := loaded(t)
	before := current(t, trust)
	writeAtomically(t, path, make([]byte, maxBundleBytes+1))
	err := trust.Reload(t.Context())
	keeps(t, trust, before, err)
	if !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	plain := []byte(`{"format_version":2}`)
	f.Add(plain)
	f.Add(gzipped(f, plain))
	f.Add(gzipped(f, plain)[:12])
	f.Add(append(gzipped(f, plain), 0))
	f.Add(append(gzipped(f, plain), gzipped(f, plain)...))
	f.Add(gzipped(f, make([]byte, 1<<16)))
	f.Add(gzipMagic)
	f.Fuzz(func(t *testing.T, raw []byte) {
		data, err := decode(raw)
		if err != nil {
			if data != nil {
				t.Error("data with an error")
			}
			return
		}
		if len(data) > maxBundleBytes {
			t.Errorf("%d bytes decompressed", len(data))
		}
		if !bytes.HasPrefix(raw, gzipMagic) && !bytes.Equal(data, raw) {
			t.Error("a plain file was changed")
		}
		bundle, err := tipki.ParseBundle(data)
		if (bundle == nil) != (err != nil) {
			t.Errorf("%+v %v", bundle, err)
		}
	})
}
