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

package titls

import (
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

// webCorpusCheck is the web profile over the corpus's root in place of the system's (TLSV-040).
func webCorpusCheck(t *testing.T) *WebCheck {
	t.Helper()
	return NewWebCheck([]*x509.Certificate{corpusCert(t, "web-root.pem")})
}

// TLSV-050 and TLSV-051: an accepted web verdict is reused for the same chain and host until its revocation
// status is a day old, then the responder is asked again; another host is judged afresh.
func TestTLSV050AWebVerdictIsReusedUntilItsStatusIsADayOld(t *testing.T) {
	fetch := &network{ocsp: corpusFile(t, "ocsp/web-p256-good.der")}
	verifier := NewWebVerifier(webCorpusCheck(t), fetch, Options{})
	chain := [][]byte{corpusDER(t, "web-p256.pem"), corpusDER(t, "web-ca.pem")}
	verify := func(now time.Time) Verdict { return verifier.Verify(t.Context(), chain, "www.web.test", nil, now) }

	if v := verify(at); !v.Valid() || fetch.asked.Load() != 1 {
		t.Fatalf("first: %s %s, asked %d", v.Code, v.Detail, fetch.asked.Load())
	}
	if v := verify(at.Add(23 * time.Hour)); !v.Valid() || fetch.asked.Load() != 1 {
		t.Fatalf("within the day: %s, asked %d; expected reuse", v.Code, fetch.asked.Load())
	}
	if v := verify(at.Add(24 * time.Hour)); !v.Valid() || fetch.asked.Load() != 2 {
		t.Fatalf("a day on: %s, asked %d; expected the responder asked again", v.Code, fetch.asked.Load())
	}
	if v := verifier.Verify(t.Context(), chain, "other.web.test", nil, at); v.Code != NameMismatch {
		t.Fatalf("another host: %s", v.Code)
	}
	if v := verifier.Verify(t.Context(), chain, "WWW.Web.Test", nil, at.Add(24*time.Hour)); !v.Valid() || fetch.asked.Load() != 2 {
		t.Fatalf("the host in other case: %s, asked %d; expected reuse", v.Code, fetch.asked.Load())
	}
}

// TLSV-050: a refusal is never reused; every verification asks the responder again.
func TestTLSV050ARefusalIsJudgedAgainEveryTime(t *testing.T) {
	fetch := &network{ocsp: corpusFile(t, "ocsp/web-revoked-revoked.der")}
	verifier := NewWebVerifier(webCorpusCheck(t), fetch, Options{})
	chain := [][]byte{corpusDER(t, "web-revoked.pem"), corpusDER(t, "web-ca.pem")}
	for round := int64(1); round <= 3; round++ {
		if v := verifier.Verify(t.Context(), chain, "www.web.test", nil, at); v.Code != Revoked {
			t.Fatalf("round %d: %s", round, v.Code)
		}
		if fetch.asked.Load() != round {
			t.Fatalf("round %d: asked %d times, expected the responder each round", round, fetch.asked.Load())
		}
	}
	if verifier.verdicts.size() != 0 {
		t.Fatalf("%d verdicts kept", verifier.verdicts.size())
	}
}

// TLSV-044 and TLSV-050: a server no source gives a status for is accepted with revocation_unavailable; the
// verdict rests on no status, so every verification asks the responder and the CRL host again.
func TestTLSV044AServerWithoutStatusIsAcceptedWithAWarningAndNotReused(t *testing.T) {
	fetch := &network{}
	verifier := NewWebVerifier(webCorpusCheck(t), fetch, Options{})
	chain := [][]byte{corpusDER(t, "web-p256.pem"), corpusDER(t, "web-ca.pem")}
	for round := int64(1); round <= 2; round++ {
		v := verifier.Verify(t.Context(), chain, "www.web.test", nil, at)
		if !v.Valid() || !slices.Equal(v.Warnings, []string{WarningRevocationUnavailable}) {
			t.Fatalf("round %d: %s %q", round, v.Code, v.Warnings)
		}
		if fetch.asked.Load() != 2*round {
			t.Fatalf("round %d: asked %d times, expected OCSP and CRL each round", round, fetch.asked.Load())
		}
	}
	if verifier.verdicts.size() != 0 {
		t.Fatalf("%d verdicts kept", verifier.verdicts.size())
	}
}

// TLSV-041 and TLSV-050: an RSA-2048 server is accepted with key_phased_out, and a reused verdict reports
// the warning too.
func TestTLSV041AReusedVerdictKeepsItsWarning(t *testing.T) {
	fetch := &network{}
	verifier := NewWebVerifier(webCorpusCheck(t), fetch, Options{})
	chain := [][]byte{corpusDER(t, "web-rsa2048.pem"), corpusDER(t, "web-ca.pem")}
	stapled := corpusFile(t, "ocsp/web-rsa2048-good.der")
	for _, detail := range []string{"valid", "reused"} {
		v := verifier.Verify(t.Context(), chain, "www.web.test", stapled, at)
		if !v.Valid() || v.Detail != detail || !slices.Equal(v.Warnings, []string{WarningKeyPhasedOut}) {
			t.Fatalf("%s: %s %q %q", detail, v.Code, v.Detail, v.Warnings)
		}
	}
}

// TLSV-041: RSA from 3000 bits is admitted, 2048 to 2999 bits phased out, anything smaller refused;
// TLSV-042's CA floor stays at 2048.
func TestTLSV041RSABelow3000IsPhasedOutAndBelow2048Refused(t *testing.T) {
	for _, c := range []struct {
		bits                  int
		admissible, phasedOut bool
	}{{1024, false, false}, {2047, false, false}, {2048, true, true}, {2999, true, true}, {3000, true, false}, {4096, true, false}} {
		k := key{bits: c.bits}
		if k.admissibleEndEntity() != c.admissible || (k.admissibleEndEntity() && k.phasedOut()) != c.phasedOut {
			t.Errorf("RSA %d: admissible %v, phased out %v", c.bits, k.admissibleEndEntity(), k.phasedOut())
		}
	}
	if (key{bits: 2047}).admissibleCA() || !(key{bits: 2048}).admissibleCA() {
		t.Error("the CA floor moved")
	}
	for _, curve := range []string{"P-256", "P-384"} {
		if k := (key{curve: curve}); !k.admissibleEndEntity() || k.phasedOut() {
			t.Errorf("%s", curve)
		}
	}
	if (key{curve: "P-521"}).admissibleEndEntity() || (key{}).admissibleEndEntity() {
		t.Error("another key is admitted")
	}
}

func tiCorpusVerifier(t *testing.T, fetch *network, clock *fixedClock) (*TiVerifier, *TrustSource) {
	t.Helper()
	source := NewTrustSource(corpusStore(t, readManifest(t), "ti"))
	return NewTiVerifier(source, responder(fetch, clock), Options{Now: clock.Now}), source
}

// TLSV-051: a ti verdict rests on its OCSP answer for OCSP-005's hour at most.
func TestTLSV051ATiVerdictIsReusedForTheHourOfItsOCSPAnswer(t *testing.T) {
	clock := newClock(at)
	fetch := &network{ocsp: corpusFile(t, "ocsp/ti-good-good.der")}
	verifier, _ := tiCorpusVerifier(t, fetch, clock)
	chain := [][]byte{corpusDER(t, "ti-good.pem"), corpusDER(t, "ti-ca.pem")}
	verify := func(now time.Time) Verdict {
		clock.set(now)
		return verifier.Verify(t.Context(), chain, "svc.ti.test", nil, now)
	}
	if v := verify(at); !v.Valid() || fetch.asked.Load() != 1 {
		t.Fatalf("first: %s %s, asked %d", v.Code, v.Detail, fetch.asked.Load())
	}
	if v := verify(at.Add(59 * time.Minute)); !v.Valid() || fetch.asked.Load() != 1 {
		t.Fatalf("within the hour: %s, asked %d; expected reuse", v.Code, fetch.asked.Load())
	}
	// The responder's answer is now older than OCSP-005 allows, so asking again cannot succeed.
	if v := verify(at.Add(61 * time.Minute)); v.Valid() || fetch.asked.Load() == 1 {
		t.Fatalf("an hour on: %s, asked %d; expected the responder asked again", v.Code, fetch.asked.Load())
	}
}

// TLSV-050: replacing the trust material ends the reuse of every verdict reached with the old one; a
// withdrawn material refuses every ti server (TLSV-033).
func TestTLSV050ASwappedTrustSnapshotEndsReuse(t *testing.T) {
	clock := newClock(at)
	fetch := &network{ocsp: corpusFile(t, "ocsp/ti-good-good.der")}
	verifier, source := tiCorpusVerifier(t, fetch, clock)
	chain := [][]byte{corpusDER(t, "ti-good.pem"), corpusDER(t, "ti-ca.pem")}
	verify := func() Verdict { return verifier.Verify(t.Context(), chain, "svc.ti.test", nil, at) }

	if v := verify(); !v.Valid() {
		t.Fatalf("%s: %s", v.Code, v.Detail)
	}
	if v := verify(); !v.Valid() || fetch.asked.Load() != 1 {
		t.Fatalf("same snapshot: %s, asked %d; expected reuse", v.Code, fetch.asked.Load())
	}
	source.Swap(source.Store())
	if v := verify(); !v.Valid() || fetch.asked.Load() != 2 {
		t.Fatalf("new snapshot: %s, asked %d; expected a fresh verification", v.Code, fetch.asked.Load())
	}
	source.Swap(nil)
	if v := verify(); v.Code != TrustMaterialUnavailable {
		t.Fatalf("withdrawn: %s", v.Code)
	}
}

// TLSV-050: the cache holds at most its size; an insert first drops the verdicts no longer reusable, then
// the one that would end soonest, and a verdict is not served at or after its end.
func TestTLSV050TheVerdictCacheIsBounded(t *testing.T) {
	cache := newVerdictCache(3)
	key := func(i int) verdictKey { return keyFor("web", 0, strconv.Itoa(i), nil) }
	valid := func(until time.Time) Verdict { return Verdict{Code: Valid, ReusableUntil: until} }

	cache.keep(key(1), valid(at.Add(time.Minute)), at)
	cache.keep(key(2), valid(at.Add(3*time.Hour)), at)
	cache.keep(key(3), valid(at.Add(2*time.Hour)), at)
	cache.keep(key(4), valid(at.Add(4*time.Hour)), at)
	if cache.size() != 3 {
		t.Fatalf("%d entries", cache.size())
	}
	if _, ok := cache.reusable(key(1), at); ok {
		t.Fatal("the soonest-ending verdict survived a full insert")
	}
	for _, i := range []int{2, 3, 4} {
		if _, ok := cache.reusable(key(i), at); !ok {
			t.Fatalf("verdict %d was dropped", i)
		}
	}

	later := at.Add(150 * time.Minute)
	cache.keep(key(5), valid(later.Add(time.Hour)), later)
	if _, ok := cache.reusable(key(3), later); ok {
		t.Fatal("an ended verdict is served")
	}
	if _, ok := cache.reusable(key(2), later); !ok {
		t.Fatal("a live verdict was evicted while an ended one could go")
	}
	if reused, ok := cache.reusable(key(4), at.Add(4*time.Hour)); ok {
		t.Fatalf("served at its end, until %s", reused.ReusableUntil)
	}

	cache.keep(key(6), Verdict{Code: NameMismatch, ReusableUntil: at.Add(time.Hour)}, at)
	cache.keep(key(7), valid(at), at)
	for _, i := range []int{6, 7} {
		if _, ok := cache.reusable(key(i), at); ok {
			t.Fatalf("verdict %d is a refusal or ended, and was kept", i)
		}
	}

	off := newVerdictCache(-1)
	off.keep(key(1), valid(at.Add(time.Hour)), at)
	if off.size() != 0 {
		t.Fatal("a negative size keeps verdicts")
	}
}

// TLSV-050: concurrent handshakes share the cache safely and it stays bounded (run with -race).
func TestTLSV050TheVerdictCacheIsSafeForConcurrentUse(t *testing.T) {
	cache := newVerdictCache(16)
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 200 {
				key := keyFor("web", 0, fmt.Sprint(worker, i%40), nil)
				cache.keep(key, Verdict{Code: Valid, ReusableUntil: at.Add(time.Duration(i+1) * time.Minute)}, at)
				cache.reusable(key, at)
			}
		})
	}
	wg.Wait()
	if cache.size() > 16 {
		t.Fatalf("%d entries", cache.size())
	}
}

// TLSV-050: the key separates profiles, trust snapshots, hosts and chains, and certificate boundaries; the
// host compares without case.
func TestTLSV050TheKeyNamesChainHostProfileAndSnapshot(t *testing.T) {
	base := keyFor("ti", 1, "svc.ti.test", [][]byte{{1, 2}, {3}})
	for name, other := range map[string]verdictKey{
		"profile":  keyFor("web", 1, "svc.ti.test", [][]byte{{1, 2}, {3}}),
		"snapshot": keyFor("ti", 2, "svc.ti.test", [][]byte{{1, 2}, {3}}),
		"host":     keyFor("ti", 1, "alt.ti.test", [][]byte{{1, 2}, {3}}),
		"boundary": keyFor("ti", 1, "svc.ti.test", [][]byte{{1}, {2, 3}}),
		"chain":    keyFor("ti", 1, "svc.ti.test", [][]byte{{1, 2}}),
	} {
		if other == base {
			t.Errorf("another %s, the same key", name)
		}
	}
	if keyFor("ti", 1, "SVC.ti.TEST", [][]byte{{1, 2}, {3}}) != base {
		t.Error("the host's case changes the key")
	}
}
