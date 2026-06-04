package main

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/vau"
	"github.com/gematik/zero-lab/go/gemidp"
)

// TestVAUResumptionE2E proves the snapshot/restore story end-to-end against a
// live ePA aggregator: open + authorize a VAU session, snapshot it, throw the
// HTTP client away (simulating a separate process), restore from the snapshot
// into a fresh client, then call VAU-Status and confirm the server still talks
// to us. Then we re-snapshot to confirm counters advanced and resume again, so
// the per-process counter-persist loop is fully exercised.
//
// Env-guarded by TI_TEST_KON_FILE — the test signs with a real SMC-B via
// Konnektor ExternalAuthenticate, so it needs the connector reachable. Without
// the env var it skips cleanly.
//
// We deliberately keep this in the `main` package (not `_test`) so it can poke
// at the package globals connectorConfigFlag / authCardFlagVal in the same
// way as TestConnectorAuthE2E.
func TestVAUResumptionE2E(t *testing.T) {
	konPath := os.Getenv("TI_TEST_KON_FILE")
	if konPath == "" {
		t.Skip("TI_TEST_KON_FILE not set; skipping VAU resumption e2e test")
	}

	prevConfig := connectorConfigFlag
	prevCard := authCardFlagVal
	connectorConfigFlag = konPath
	authCardFlagVal = ""
	t.Cleanup(func() {
		connectorConfigFlag = prevConfig
		authCardFlagVal = prevCard
	})

	ctx := context.Background()
	env := epa.EnvRef
	provider := epa.ProviderNumber1

	am, err := newConnectorAuthMethod()
	if err != nil {
		t.Fatalf("newConnectorAuthMethod: %v", err)
	}
	sf, err := am.SecurityFunctions(ctx)
	if err != nil {
		t.Fatalf("SecurityFunctions: %v", err)
	}

	// Fresh client for the initial handshake.
	client1, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		t.Fatalf("newEpaClient: %v", err)
	}
	defer client1.Close()

	session, err := client1.OpenSession()
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        gemidp.GetIdpByEnvironment(epa.IDPEnvironment(env)),
		SignerFunc: gemidp.SignWith(sf.AuthnSignFunc, sf.AuthnCertFunc),
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := session.Authorize(authenticator); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// Sanity: probe the live session before resumption.
	statusBefore, err := session.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus on original session: %v", err)
	}
	t.Logf("original session VAU-Status: %+v", statusBefore)

	// Snapshot. Counters should reflect at least the one GetStatus call we
	// just made (Authorize internally makes more — it's the multi-roundtrip
	// part of the flow).
	snap := session.VAUChannel.Snapshot()
	if snap.RequestCounter == 0 || snap.K2C2SAppDataCounter == 0 {
		t.Fatalf("snapshot counters should have advanced past 0 by now: %+v", snap)
	}
	t.Logf("snapshot at counters: request=%d iv=%d", snap.RequestCounter, snap.K2C2SAppDataCounter)

	// Drop the original session/client to simulate process exit. We keep
	// `sf` for the second leg only because nothing here needs it — restore
	// uses just the snapshot. Build an entirely fresh Client (new HTTP
	// transport, fresh cert pool path) and restore the channel into it.
	client1.Close()

	client2, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		t.Fatalf("newEpaClient (second): %v", err)
	}
	defer client2.Close()
	if client2.HttpClient == client1.HttpClient {
		t.Fatal("expected a fresh HTTP client for the restored session")
	}

	channel, err := vau.RestoreChannel(snap, client2.HttpClient)
	if err != nil {
		t.Fatalf("RestoreChannel: %v", err)
	}

	restored := &epa.Session{
		Client:     client2,
		VAUChannel: channel,
		OpenedAt:   session.OpenedAt,
	}

	statusAfter, err := restored.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus on restored session: %v (server didn't recognize the resumed channel)", err)
	}
	t.Logf("restored session VAU-Status: %+v", statusAfter)

	// Counters must have moved past the snapshot — that one GetStatus call
	// burned at least one request + IV counter slot.
	snap2 := channel.Snapshot()
	if snap2.RequestCounter <= snap.RequestCounter {
		t.Errorf("request counter did not advance: %d → %d", snap.RequestCounter, snap2.RequestCounter)
	}
	if snap2.K2C2SAppDataCounter <= snap.K2C2SAppDataCounter {
		t.Errorf("IV counter did not advance: %d → %d", snap.K2C2SAppDataCounter, snap2.K2C2SAppDataCounter)
	}
	t.Logf("after restored GetStatus: request=%d iv=%d", snap2.RequestCounter, snap2.K2C2SAppDataCounter)

	// And resume one more time, from the *updated* snapshot, into yet
	// another client. This proves the counter-persist loop survives an
	// arbitrary number of cycles.
	client3, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		t.Fatalf("newEpaClient (third): %v", err)
	}
	defer client3.Close()
	channel2, err := vau.RestoreChannel(snap2, client3.HttpClient)
	if err != nil {
		t.Fatalf("RestoreChannel from updated snapshot: %v", err)
	}
	again := &epa.Session{Client: client3, VAUChannel: channel2, OpenedAt: session.OpenedAt}
	if _, err := again.GetStatus(); err != nil {
		t.Fatalf("GetStatus on second resume: %v", err)
	}
}

// TestVAUResumeFromStaleSnapshotIsObservable documents what happens when a
// caller resumes from an OLD snapshot — i.e. one whose counters lag the
// server's state. The aggregator's behavior here is implementation-defined:
// some enforce monotonic request counters, some don't. We don't assert either
// outcome; this test just logs it so a humans reviewing CI output can spot
// regressions and so we have an explicit record of the behavior we're relying
// on (or not).
//
// AEAD nonce security is NOT at risk from counter rewinds: the IV is
// `4 random bytes || 8 counter bytes` (channel.go::Encrypt), so even with
// counter reuse the IV stays unique with overwhelming probability.
func TestVAUResumeFromStaleSnapshotIsObservable(t *testing.T) {
	konPath := os.Getenv("TI_TEST_KON_FILE")
	if konPath == "" {
		t.Skip("TI_TEST_KON_FILE not set; skipping stale-snapshot observation test")
	}

	prevConfig := connectorConfigFlag
	prevCard := authCardFlagVal
	connectorConfigFlag = konPath
	authCardFlagVal = ""
	t.Cleanup(func() {
		connectorConfigFlag = prevConfig
		authCardFlagVal = prevCard
	})

	ctx := context.Background()
	env := epa.EnvRef
	provider := epa.ProviderNumber2

	am, err := newConnectorAuthMethod()
	if err != nil {
		t.Fatalf("newConnectorAuthMethod: %v", err)
	}
	sf, err := am.SecurityFunctions(ctx)
	if err != nil {
		t.Fatalf("SecurityFunctions: %v", err)
	}

	client, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		t.Fatalf("newEpaClient: %v", err)
	}
	defer client.Close()
	session, err := client.OpenSession()
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        gemidp.GetIdpByEnvironment(epa.IDPEnvironment(env)),
		SignerFunc: gemidp.SignWith(sf.AuthnSignFunc, sf.AuthnCertFunc),
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := session.Authorize(authenticator); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	early := session.VAUChannel.Snapshot()
	for i := 0; i < 3; i++ {
		if _, err := session.GetStatus(); err != nil {
			t.Fatalf("GetStatus during burn loop: %v", err)
		}
	}

	client2, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		t.Fatalf("newEpaClient (rewind): %v", err)
	}
	defer client2.Close()
	channel, err := vau.RestoreChannel(early, client2.HttpClient)
	if err != nil {
		t.Fatalf("RestoreChannel: %v", err)
	}
	stale := &epa.Session{Client: client2, VAUChannel: channel, OpenedAt: session.OpenedAt}
	if _, err := stale.GetStatus(); err == nil {
		t.Logf("aggregator accepts a stale snapshot — counter monotonicity is NOT enforced for this provider/env")
	} else {
		t.Logf("aggregator rejects a stale snapshot — counter monotonicity IS enforced: %v", err)
	}
}

// _ keeps net/http and the auth package fully linked even if the test files
// above evolve. Cheap, no runtime impact.
var _ = http.DefaultClient
