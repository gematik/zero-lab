package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/vau"
	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/ti/state"
	"github.com/spf13/cobra"
)

// sessionOpenEntry records a successful VAU handshake and carries enough state
// to resume the channel in a later process. VAU is a CBOR/AEAD tunnel over
// plain HTTP POSTs — keys + counters are all that's needed to keep sending
// encrypted traffic; the live HTTP connection underneath is disposable.
//
// `ChannelSnapshot` is omitempty so older metadata-only entries written before
// resumption was wired still parse cleanly.
type sessionOpenEntry struct {
	Provider        epa.ProviderNumber   `json:"provider"`
	Env             epa.Env              `json:"env"`
	BaseURL         string               `json:"base_url"`
	OpenedAt        time.Time            `json:"opened_at"`
	ChannelSnapshot *vau.ChannelSnapshot `json:"channel_snapshot,omitempty"`
}

// sessionEntryTTL matches the upper bound of an authorized VAU session at the
// aggregator (~24h). Cached metadata stays trusted for that window; once
// expired, callers must reopen. The live channel itself is gone the moment
// the opening CLI process exits — only the metadata persists.
const sessionEntryTTL = 24 * time.Hour

func newEpaSessionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Inspect / close cached VAU session metadata",
		Long: "VAU channels hold live crypto state and cannot survive across CLI invocations.\n" +
			"Open a session with `ti epa connect`; this group only inspects and clears\n" +
			"the cached metadata about previous opens. Live sessions exist inside\n" +
			"`ti epa proxy`.",
	}
	cmd.AddCommand(newEpaSessionListCmd())
	cmd.AddCommand(newEpaSessionCloseCmd())
	return cmd
}

// obtainSession returns a cacheable session entry, preferring resumption from
// a cached snapshot. On cache miss or failed probe it falls through to a fresh
// handshake + authorize. The boolean tells the caller which path ran so the
// UX can say "resumed" vs "opened".
//
// Safety note on counter persistence: the VAU client constructs each AEAD nonce
// as `4 random bytes || 8 counter bytes` (vau/channel.go::Encrypt), so even if
// two CLI invocations race and the persisted counter is briefly reused, the
// random component prevents IV collisions with overwhelming probability. We
// still snapshot after every successful probe / open so the persisted state
// reflects the latest counter we've actually sent; the cache is monotonic
// from our side. Server-side counter enforcement varies by aggregator (see
// TestVAUResumeFromStaleSnapshotIsObservable).
func obtainSession(ctx context.Context, env epa.Env, provider epa.ProviderNumber, sf *epa.SecurityFunctions, st state.Store) (*sessionOpenEntry, bool, error) {
	if entry, ok := tryResumeSession(ctx, env, provider, sf, st); ok {
		return entry, true, nil
	}
	entry, err := openSessionFresh(ctx, env, provider, sf)
	if err != nil {
		return nil, false, err
	}
	return entry, false, nil
}

// tryResumeSession attempts to restore the channel from cache and verifies it
// with a quick GetStatus probe. Any failure returns ok=false so the caller
// falls back to a fresh open. The returned entry includes a fresh snapshot
// (counters advanced by the probe).
func tryResumeSession(ctx context.Context, env epa.Env, provider epa.ProviderNumber, sf *epa.SecurityFunctions, st state.Store) (*sessionOpenEntry, bool) {
	cached, hit, err := getJSON[sessionOpenEntry](st, vauKeysKey(env, provider))
	if err != nil || !hit || cached.ChannelSnapshot == nil {
		return nil, false
	}
	client, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		slog.Debug("resume: building client failed", "provider", provider, "err", err)
		return nil, false
	}
	defer client.Close()

	channel, err := vau.RestoreChannel(*cached.ChannelSnapshot, client.HttpClient)
	if err != nil {
		slog.Debug("resume: restoring channel failed, will reopen", "provider", provider, "err", err)
		return nil, false
	}
	session := &epa.Session{
		Client:     client,
		VAUChannel: channel,
		OpenedAt:   cached.OpenedAt,
	}
	if _, err := session.GetStatus(); err != nil {
		slog.Debug("resume: GetStatus probe failed, will reopen", "provider", provider, "err", err)
		return nil, false
	}

	// Counters have advanced; capture them for the next process.
	snap := channel.Snapshot()
	cached.ChannelSnapshot = &snap
	return &cached, true
}

// openSessionFresh runs the full handshake + IDP authorize and captures a
// snapshot of the resulting channel.
func openSessionFresh(ctx context.Context, env epa.Env, provider epa.ProviderNumber, sf *epa.SecurityFunctions) (*sessionOpenEntry, error) {
	client, err := newEpaClient(ctx, env, provider, sf)
	if err != nil {
		return nil, fmt.Errorf("building epa client: %w", err)
	}
	defer client.Close()

	session, err := client.OpenSession()
	if err != nil {
		return nil, err
	}

	// Authorize so the cached entry represents a session that's actually
	// usable for VAU-bound calls — matches what zero-epa's session manager
	// does after every open (session_manager.go:53). Build a fresh
	// gemidp.Authenticator from the same SecurityFunctions; same shape as
	// epa/proxy.go:193-196.
	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        gemidp.GetIdpByEnvironment(epa.IDPEnvironment(env)),
		SignerFunc: gemidp.SignWith(sf.AuthnSignFunc, sf.AuthnCertFunc),
	})
	if err != nil {
		return nil, fmt.Errorf("building IDP authenticator: %w", err)
	}
	if err := session.Authorize(authenticator); err != nil {
		return nil, fmt.Errorf("authorize: %w", err)
	}

	snap := session.VAUChannel.Snapshot()
	return &sessionOpenEntry{
		Provider:        provider,
		Env:             env,
		BaseURL:         session.BaseURL,
		OpenedAt:        session.OpenedAt,
		ChannelSnapshot: &snap,
	}, nil
}

func newEpaSessionListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List cached VAU session metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			env, _, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			st, err := loadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()
			var entries []sessionOpenEntry
			for _, p := range epa.AllProviders {
				e, hit, err := getJSON[sessionOpenEntry](st, vauKeysKey(env, p))
				if err != nil {
					return err
				}
				if hit {
					entries = append(entries, e)
				}
			}
			if outputFlag == "json" {
				return printJSON(entries)
			}
			if len(entries) == 0 {
				fmt.Printf("no cached sessions for %s\n", env)
				return nil
			}
			return printTable("PROVIDER\tENV\tBASE URL\tOPENED AT", func(w io.Writer) {
				for _, e := range entries {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", e.Provider, e.Env, e.BaseURL, e.OpenedAt.Format(time.RFC3339))
				}
			})
		},
	}
	addEpaEnvFlag(cmd)
	return cmd
}

func newEpaSessionCloseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "close [<provider>]",
		Short: "Drop cached session metadata for one provider, or all",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			env, _, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			st, err := loadCLIState()
			if err != nil {
				return err
			}
			defer st.Close()
			targets := epa.AllProviders
			if len(args) == 1 {
				p, err := parseProvider(args[0])
				if err != nil {
					return err
				}
				targets = []epa.ProviderNumber{p}
			}
			for _, p := range targets {
				if err := st.Delete(vauKeysKey(env, p)); err != nil {
					return err
				}
			}
			fmt.Printf("cleared %d cached session entries for %s\n", len(targets), env)
			return nil
		},
	}
	addEpaEnvFlag(cmd)
	return cmd
}

func parseProvider(s string) (epa.ProviderNumber, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("provider must be 1, 2, or 3 (got %q)", s)
	}
	if n < int(epa.ProviderNumber1) || n > int(epa.ProviderNumber3) {
		return 0, fmt.Errorf("provider must be 1, 2, or 3 (got %d)", n)
	}
	return epa.ProviderNumber(n), nil
}
