package idp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/gematik/zero-lab/go/ti/internal/smcb"
	"github.com/spf13/cobra"
)

type authenticateFlags struct {
	yes bool
}

func (f *authenticateFlags) register(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&f.yes, "yes", "y", false, "sign without asking for consent on the terminal")
	smcb.AddFlags(cmd)
}

func newAuthenticateCmd() *cobra.Command {
	var flags authenticateFlags
	cmd := &cobra.Command{
		Use:   "authenticate URL",
		Short: "Sign an IDP-Dienst challenge with an SMC-B and return the redirect",
		Long: `Sign an IDP-Dienst challenge with an SMC-B and return the redirect.

URL is the authenticator:// deep link a client shows for the gematik
Authenticator app, or the plain IDP authorization URL inside it. The command
fetches the challenge, shows what the client asks for, signs it with the
SMC-B selected by the --auth-* flags and prints one JSON object on stdout:

  {"redirect_url":"https://client/callback?code=…&state=…","code":"…","state":"…",
   "idp":"https://idp-ref.app.ti-dienste.de","client_id":"…","scope":"…",
   "card_type":"SMC-B","consent":{"requested_scopes":{…},"requested_claims":{…}}}

The redirect is never followed and nothing is opened: delivering it to the
client is the caller's job. On failure the object is {"error":…,
"error_description":…} (plus the gematik error fields when the IDP sent
them), the message also goes to stderr, and the exit status is 1.

Consent is asked for on the terminal unless --yes is given; without a
terminal --yes is required.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true // the failure JSON and the stderr line are the report
			method, err := smcb.Build()
			if err != nil {
				return report(&failure{Code: "identity", Description: err.Error()})
			}
			res, err := authenticate(cmd.Context(), args[0], method, flags.yes, common.AskYesNo)
			if err != nil {
				return report(err)
			}
			return emit(os.Stdout, res)
		},
	}
	flags.register(cmd)
	return cmd
}

// result is the success object; consent is what the IDP said the client
// asks for, kept so the caller has a record of what the card attested to.
type result struct {
	RedirectURL string              `json:"redirect_url"`
	Code        string              `json:"code"`
	State       string              `json:"state"`
	IDP         string              `json:"idp"`
	ClientID    string              `json:"client_id"`
	Scope       string              `json:"scope"`
	CardType    string              `json:"card_type,omitempty"`
	Consent     *gemidp.UserConsent `json:"consent,omitempty"`
}

// failure is the error object, in the shape of an OAuth error response.
type failure struct {
	Code             string              `json:"error"`
	Description      string              `json:"error_description"`
	GematikErrorText string              `json:"gematik_error_text,omitempty"`
	GematikCode      string              `json:"gematik_code,omitempty"`
	GematikUUID      string              `json:"gematik_uuid,omitempty"`
	GematikTimestamp int64               `json:"gematik_timestamp,omitempty"`
	Consent          *gemidp.UserConsent `json:"consent,omitempty"`
}

func (f *failure) Error() string {
	if f.GematikCode != "" {
		return fmt.Sprintf("%s: %s (gematik_code %s, %s)", f.Code, f.Description, f.GematikCode, f.GematikUUID)
	}
	return f.Code + ": " + f.Description
}

// report prints the failure JSON on stdout and its message on stderr, and
// returns it so the command exits 1. Anything that is not a failure yet is
// wrapped as an IDP failure.
func report(err error) error {
	f, ok := err.(*failure)
	if !ok {
		f = &failure{Code: "idp", Description: err.Error()}
		var gerr *gemidp.Error
		if errors.As(err, &gerr) {
			f.Code, f.Description = gerr.ErrorCode, gerr.Error()
			f.GematikErrorText, f.GematikCode, f.GematikUUID, f.GematikTimestamp = gerr.GematikErrorText, gerr.GematikCode, gerr.GematikUUID, gerr.GematikTimestamp
		}
	}
	fmt.Fprintln(os.Stderr, f.Error())
	if err := emit(os.Stdout, f); err != nil {
		return err
	}
	return f
}

func emit(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

// authorization is what the input URL says about the request the card is
// asked to attest.
type authorization struct {
	URL      *url.URL
	IDP      string // scheme://host of the authorization endpoint
	Env      gemidp.Environment
	ClientID string
	Scope    string
	Redirect string
	CardType string
}

// authenticate runs the whole dance for one URL. ask is how consent is
// obtained when yes is false; it is injected so tests never touch a terminal.
func authenticate(ctx context.Context, raw string, method smcb.Method, yes bool, ask func(string) (bool, error)) (*result, error) {
	auth, err := parseAuthorizationURL(raw)
	if err != nil {
		return nil, &failure{Code: "invalid_url", Description: err.Error()}
	}
	if err := trustedIDP(auth); err != nil {
		return nil, &failure{Code: "untrusted_idp", Description: err.Error()}
	}

	id, err := method.Identity(ctx)
	if err != nil {
		return nil, &failure{Code: "identity", Description: err.Error()}
	}

	res := &result{IDP: auth.IDP, ClientID: auth.ClientID, Scope: auth.Scope, CardType: auth.CardType}
	signer := consentSigner(auth, id, yes, ask, gemidp.SignWith(id.Sign, id.Cert), &res.Consent)

	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Idp:        gemidp.NewIdp(auth.Env, auth.IDP),
		SignerFunc: signer,
		HTTPClient: common.NewHTTPClient(),
	})
	if err != nil {
		return nil, fmt.Errorf("IDP discovery: %w", err)
	}
	redirect, err := authenticator.Authenticate(auth.URL.String())
	if err != nil {
		var f *failure
		if errors.As(err, &f) {
			f.Consent = res.Consent
			return nil, f
		}
		return nil, err
	}
	res.RedirectURL, res.Code, res.State = redirect.String(), redirect.Code, redirect.State
	return res, nil
}

// consentSigner wraps the real signer with the consent step: it records the
// IDP's user_consent, shows the caller what is about to be attested, and asks
// unless yes is set.
func consentSigner(auth *authorization, id *smcb.Identity, yes bool, ask func(string) (bool, error), sign gemidp.ChallengeSignerFunc, consent **gemidp.UserConsent) gemidp.ChallengeSignerFunc {
	return func(ch gemidp.Challenge) (string, error) {
		uc := ch.UserConsent
		*consent = &uc
		printSummary(os.Stderr, auth, id, &uc)
		if !yes {
			ok, err := ask(fmt.Sprintf("Sign with %s? [y/N] ", subjectOf(id)))
			if errors.Is(err, common.ErrNoTerminal) {
				return "", &failure{Code: "consent_required", Description: "no terminal to ask for consent; pass --yes"}
			}
			if err != nil {
				return "", &failure{Code: "consent_required", Description: err.Error()}
			}
			if !ok {
				return "", &failure{Code: "consent_declined", Description: "signing declined"}
			}
		}
		return sign(ch)
	}
}

func printSummary(w io.Writer, auth *authorization, id *smcb.Identity, uc *gemidp.UserConsent) {
	fmt.Fprintf(w, "IDP        %s\n", auth.URL.Host)
	fmt.Fprintf(w, "Client     %s → %s\n", auth.ClientID, redirectHost(auth.Redirect))
	fmt.Fprintf(w, "Scope      %s\n", auth.Scope)
	if tid := id.TelematikID(); tid != "" {
		fmt.Fprintf(w, "Identity   %s (Telematik-ID %s)\n", subjectOf(id), tid)
	} else {
		fmt.Fprintf(w, "Identity   %s\n", subjectOf(id))
	}
	for _, k := range sortedKeys(uc.RequestedScopes) {
		fmt.Fprintf(w, "  scope  %-24s %s\n", k, uc.RequestedScopes[k])
	}
	for _, k := range sortedKeys(uc.RequestedClaims) {
		fmt.Fprintf(w, "  claim  %-24s %s\n", k, uc.RequestedClaims[k])
	}
}

func subjectOf(id *smcb.Identity) string {
	if cert := id.Certificate(); cert != nil {
		return cert.Subject.CommonName
	}
	return id.Source
}

func redirectHost(redirect string) string {
	if u, err := url.Parse(redirect); err == nil && u.Host != "" {
		return u.Host
	}
	return redirect
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseAuthorizationURL accepts the authenticator:// deep link or the plain
// authorization URL. cardType and callback are parameters for the
// Authenticator app, not for the IDP, so they are stripped; the card is
// whatever the caller configured, so cardType is only reported.
func parseAuthorizationURL(raw string) (*authorization, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	var cardType string
	if u.Scheme == "authenticator" {
		path := u.Query().Get("challenge_path")
		if path == "" {
			return nil, errors.New("authenticator:// link carries no challenge_path")
		}
		if u, err = url.Parse(path); err != nil {
			return nil, fmt.Errorf("challenge_path: %w", err)
		}
		q := u.Query()
		cardType = q.Get("cardType")
		q.Del("cardType")
		q.Del("callback")
		u.RawQuery = q.Encode()
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("authorization URL must be https, got %q", raw)
	}
	q := u.Query()
	if q.Get("client_id") == "" || q.Get("redirect_uri") == "" {
		return nil, errors.New("authorization URL carries no client_id/redirect_uri")
	}
	return &authorization{
		URL:      u,
		IDP:      u.Scheme + "://" + u.Host,
		ClientID: q.Get("client_id"),
		Scope:    q.Get("scope"),
		Redirect: q.Get("redirect_uri"),
		CardType: cardType,
	}, nil
}

// idpHosts names the IDP-Dienst instances a challenge may come from: the
// internet-facing hosts gemidp knows and the splitdns hosts the TI network
// uses. A challenge from any other host is never signed — the card would be
// attesting to whoever put the URL together.
var idpHosts = func() map[string]gemidp.Environment {
	hosts := map[string]gemidp.Environment{
		"idp.app.ti-dienste.de":      gemidp.EnvironmentProduction,
		"idp-ref.app.ti-dienste.de":  gemidp.EnvironmentReference,
		"idp-test.app.ti-dienste.de": gemidp.EnvironmentTest,
	}
	for _, def := range common.EnvDefs {
		if u, err := url.Parse(def.IDP); err == nil && u.Host != "" {
			env := gemidp.EnvironmentReference
			if def.Env == "prod" {
				env = gemidp.EnvironmentProduction
			}
			hosts[u.Host] = env
		}
	}
	return hosts
}()

func trustedIDP(auth *authorization) error {
	env, ok := idpHosts[auth.URL.Hostname()]
	if !ok {
		return fmt.Errorf("%s is not a known IDP-Dienst host", auth.URL.Hostname())
	}
	auth.Env = env
	return nil
}
