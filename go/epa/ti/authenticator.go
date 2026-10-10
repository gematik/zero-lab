package ti

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Authenticator runs `ti idpd authenticate`: the IDP-Dienst's Authenticator-Modul flow
// with an identity, from the authorization URL the Aktensystem made to the code.
type Authenticator struct {
	Runner Runner
	Source IdentitySource
	// Env names the TI environment whose IDP-Dienst to use (prod, ref, test; dev as
	// ref), or IdpURL another IDP by base URL.
	Env    string
	IdpURL string
}

// CodeRedirect is what the IDP sent the user back with.
type CodeRedirect struct {
	Code  string
	State string
	URL   string
}

// Authenticate turns authURL into an authorization code. The IDP's refusal comes back
// as an [*Error] of kind `idpd_error` whose message carries its `gematik_error_text`.
func (a *Authenticator) Authenticate(ctx context.Context, authURL string) (*CodeRedirect, error) {
	args, err := a.Source.Args()
	if err != nil {
		return nil, err
	}
	args = append([]string{"idpd", "authenticate", "--auth-url", authURL}, args...)
	switch {
	case a.IdpURL != "":
		args = append(args, "--idp-url", a.IdpURL)
	case a.Env != "":
		args = append(args, "--env", a.Env)
	default:
		return nil, fmt.Errorf("authenticator: Env or IdpURL is required")
	}
	out, err := a.Runner.Run(ctx, nil, args...)
	if err != nil {
		return nil, fmt.Errorf("IDP-Dienst with %s: %w", a.Source, err)
	}
	var report struct {
		Code        string   `json:"code"`
		State       *string  `json:"state"`
		RedirectURL string   `json:"redirect_url"`
		Warnings    []string `json:"warnings"`
		Idp         struct {
			Issuer string `json:"issuer"`
		} `json:"idp"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("idpd authenticate: %w", err)
	}
	for _, warning := range report.Warnings {
		slog.Warn("IDP-Dienst", "issuer", report.Idp.Issuer, "warning", warning)
	}
	redirect := &CodeRedirect{Code: report.Code, URL: report.RedirectURL}
	if report.State != nil {
		redirect.State = *report.State
	}
	return redirect, nil
}
