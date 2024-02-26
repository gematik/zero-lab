package reg

import (
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/util"
)

func WithOIDCClient(client *oidc.Client) RegistrationServiceOption {
	return func(s *RegistrationService) error {
		s.oidcClient = client
		return nil
	}
}

func (s *RegistrationService) AuthCodeURLOidc(nonce string) (string, error) {
	if s.oidcClient == nil {
		return "", fmt.Errorf("no OIDC client configured")
	}

	authSession := &AuthSessionEntity{
		Idp:          s.oidcClient.DiscoveryDocument().Issuer,
		State:        util.GenerateRandomString(32),
		Nonce:        nonce,
		CodeVerifier: oauth2.GenerateCodeVerifier(),
	}

	if err := s.store.UpsertAuthSession(authSession); err != nil {
		return "", fmt.Errorf("unable to create auth session: %w", err)
	}

	codeChallenge := oauth2.S256ChallengeFromVerifier(authSession.CodeVerifier)

	return s.oidcClient.AuthCodeURL(
		authSession.State,
		authSession.Nonce,
		codeChallenge,
		oauth2.CodeChallengeMethodS256,
	), nil

}

func (s *RegistrationService) AuthCallbackOidc(state, code string) (*ClientEntity, error) {
	authSession, err := s.store.PopAuthSession(state)
	if err != nil {
		return nil, fmt.Errorf("unable to find auth session: %w", err)
	}

	resp, err := s.oidcClient.Exchange(code, authSession.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code: %w", err)
	}

	slog.Info("auth callback", "token", util.JWSToText(resp.IDTokenRaw))

	account := &AccountEntity{
		Subject: resp.IDToken.Subject(),
		Issuer:  resp.IDToken.Issuer(),
	}

	registrationID, ok := resp.IDToken.PrivateClaims()["nonce"].(string)
	if !ok {
		return nil, fmt.Errorf("missing nonce claim")
	}

	registration, err := s.store.GetRegistration(registrationID)
	if err != nil {
		return nil, fmt.Errorf("unable to find registration: %w", err)
	}

	if err := s.store.UpsertAccount(account); err != nil {
		return nil, fmt.Errorf("unable to upsert account: %w", err)
	}

	// find oidc challenge
	var oidcChallenge *RegistrationChallengeEntity
	for _, c := range registration.Challenges {
		if c.Type == RegistrationChallengeTypeOIDC {
			oidcChallenge = c
			break
		}
	}
	if oidcChallenge == nil {
		return nil, fmt.Errorf("no OIDC challenge found")
	}
	oidcChallenge.Status = "valid"
	registration.Status = RegistrationStatusComplete

	client, err := s.assertChallengesAndRegister(registration)
	if err != nil {
		return nil, fmt.Errorf("unable to register client: %w", err)
	}

	return client, nil
}
