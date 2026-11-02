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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

func runJose(opts *options, args []string) error {
	if len(args) == 0 {
		return errors.New("jose needs a subcommand: generate-jwk, generate-jwks, public-jwk or public-jwks")
	}
	flags := newFlags("jose "+args[0], opts)
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if err := opts.prepare(); err != nil {
		return err
	}
	out := json.NewEncoder(os.Stdout)
	switch args[0] {
	case "generate-jwk":
		key, err := authzserver.GenerateRandomJwk()
		if err != nil {
			return err
		}
		return out.Encode(key)
	case "generate-jwks":
		num := 1
		if flags.NArg() > 0 {
			var err error
			if num, err = strconv.Atoi(strings.TrimSpace(flags.Arg(0))); err != nil {
				return fmt.Errorf("number of keys: %w", err)
			}
		}
		set, err := authzserver.GenerateJwkSet(num)
		if err != nil {
			return err
		}
		return out.Encode(set)
	case "public-jwk":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		key, err := oidc.ParseKey(data)
		if err != nil {
			return err
		}
		public, err := authzserver.PublicKey(key)
		if err != nil {
			return err
		}
		return out.Encode(public)
	case "public-jwks":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		set, err := oidc.ParseKeySet(data)
		if err != nil {
			return err
		}
		public, err := authzserver.PublicJwkSet(set)
		if err != nil {
			return err
		}
		return out.Encode(public)
	default:
		return fmt.Errorf("unknown jose subcommand %q", args[0])
	}
}

type issueResponse struct {
	TokenResponse *authzserver.TokenResponse `json:"token_response"`
	DpopKey       *jose.JSONWebKey           `json:"dpop_key"`
}

func runNonProd(opts *options, args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return errors.New("non-prod needs the subcommand issue")
	}
	flags := newFlags("non-prod issue", opts)
	var audience, scopes repeated
	var clientID string
	flags.Var(&audience, "aud", "audience of the access token, repeatable")
	flags.Var(&audience, "a", "audience of the access token, repeatable")
	flags.Var(&scopes, "scope", "scope of the access token, repeatable")
	flags.Var(&scopes, "s", "scope of the access token, repeatable")
	flags.StringVar(&clientID, "client_id", "", "client ID of the access token")
	flags.StringVar(&clientID, "c", "", "client ID of the access token")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if len(audience) == 0 || len(scopes) == 0 || clientID == "" {
		return errors.New("non-prod issue needs --aud, --scope and --client_id")
	}
	if err := opts.prepare(); err != nil {
		return err
	}
	server, err := createPdp(opts)
	if err != nil {
		return err
	}
	dpopKey, err := authzserver.GenerateRandomJwk()
	if err != nil {
		return err
	}
	thumbprint, err := authzserver.ThumbprintS256(dpopKey)
	if err != nil {
		return err
	}
	session := &authzserver.Session{
		AccessTokenDuration: 5 * time.Minute,
		ExpiresAt:           time.Now().Add(4 * time.Hour),
		ClientID:            clientID,
		Audience:            audience,
		Scopes:              scopes,
		DPoPThumbprint:      thumbprint,
	}
	if err := server.AuthzServer.NonProdStartSession(session); err != nil {
		return err
	}
	tokens, err := server.AuthzServer.NonProdIssueTokens(session.ID)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(issueResponse{TokenResponse: tokens, DpopKey: dpopKey})
}
