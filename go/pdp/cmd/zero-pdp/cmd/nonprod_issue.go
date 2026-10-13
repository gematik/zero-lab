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

package cmd

import (
	"encoding/json"
	"os"
	"time"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/spf13/cobra"
)

type issueCmdResponse struct {
	TokenResponse *authzserver.TokenResponse `json:"token_response"`
	DpopKey       jwk.Key                    `json:"dpop_key"`
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue an access token",
	Run: func(cmd *cobra.Command, args []string) {

		scopes, err := cmd.Flags().GetStringArray("scope")
		cobra.CheckErr(err)

		pdp, err := createPdp()
		cobra.CheckErr(err)

		dpopPrK, err := authzserver.GenerateRandomJwk()
		cobra.CheckErr(err)

		dpopThumbprit, err := authzserver.ThumbprintS256(dpopPrK)
		cobra.CheckErr(err)

		session := &authzserver.AuthzServerSession{
			AccessTokenDuration: 5 * time.Minute,
			ExpiresAt:           time.Now().Add(4 * time.Hour),
			ClientID:            "client_id",
			Audience:            aud,
			Scopes:              scopes,
			DPoPThumbprint:      dpopThumbprit,
		}
		cobra.CheckErr(pdp.AuthzServer.NonProdStartSession(session))
		tokenResponse, err := pdp.AuthzServer.NonProdIssueTokens(session.ID)
		cobra.CheckErr(err)
		response := issueCmdResponse{
			TokenResponse: tokenResponse,
			DpopKey:       dpopPrK,
		}
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(response))
	},
}

var aud []string
var scope []string
var clientId string
var sub string

func init() {
	issueCmd.Flags().StringArrayVarP(&aud, "aud", "a", []string{}, "Specify audience(s) for the access token")
	issueCmd.Flags().StringArrayVarP(&scope, "scope", "s", []string{}, "Specify scope(s) for the access token")
	issueCmd.Flags().StringVarP(&clientId, "client_id", "c", "", "Specify client ID for the access token")
	issueCmd.Flags().StringVarP(&sub, "sub", "u", "", "Specify subject for the access token")
	cobra.MarkFlagRequired(issueCmd.Flags(), "aud")
	cobra.MarkFlagRequired(issueCmd.Flags(), "scope")
	cobra.MarkFlagRequired(issueCmd.Flags(), "client_id")
	cobra.MarkFlagRequired(issueCmd.Flags(), "sub")
}
