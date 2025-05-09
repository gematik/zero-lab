package cmd

import (
	"encoding/json"
	"os"
	"time"

	"github.com/gematik/zero-lab/go/pdp/oauth2server"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
)

type issueCmdResponse struct {
	TokenResponse *oauth2server.TokenResponse `json:"token_response"`
	DpopKey       jwk.Key                     `json:"dpop_key"`
}

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue an access token",
	Run: func(cmd *cobra.Command, args []string) {

		scopes, err := cmd.Flags().GetStringArray("scope")
		cobra.CheckErr(err)

		pdp, err := createPdp()
		cobra.CheckErr(err)

		dpopPrK, err := oauth2server.GenerateRandomJwk()
		cobra.CheckErr(err)

		dpopThumbprit, err := oauth2server.ThumbprintS256(dpopPrK)
		cobra.CheckErr(err)

		session := &oauth2server.AuthzServerSession{
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
