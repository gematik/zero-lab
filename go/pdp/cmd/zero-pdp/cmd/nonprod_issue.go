package cmd

import (
	"encoding/json"
	"os"
	"time"

	"github.com/gematik/zero-lab/go/pdp/oauth2server"
	"github.com/spf13/cobra"
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue an access token",
	Run: func(cmd *cobra.Command, args []string) {

		scopes, err := cmd.Flags().GetStringArray("scope")
		cobra.CheckErr(err)

		pdp, err := createPdp()
		cobra.CheckErr(err)
		session := &oauth2server.AuthzServerSession{
			AccessTokenDuration: 5 * time.Minute,
			ExpiresAt:           time.Now().Add(4 * time.Hour),
			ClientID:            "client_id",
			Audience:            aud,
			Scopes:              scopes,
		}
		cobra.CheckErr(pdp.AuthzServer.NonProdStartSession(session))
		tokenResponse, err := pdp.AuthzServer.NonProdIssueTokens(session.ID)
		cobra.CheckErr(err)
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(tokenResponse))
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
