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
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(joseCmd)
	joseCmd.AddCommand(joseGenerateJwkCmd)
	joseCmd.AddCommand(joseGenerateJwkSetCmd)
	joseCmd.AddCommand(josePublicJwkCmd)
	joseCmd.AddCommand(josePublicJwkSetCmd)
}

var joseCmd = &cobra.Command{
	Use:   "jose",
	Short: "Various JOSE utilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var joseGenerateJwkCmd = &cobra.Command{
	Use:   "generate-jwk",
	Short: "Generate a JWK",
	Run: func(cmd *cobra.Command, args []string) {
		randomJwk, err := authzserver.GenerateRandomJwk()
		cobra.CheckErr(err)
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(randomJwk))
	},
}

var joseGenerateJwkSetCmd = &cobra.Command{
	Use:   "generate-jwks [number of keys]",
	Short: "Generate a JWK Set",
	Run: func(cmd *cobra.Command, args []string) {
		num := 1
		if len(args) > 0 {
			var err error
			num, err = strconv.Atoi(strings.TrimSpace(args[0]))
			cobra.CheckErr(err)
		}
		jwks, err := authzserver.GenerateJwkSet(num)
		cobra.CheckErr(err)
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(jwks))
	},
}

var josePublicJwkCmd = &cobra.Command{
	Use:   "public-jwk",
	Short: "Reads the JWK from stdin and prints the public JWK to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := io.ReadAll(os.Stdin)
		cobra.CheckErr(err)
		key, err := jwk.ParseKey(data)
		cobra.CheckErr(err)
		publicKey, err := key.PublicKey()
		cobra.CheckErr(err)
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(publicKey))
	},
}

var josePublicJwkSetCmd = &cobra.Command{
	Use:   "public-jwks",
	Short: "Reads the a single JWK or JWK Set from stdin and prints the public JWK Set to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := io.ReadAll(os.Stdin)
		cobra.CheckErr(err)
		set, err := jwk.Parse(data)
		cobra.CheckErr(err)
		publicSet, err := authzserver.PublicJwkSet(set)
		cobra.CheckErr(err)
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(publicSet))
	},
}
