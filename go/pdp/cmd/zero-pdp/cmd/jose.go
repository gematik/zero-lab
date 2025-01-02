package cmd

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gematik/zero-lab/go/oauth/jwkutil"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
		randomJwk, err := jwkutil.GenerateRandomJwk()
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
		jwks, err := jwkutil.GenerateJwkSet(num)
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
	Short: "Reads the JWK Set from stdin and prints the public JWK Set to stdout",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := io.ReadAll(os.Stdin)
		cobra.CheckErr(err)
		set, err := jwk.Parse(data)
		cobra.CheckErr(err)
		publicSet, err := jwkutil.PublicJwkSet(set)
		println(set, publicSet)
		cobra.CheckErr(err)
		cobra.CheckErr(json.NewEncoder(os.Stdout).Encode(publicSet))
	},
}
