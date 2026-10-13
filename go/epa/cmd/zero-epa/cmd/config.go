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
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

func init() {
	rootCmd.AddCommand(configCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print the loaded configuration",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Config file: %s\n", viper.GetString("config_file"))
		config, err := epa.LoadConfigFile(viper.GetString("config_file"))
		if err != nil {
			slog.Error(fmt.Sprintf("load config file %q", viper.GetString("config_file")), "error", err)
			return
		}
		fmt.Printf("Base dir: %s\n", config.BaseDir)
		yaml.NewEncoder(cmd.OutOrStdout()).Encode(config)
	},
}
