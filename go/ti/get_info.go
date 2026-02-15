package main

import (
	"fmt"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

func newGetInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show Konnektor product information",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			config, err := loadDotkon()
			if err != nil {
				return err
			}
			return runGetInfo(config)
		},
	}
}

func credentialsType(config *kon.Dotkon) string {
	switch config.Credentials.(type) {
	case kon.CredentialsConfigBasic:
		return "basic"
	case kon.CredentialsConfigPKCS12:
		return "pkcs12"
	default:
		return "unknown"
	}
}

func runGetInfo(config *kon.Dotkon) error {
	services, err := loadServices(config)
	if err != nil {
		return err
	}

	if outputFlag == "json" {
		return printJSON(services.ProductInformation)
	}

	pi := services.ProductInformation
	return printKeyValue(func(w io.Writer) {
		fmt.Fprintf(w, "URL\t%s\n", config.URL)
		fmt.Fprintf(w, "Mandant\t%s\n", config.MandantId)
		fmt.Fprintf(w, "Workplace\t%s\n", config.WorkplaceId)
		fmt.Fprintf(w, "Client System\t%s\n", config.ClientSystemId)
		fmt.Fprintf(w, "Credentials\t%s\n", credentialsType(config))
		if config.Env != "" {
			fmt.Fprintf(w, "Environment\t%s\n", config.Env)
		}
fmt.Fprintf(w, "\t\n")
		fmt.Fprintf(w, "Product Type\t%s\n", pi.ProductTypeInformation.ProductType)
		fmt.Fprintf(w, "Product Type Version\t%s\n", pi.ProductTypeInformation.ProductTypeVersion)
		fmt.Fprintf(w, "Vendor\t%s\n", pi.ProductIdentification.ProductVendorID)
		fmt.Fprintf(w, "Product Code\t%s\n", pi.ProductIdentification.ProductCode)
		fmt.Fprintf(w, "Hardware Version\t%s\n", pi.ProductIdentification.ProductVersion.Local.HWVersion)
		fmt.Fprintf(w, "Firmware Version\t%s\n", pi.ProductIdentification.ProductVersion.Local.FWVersion)
	})
}
