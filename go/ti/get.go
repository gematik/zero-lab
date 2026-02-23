package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/spf13/cobra"
)

var outputFlag string

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get resources from the Konnektor",
	}

	cmd.AddCommand(newGetInfoCmd())
	cmd.AddCommand(newGetServicesCmd())
	cmd.AddCommand(newGetCardsCmd())
	cmd.AddCommand(newGetCertificatesCmd())
	cmd.AddCommand(newGetStatusCmd())
	cmd.AddCommand(newGetIdentitiesCmd())
	cmd.AddCommand(newGetExpirationCmd())

	return cmd
}

func loadClient(config *kon.Dotkon) (*kon.Client, error) {
	return kon.NewClient(config)
}

func loadServices(config *kon.Dotkon) (*kon.ConnectorServices, error) {
	httpClient, baseURL, err := kon.NewHTTPClient(config)
	if err != nil {
		return nil, err
	}
	services, err := kon.LoadConnectorServices(context.Background(), httpClient, baseURL)
	if err != nil {
		return nil, err
	}
	if config.RewriteServiceEndpoints {
		services.RewriteEndpoints(baseURL)
	}
	return services, nil
}

func indentXML(data []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var buf bytes.Buffer
	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ")

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if err := encoder.EncodeToken(token); err != nil {
			return "", err
		}
	}
	if err := encoder.Flush(); err != nil {
		return "", err
	}
	buf.WriteByte('\n')
	return buf.String(), nil
}
