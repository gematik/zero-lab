package epa_test

import (
	"log/slog"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/libzero/prettylog"
)

func TestConnect(t *testing.T) {
	logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
	slog.SetDefault(logger)

	client, err := epa.Connect(epa.EnvDev, epa.ProviderNumber2, epa.WithInsecureSkipVerify())
	if err != nil {
		t.Fatalf("Connect returned an error: %v", err)
	}
	t.Logf("Client: %v", client)

	nonce, err := client.GetNonce()
	if err != nil {
		t.Errorf("GetNonce returned an error: %v", err)
	}
	t.Logf("Nonce: %v", nonce)

	authz_uri, err := client.SendAuthorizationRequestSC()
	if err != nil {
		t.Errorf("SendAuthorizationRequestSC returned an error: %v", err)
	}
	t.Logf("Authorization URI: %v", authz_uri)

	exsists, err := client.GetRecordStatus("X110611629")
	if err != nil {
		t.Errorf("GetRecordStatus returned an error: %v", err)
	}
	t.Logf("Record exists: %v", exsists)

}
