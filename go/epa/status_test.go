package epa

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/epa/vau"
)

func TestProxyStatusJSONShape(t *testing.T) {
	status := ProxyStatus{
		Name:            "1",
		Env:             EnvDev,
		Subject:         "Adler ApothekeTEST-ONLY",
		TelematikID:     "3-SMC-B-Testkarte--883110000153440",
		InsurantsCached: 2,
		Providers: []ProviderVAUStatus{
			{
				Number:          1,
				BaseURL:         "https://epa-as-1.dev.epa4all.de",
				SessionOpenedAt: "2026-07-07T10:00:00Z",
				VAU: &vau.Status{
					VAUType:            "epa",
					VAUVersion:         "v-4.31.617 Release",
					UserAuthentication: "TID:3-SMC-B-Testkarte--883110000153440",
					KeyID:              "9cbdf210",
					ConnectionStart:    "2026-07-07T09:00:00Z",
				},
			},
			{Number: 2, Error: "open session at provider 2: dial tcp: timeout"},
		},
	}

	data, err := json.Marshal(&status)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)

	for _, key := range []string{
		`"name"`, `"env"`, `"subject"`, `"telematikId"`, `"insurantsCached"`,
		`"providers"`, `"number"`, `"baseURL"`, `"sessionOpenedAt"`,
		`"vau"`, `"VAU-Version"`, `"User-Authentication"`, `"Connection-Start"`,
		`"error"`,
	} {
		if !strings.Contains(body, key) {
			t.Errorf("marshaled ProxyStatus missing key %s: %s", key, body)
		}
	}
	if strings.Contains(body, `"identityError"`) {
		t.Errorf("identityError should be omitted when empty: %s", body)
	}
}
