package epa_test

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"html/template"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/libzero/prettylog"
)

//go:embed templates/getFoldersAndContents.xml
var getFoldersAndContentsTmplStr string
var getFoldersAndContentsTmpl = template.Must(template.New("getFoldersAndContents.xml").Parse(getFoldersAndContentsTmplStr))

//go:embed templates/findFolders.xml
var findFoldersTmplStr string
var findFoldersTmpl = template.Must(template.New("findFolders.xml").Parse(findFoldersTmplStr))

func TestXDS(t *testing.T) {

	var body bytes.Buffer
	if err := findFoldersTmpl.Execute(&body, struct {
		InsurantID string
	}{
		InsurantID: "X110611629",
	}); err != nil {
		t.Fatalf("Error executing template: %v", err)
	}
	url := "http://localhost:8082/insurants/X110611629/vau/epa/xds-document/api/I_Document_Management_Insurant"
	req, _ := http.NewRequest("POST", url, &body)
	req.Header.Set("Content-Type", "application/xml")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// read body from response to string
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	t.Logf("Response: %s", buf.String())

}

func reservedTestXDS(t *testing.T) {

	for _, testRecord := range testRecords {
		t.Run(testRecord.insurantId, func(t *testing.T) {
			providerNumber := testRecord.providerNumber
			//insurantId := testRecord.insurantId

			testKey, _ := brainpool.ParsePrivateKeyPEM(testKeyBytes)
			testCert, _ := brainpool.ParseCertificatePEM(testCertBytes)

			logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
			slog.SetDefault(logger)

			session, err := epa.OpenSession(
				epa.EnvDev,
				providerNumber,
				epa.SecurityFunctions{
					AuthnSignFunc:            brainpool.SignFuncPrivateKey(testKey),
					AuthnCertFunc:            func() (*x509.Certificate, error) { return testCert, nil },
					ClientAssertionSignFunc:  brainpool.SignFuncPrivateKey(testKey),
					ClientAssertionCertFunc:  func() (*x509.Certificate, error) { return testCert, nil },
					ProofOfAuditEvidenceFunc: EnvProofOfAuditEvidenceFunc,
				},
				epa.WithInsecureSkipVerify(),
			)
			if err != nil {
				t.Fatalf("Connect returned an error: %v", err)
			}

			err = session.Authorize()
			if err != nil {
				t.Fatalf("Authorize returned an error: %v", err)
			}

		})
	}
}
