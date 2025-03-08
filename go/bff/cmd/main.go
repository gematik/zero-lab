package main

import (
	"embed"
	"encoding/base64"
	"log"
	"net/http"
	"text/template"

	"github.com/gematik/zero-lab/go/bff"
)

var (
	//go:embed *.html
	templatesFS embed.FS
)

func main() {

	templateFrontend := template.Must(template.ParseFS(templatesFS, "test_frontend.html"))

	randomSignKey := bff.GenerateRandomKey(256)

	randomEncryptKey := bff.GenerateRandomKey(256)

	b, err := bff.New(bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:      "http://127.0.0.1:8011",
			ClientID:    "public-client",
			RedirectURI: "http://127.0.0.1:8080/bff/as-callback",
		},
		EncryptKeyString:    base64.StdEncoding.EncodeToString(randomEncryptKey),
		SignKeyString:       base64.StdEncoding.EncodeToString(randomSignKey),
		CookieName:          "ZETA-BFF-SID",
		FrontendRedirectURI: "http://127.0.0.1:8080/",
	})
	if err != nil {
		log.Fatalf("Failed to create middleware: %v", err)
	}

	mux := http.NewServeMux()
	b.Mount(mux)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		templateFrontend.Execute(w, nil)
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}
