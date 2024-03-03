package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/pkg"
	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/gematik/zero-lab/pkg/nonce"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/gematik/zero-lab/pkg/reg"
	regapi "github.com/gematik/zero-lab/pkg/reg/api"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/gematik/zero-lab/pkg/zas"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var unattestedClientsCA ca.CertificateAuthority
var clientsCA ca.CertificateAuthority

func init() {
	var err error
	unattestedClientsIssuer := pkix.Name{
		OrganizationalUnit: []string{"Unattested Clients CA"},
	}
	unattestedClientsCA, err = ca.NewMockCA(unattestedClientsIssuer)
	if err != nil {
		log.Fatal(err)
	}

	clientsIssuer := pkix.Name{
		OrganizationalUnit: []string{"DMS-01 Clients CA"},
		Organization:       []string{"gematik GmbH"},
		Country:            []string{"DE"},
		Province:           []string{"Berlin"},
		Locality:           []string{"Berlin"},
	}

	clientsCA, err = ca.NewMockCA(clientsIssuer)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	godotenv.Load()

	root := echo.New()

	root.Use(middleware.Recover())

	bodyDump := middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
		slog.Info("request", "requestBody", string(reqBody), "responseBody", string(resBody))
	})

	root.Renderer = &Template{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}

	root.GET("/", getIndex)
	root.GET("/echo", getEcho)
	root.GET("/ca/ca-chain.pem", getUnattestedClientsCAChain)
	root.POST("/ca/issue-cert", issueCert, bodyDump)

	clientsPolicy, err := zas.LoadClientsPolicy("policy/clients-policy.yaml")
	if err != nil {
		log.Fatal(err)
	}
	zas, err := zas.NewServer(nil, clientsPolicy)
	if err != nil {
		log.Fatal(err)
	}
	zas.MountRoutes(root.Group("/as"))

	nonceService, err := nonce.NewHashicorpNonceService()
	if err != nil {
		log.Fatal(err)
	}

	store := reg.NewMockRegistrationStore()
	if err != nil {
		log.Fatal(err)
	}

	opts := []reg.RegistrationServiceOption{}

	if os.Getenv("OIDC_CLIENT_ID") != "" {
		config := &oidc.Config{
			Issuer:       os.Getenv("OIDC_ISSUER"),
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURI:  os.Getenv("OIDC_CALLBACK_URL"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"openid",
			},
		}
		oidcClient, err := oidc.NewClient(config)
		if err != nil {
			log.Fatal(err)
		}
		opts = append(opts, reg.WithOIDCClient(oidcClient))
		slog.Info("Using OIDC client (Test only)", "client_id", config.ClientID)
		zas.AddIdentityIssuers(oidcClient)
	}

	var regEntityStatementPath string
	if os.Getenv("RELYING_PARTY_CONFIG_PATH") != "" {
		regEntityStatementPath = os.Getenv("RELYING_PARTY_CONFIG_PATH")
	} else if _, err := os.Stat("relying-party-reg.yaml"); err == nil {
		regEntityStatementPath = "relying-party-reg.yaml"
	}

	if regEntityStatementPath != "" {
		rp, err := oidf.NewRelyingPartyFromConfigFile(regEntityStatementPath)
		if err != nil {
			log.Fatal(err)
		}
		opts = append(opts, reg.WithOIDFRelyingParty(rp))
		root.GET("/.well-known/openid-federation", echo.WrapHandler(http.HandlerFunc(rp.Serve)))

		oidfClient, err := NewOidfClient(rp, "https://idbroker.tk.ru2.nonprod-ehealth-id.de")
		if err != nil {
			log.Fatal(err)
		}

		root.GET("/reg/auth/gematik-fed", oidfClient.auth)
		root.GET("/reg/auth/gematik-fed/callback", oidfClient.callback)
		root.GET("/reg/auth/gematik-fed/handover-listener", oidfClient.handoverListener)
		root.GET("/reg/auth/gematik-fed/identity-providers", oidfClient.getIdentityProviders)
		//root.POST("/reg/auth/gematik-fed/device/code", oidfClient.deviceCode, dpop.VerifyDPoPHeader)
		//root.POST("/reg/auth/gematik-fed/device/token", oidfClient.deviceToken, dpop.VerifyDPoPHeader)
		root.GET("/handover-demo", oidfClient.getHandoverDemo)
		slog.Info("Using gematik OpenID Federation", "client_id", rp.ClientID())

	} else {
		slog.Warn("RELYING_PARTY_CONFIG_PATH not set, not serving /.well-known/openid-federation")
	}

	regService, err := reg.NewRegistrationService(nonceService, store, clientsCA, opts...)
	if err != nil {
		log.Fatal(err)
	}

	regapi, err := regapi.NewRegistrationAPI(regService)
	if err != nil {
		log.Fatal(err)
	}

	regGroup := root.Group("/reg")
	regapi.MountRoutes(regGroup)

	if wellKnownDir := os.Getenv("WELL_KNOWN_DIR"); wellKnownDir != "" {
		slog.Info("Serving static /.well-known", "dir", wellKnownDir)
		wk := root.Group("/.well-known")
		wk.Use(middleware.Logger())
		wk.Static("/", wellKnownDir)
	}

	// TODO: make this configurable
	root.Static("/static", "static")

	if os.Getenv("TLS_CERT_PATH") != "" {
		certPath := os.Getenv("TLS_CERT_PATH")
		if certPath == "" {
			log.Fatal("TLS_CERT_PATH not set")
		}
		keyPath := os.Getenv("TLS_KEY_PATH")
		if keyPath == "" {
			log.Fatal("TLS_KEY_PATH not set")
		}
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(unattestedClientsCA.IssuerCertificate())
		clientCAs.AddCert(clientsCA.IssuerCertificate())

		server := &http.Server{
			Addr:    util.GetEnv("SERVER_ADDR", ":8443"),
			Handler: root,
			TLSConfig: &tls.Config{
				PreferServerCipherSuites: true,
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.X25519,
				},
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256, // TLS 1.3
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // TLS 1.2
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				},
				ClientCAs:  clientCAs,
				ClientAuth: tls.VerifyClientCertIfGiven,
			},
		}
		slog.Info("Starting zero-zerobin", "addr", server.Addr, "version", pkg.Version)
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
	} else {
		addr := util.GetEnv("SERVER_ADDR", ":8080")
		slog.Info("Starting zero-zerobin", "addr", addr, "version", pkg.Version)
		log.Fatal(http.ListenAndServe(addr, root))
	}
}
