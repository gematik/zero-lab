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
	"strings"

	"github.com/gematik/zero-lab/pkg"
	"github.com/gematik/zero-lab/pkg/attestation/tpmattest"
	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/gematik/zero-lab/pkg/nonce"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/reg"
	regapi "github.com/gematik/zero-lab/pkg/reg/api"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/gematik/zero-lab/pkg/zas"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var unregisteredClientsCA ca.CertificateAuthority
var clientsCA ca.CertificateAuthority

func init() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	var err error
	unattestedClientsIssuer := pkix.Name{
		OrganizationalUnit: []string{"Unregistered Clients CA"},
	}
	unregisteredClientsCA, err = ca.NewMockCA(unattestedClientsIssuer)
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

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		// Optionally, you could return the error to give each route more control over the status code
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	return nil
}

func main() {
	godotenv.Load()

	root := echo.New()
	root.Validator = &CustomValidator{validator: validator.New()}

	root.Use(middleware.Recover())

	bodyDump := middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
		slog.Info("request", "requestBody", string(reqBody), "responseBody", string(resBody))
	})

	root.Renderer = &Template{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}

	// ------------------
	tpmAttestor := tpmattest.NewTPMAttestor()
	root.POST("/tpm/activations", tpmAttestor.NewActivationSession)
	// ------------------

	root.GET("/", getIndex)
	root.GET("/echo", getEcho)
	root.GET("/ca/ca-chain.pem", getUnattestedClientsCAChain)
	root.POST("/ca/issue-cert", issueCert, bodyDump)

	clientsPolicy, err := zas.LoadClientsPolicy(util.GetEnv("CLIENTS_POLICY_PATH", "policy/clients-policy.yaml"))
	if err != nil {
		log.Fatal(err)
	}

	zasOptions := []zas.Option{
		zas.WithMockSessionStore(),
		zas.WithClientsPolicy(clientsPolicy),
		zas.WithSigningKeyFromJWK(os.Getenv("SIGNING_KEY_PATH"), true),
	}

	nonceService, err := nonce.NewHashicorpNonceService()
	if err != nil {
		log.Fatal(err)
	}

	store := reg.NewMockRegistrationStore()
	if err != nil {
		log.Fatal(err)
	}

	regOptions := []reg.RegistrationServiceOption{}

	if os.Getenv("OIDC_CLIENT_ID") != "" {
		config := &oidc.Config{
			Issuer:       os.Getenv("OIDC_ISSUER"),
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURI:  os.Getenv("OIDC_CALLBACK_URL"),
			Scopes:       strings.Split(os.Getenv("OIDC_SCOPE"), " "),
			Name:         os.Getenv("OIDC_NAME"),
			LogoURI:      os.Getenv("OIDC_LOGO_URI"),
		}
		oidcClient, err := oidc.NewClient(config)
		if err != nil {
			log.Fatal(err)
		}
		regOptions = append(regOptions, reg.WithOIDCClient(oidcClient))
		zasOptions = append(zasOptions, zas.WithOpenidProvider(oidcClient))
	}

	zasOptions = append(zasOptions, zas.WithOIDFRelyingPartyFromConfigFile(
		util.GetEnv("RELYING_PARTY_CONFIG_PATH", "relying-party-reg.yaml"),
		zas.UseMockIfNotAvailable,
	))

	zas, err := zas.NewServer(zasOptions...)
	if err != nil {
		log.Fatal(err)
	}
	zas.MountRoutes(root.Group(""))

	regService, err := reg.NewRegistrationService(nonceService, store, clientsCA, regOptions...)
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
		clientCAs.AddCert(unregisteredClientsCA.IssuerCertificate())
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
