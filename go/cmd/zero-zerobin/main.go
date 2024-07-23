package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/libzero"
	"github.com/gematik/zero-lab/go/libzero/attestation/tpmattest"
	"github.com/gematik/zero-lab/go/libzero/ca"
	"github.com/gematik/zero-lab/go/libzero/dpop"
	"github.com/gematik/zero-lab/go/libzero/nonce"
	"github.com/gematik/zero-lab/go/libzero/oauth2server"
	"github.com/gematik/zero-lab/go/libzero/oauth2server/webclient"
	"github.com/gematik/zero-lab/go/libzero/prettylog"
	"github.com/gematik/zero-lab/go/libzero/util"
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
	if os.Getenv("PRETTY_LOGS") != "false" {
		logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
		slog.SetDefault(logger)
	}

	godotenv.Load()

	root := echo.New()
	root.Validator = &CustomValidator{validator: validator.New()}

	root.Use(middleware.Recover())

	bodyDump := middleware.BodyDump(func(c echo.Context, reqBody, resBody []byte) {
		slog.Info("request", "requestBody", string(reqBody), "responseBody", string(resBody))
	})

	nonceService, err := nonce.NewHashicorpNonceService()
	if err != nil {
		log.Fatal(err)
	}

	newReplayNonce := func(c echo.Context) error {
		nonce, err := nonceService.Get()
		if err != nil {
			slog.Error("Unable to get nonce", "error", err)
			return echo.NewHTTPError(500, "Unable to get nonce")
		}
		c.Response().Header().Set("Replay-Nonce", nonce)
		c.Response().WriteHeader(http.StatusCreated)
		return nil
	}

	// ------------------ TPM Activation Service
	tpmActivationService, err := tpmattest.NewActivationService()
	if err != nil {
		slog.Error("Failed to create TPM activation service", "error", err)
		os.Exit(1)
	}
	tpmattest.MountActivationRoutes(root.Group("/tpm"), tpmActivationService)
	// ------------------

	root.GET("/", getIndex)
	root.GET("/echo", getEcho)
	root.GET("/ca/ca-chain.pem", getUnattestedClientsCAChain)
	root.POST("/ca/issue-cert", issueCert, bodyDump)
	root.GET("/nonce", newReplayNonce)
	root.HEAD("/nonce", newReplayNonce)

	// DPoP
	dpopGroup := root.Group("/dpop")
	dpopMiddleware, err := dpop.NewMiddleware()
	if err != nil {
		log.Fatal(err)
	}
	dpopGroup.Use(dpopMiddleware.VerifyDPoPHeader)
	dpopGroup.GET("/echo", getEcho)
	dpopGroup.POST("/token", dpopAccessToken)

	// DPoP with nonce
	dpopNonceGroup := root.Group("/dpop-nonce")
	dpopNonceMiddleware, err := dpop.NewMiddleware(dpop.WithNonceService(nonceService))
	if err != nil {
		log.Fatal(err)
	}
	dpopNonceGroup.Use(dpopNonceMiddleware.VerifyDPoPHeader)
	dpopNonceGroup.GET("/echo", getEcho)
	dpopNonceGroup.POST("/token", dpopAccessToken)

	as, err := oauth2server.NewFromConfigFile(util.GetEnv("AUTHZ_SERVER_CONFIG_PATH", "config/authz-server.yaml"))
	if err != nil {
		log.Fatal(err)
	}
	as.MountRoutes(root.Group(""))

	webClient, err := webclient.NewFromServerMetadata(as.Metadata)
	if err != nil {
		log.Fatal(err)
	}

	webClient.MountRoutes(root.Group("/web"))

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
		slog.Info("Starting zero-zerobin", "addr", server.Addr, "version", libzero.Version)
		log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
	} else {
		addr := util.GetEnv("SERVER_ADDR", ":8080")
		slog.Info("Starting zero-zerobin", "addr", addr, "version", libzero.Version)
		log.Fatal(http.ListenAndServe(addr, root))
	}
}

/*
	regOptions := []reg.RegistrationServiceOption{}

	nonceService, err := nonce.NewHashicorpNonceService()
	if err != nil {
		log.Fatal(err)
	}

	store := reg.NewMockRegistrationStore()
	if err != nil {
		log.Fatal(err)
	}

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

*/
