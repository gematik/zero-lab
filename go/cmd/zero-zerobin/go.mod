module github.com/gematik/zero-lab/go/cmd/zero-zerobin

go 1.22.5

require (
	github.com/gematik/zero-lab/go/authzserver v0.0.0-00010101000000-000000000000
	github.com/gematik/zero-lab/go/libzero v0.0.0-20240807173054-3f3a299ba164
	github.com/go-playground/validator/v10 v10.22.0
	github.com/joho/godotenv v1.5.1
	github.com/labstack/echo/v4 v4.12.0
)

replace github.com/gematik/zero-lab/go/authzserver => ../../authzserver

replace github.com/gematik/zero-lab/go/libzero => ../../libzero

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gematik/zero-lab v0.0.0-20240429121620-438f3cf7af8f // indirect
	github.com/go-jose/go-jose/v4 v4.0.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/google/certificate-transparency-go v1.1.8 // indirect
	github.com/google/go-attestation v0.5.1 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/gorilla/context v1.1.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/gorilla/sessions v1.3.0 // indirect
	github.com/hashicorp/go-secure-stdlib/nonceutil v0.1.0 // indirect
	github.com/labstack/echo-contrib v0.17.1 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/jwx/v2 v2.1.0 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/spilikin/go-brainpool v0.0.0-20240412075109-c5a9e2e50b53 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
