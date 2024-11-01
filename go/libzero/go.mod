module github.com/gematik/zero-lab/go/libzero

go 1.22.5

// needed to process brainpool curves in gemidp
// replace github.com/go-jose/go-jose/v4 => github.com/spilikin/go-jose-brainpool/v4 v4.0.3-0.20240723175330-b6b6406b4234

require (
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/go-playground/validator/v10 v10.22.0
	github.com/google/go-attestation v0.5.1
	github.com/gorilla/sessions v1.3.0
	github.com/hashicorp/go-secure-stdlib/nonceutil v0.1.0
	github.com/labstack/echo-contrib v0.17.1
	github.com/labstack/echo/v4 v4.12.0
	github.com/lestrrat-go/jwx/v2 v2.1.0
	github.com/matishsiao/goInfo v0.0.0-20210923090445-da2e3fa8d45f
	github.com/segmentio/ksuid v1.0.4
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/google/certificate-transparency-go v1.1.8 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tpm-tools v0.4.4 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/gorilla/context v1.1.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
