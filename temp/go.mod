module github.com/gematik/zero-lab

go 1.22.4

require (
	github.com/cloudflare/circl v1.3.9
	github.com/fxamacker/cbor/v2 v2.6.0
	github.com/go-jose/go-jose/v4 v4.0.1
	github.com/go-playground/validator/v10 v10.19.0
	github.com/google/go-attestation v0.5.1
	github.com/gorilla/sessions v1.2.2
	github.com/gorilla/websocket v1.5.3
	github.com/hashicorp/go-secure-stdlib/nonceutil v0.1.0
	github.com/joho/godotenv v1.5.1
	github.com/labstack/echo-contrib v0.17.1
	github.com/labstack/echo/v4 v4.12.0
	github.com/lestrrat-go/jwx/v2 v2.0.21
	github.com/matishsiao/goInfo v0.0.0-20210923090445-da2e3fa8d45f
	github.com/segmentio/ksuid v1.0.4
	github.com/spf13/cobra v1.8.0
	github.com/spilikin/go-brainpool v0.0.0-20240412075109-c5a9e2e50b53
	golang.org/x/crypto v0.22.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/google/certificate-transparency-go v1.1.8 // indirect
	github.com/google/go-tpm v0.9.0 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/gorilla/context v1.1.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
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
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sys v0.19.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
)

//replace github.com/go-jose/go-jose/v4 => ../go-jose-brainpool
replace github.com/go-jose/go-jose/v4 v4.0.1 => github.com/spilikin/go-jose-brainpool/v4 v4.0.2
