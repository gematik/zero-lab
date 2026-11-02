module github.com/gematik/zero-lab/go/pdp

go 1.27.0

require (
	github.com/gematik/zero-lab/go/dpop v1.0.0-beta.1.0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/idpd v0.0.0-00010101000000-000000000000
	github.com/gematik/zero-lab/go/kv v0.0.3-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/nonce v0.21.1-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/oauth v0.51.1-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/oidf v0.50.3-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/pep v0.25.8-0.20261102185424-5ad95b53e1b3
	github.com/lestrrat-go/jwx/v3 v3.3.0
	golang.org/x/oauth2 v0.37.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/gematik/zero-lab/go/brainpool v1.2.1-0.20261102185424-5ad95b53e1b3 // indirect
	github.com/gematik/zero-lab/go/tipki v0.0.0-20261102185424-5ad95b53e1b3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.11.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

// In-repo modules resolve locally until this branch is pushed and `just sync` pins them.
replace (
	github.com/gematik/zero-lab/go/brainpool => ../brainpool
	github.com/gematik/zero-lab/go/dpop => ../dpop
	github.com/gematik/zero-lab/go/idpd => ../idpd
	github.com/gematik/zero-lab/go/kv => ../kv
	github.com/gematik/zero-lab/go/nonce => ../nonce
	github.com/gematik/zero-lab/go/oauth => ../oauth
	github.com/gematik/zero-lab/go/oidf => ../oidf
	github.com/gematik/zero-lab/go/pep => ../pep
	github.com/gematik/zero-lab/go/pep/proxy => ../pep/proxy
	github.com/gematik/zero-lab/go/pkcs12 => ../pkcs12
	github.com/gematik/zero-lab/go/tipki => ../tipki
	github.com/gematik/zero-lab/go/zaddy => ../zaddy
)
