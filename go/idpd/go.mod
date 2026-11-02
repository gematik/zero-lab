module github.com/gematik/zero-lab/go/idpd

go 1.27.0

require (
	github.com/gematik/zero-lab/go/brainpool v1.2.1-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/oauth v0.51.1-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/pkcs12 v0.100.1-0.20261102185424-5ad95b53e1b3
	github.com/gematik/zero-lab/go/tipki v0.0.0-20261102185424-5ad95b53e1b3
	github.com/go-jose/go-jose/v4 v4.1.6
)

require golang.org/x/crypto v0.58.0 // indirect

// In-repo modules resolve locally until this branch is pushed and `just sync` pins them.
replace (
	github.com/gematik/zero-lab/go/brainpool => ../brainpool
	github.com/gematik/zero-lab/go/dpop => ../dpop
	github.com/gematik/zero-lab/go/kv => ../kv
	github.com/gematik/zero-lab/go/nonce => ../nonce
	github.com/gematik/zero-lab/go/oauth => ../oauth
	github.com/gematik/zero-lab/go/oidf => ../oidf
	github.com/gematik/zero-lab/go/pdp => ../pdp
	github.com/gematik/zero-lab/go/pep => ../pep
	github.com/gematik/zero-lab/go/pep/proxy => ../pep/proxy
	github.com/gematik/zero-lab/go/pkcs12 => ../pkcs12
	github.com/gematik/zero-lab/go/tipki => ../tipki
	github.com/gematik/zero-lab/go/zaddy => ../zaddy
)
