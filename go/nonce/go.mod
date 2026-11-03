module github.com/gematik/zero-lab/go/nonce

go 1.26.4

// In-repo modules resolve locally until this branch is pushed and `just sync` pins them.
replace (
	github.com/gematik/zero-lab/go/brainpool => ../brainpool
	github.com/gematik/zero-lab/go/dpop => ../dpop
	github.com/gematik/zero-lab/go/idpd => ../idpd
	github.com/gematik/zero-lab/go/kv => ../kv
	github.com/gematik/zero-lab/go/oidf => ../oidf
	github.com/gematik/zero-lab/go/openid => ../openid
	github.com/gematik/zero-lab/go/pdp => ../pdp
	github.com/gematik/zero-lab/go/pep => ../pep
	github.com/gematik/zero-lab/go/pep/proxy => ../pep/proxy
	github.com/gematik/zero-lab/go/pkcs12 => ../pkcs12
	github.com/gematik/zero-lab/go/tipki => ../tipki
	github.com/gematik/zero-lab/go/zaddy => ../zaddy
)
