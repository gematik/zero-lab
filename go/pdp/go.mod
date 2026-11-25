module github.com/gematik/zero-lab/go/pdp

go 1.27.0

require (
	github.com/gematik/zero-lab/go/dpop v1.0.0-beta.4
	github.com/gematik/zero-lab/go/egress v0.0.0-20261122165346-56c6c247e654
	github.com/gematik/zero-lab/go/idpd v0.3.1-0.20261122165346-56c6c247e654
	github.com/gematik/zero-lab/go/kv v0.7.0
	github.com/gematik/zero-lab/go/nonce v0.24.0
	github.com/gematik/zero-lab/go/oidf v0.54.3-0.20261122165346-56c6c247e654
	github.com/gematik/zero-lab/go/oidftest v0.0.0-20261122165346-56c6c247e654
	github.com/gematik/zero-lab/go/openid v0.55.1
	github.com/go-jose/go-jose/v4 v4.1.9
	go.yaml.in/yaml/v4 v4.0.0
)

require (
	github.com/gematik/zero-lab/go/brainpool v1.4.1 // indirect
	github.com/gematik/zero-lab/go/tipki v0.33.1-0.20261122165346-56c6c247e654 // indirect
	golang.org/x/crypto v0.59.0 // indirect
)

replace github.com/gematik/zero-lab/go/kv/postgres => ../kv/postgres
