module github.com/gematik/zero-lab/rust/jwz-brainpool/interop/go

go 1.26.4

require github.com/gematik/zero-lab/go/brainpool v0.0.0

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)

replace github.com/gematik/zero-lab/go/brainpool => ../../../../go/brainpool
