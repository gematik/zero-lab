module github.com/gematik/zero-lab/spec/pkcs12/interop/go

go 1.27.0

require github.com/gematik/zero-lab/go/pkcs12 v0.0.0

require golang.org/x/crypto v0.59.0 // indirect

replace github.com/gematik/zero-lab/go/pkcs12 => ../../../../go/pkcs12
