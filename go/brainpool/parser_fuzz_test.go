package brainpool

import "testing"

// These fuzz targets assert that the hand-written DER parsers never panic on
// malformed input (they may return errors). Run e.g.:
//
//	go test -run x -fuzz FuzzParseCertificate -fuzztime 30s

func FuzzParseCertificate(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificate(data)
	})
}

func FuzzParseECPrivateKey(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseECPrivateKey(data)
	})
}

func FuzzParsePKCS8PrivateKey(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePKCS8PrivateKey(data)
	})
}
