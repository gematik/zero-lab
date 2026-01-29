package main

import (
	"fmt"
	"syscall/js"

	"github.com/gematik/zero-lab/go/brainpool/v2"
)

var parseCertificate = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return "Invalid number of arguments"
	}

	certData := args[0].String()

	// Call the function from the 'brainpool' package
	cert, err := brainpool.ParseCertificatePEM([]byte(certData))
	if err != nil {
		return fmt.Sprintf("Certificate parsing failed: %v", err)
	}
	return cert.Subject.CommonName
})

func main() {
	fmt.Println("Go WebAssembly Initialized")

	// 1. Bind our Go function to the JavaScript global scope (window)
	js.Global().Set("parseCertificate", parseCertificate)

	// 2. Prevent the Go program from exiting
	// The empty select{} blocks forever, keeping the Wasm memory alive.
	select {}
}
