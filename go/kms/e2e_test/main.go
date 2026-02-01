//go:build e2e

package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/kms/rise"
)

func main() {
	url := os.Getenv("KMS_URL")
	if url == "" {
		log.Fatal("KMS_URL environment variable not set")
	}

	username := os.Getenv("KMS_USERNAME")
	if username == "" {
		log.Fatal("KMS_USERNAME environment variable not set")
	}

	password := os.Getenv("KMS_PASSWORD")
	if password == "" {
		log.Fatal("KMS_PASSWORD environment variable not set")
	}

	// Create a custom HTTP client that skips TLS verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	r := rise.New(
		rise.WithURL(url),
		rise.WithUsername(username),
		rise.WithPassword(password),
		rise.WithHTTPClient(client),
	)
	if r == nil {
		log.Fatal("Failed to create KMS instance")
	}

	err := r.Login(url, username, password)
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	log.Println("Login successful")

	infomodel, err := r.GetInfomodel()
	if err != nil {
		log.Fatalf("GetInfomodel failed: %v", err)
	}

	log.Printf("Infomodel: %+v\n", infomodel)
}
