package epa_test

import (
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestRetry(t *testing.T) {
	retres := 1
	fqdn := "epa-as-1.dev.epa4all.de"
	// resolve DNS name to IP
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		t.Fatal(err)
	}
	slog.Info("Resolved", "fqdn", fqdn, "ips", ips)
	for i := 0; i < retres; i++ {
		// resolve DNS name to IP
		ips, err := net.LookupIP(fqdn)
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) == 0 {
			t.Fatal("no IP addresses found")
		}
		fmt.Printf("%2d seconds: resolved %s to %s\n", i, fqdn, ips[0])
		time.Sleep(1 * time.Second)
	}
}
