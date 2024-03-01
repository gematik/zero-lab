package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

func main() {
	godotenv.Load()

	verifier := oauth2.GenerateCodeVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	state := oauth2.GenerateCodeVerifier()
	nonce := oauth2.GenerateCodeVerifier()

	params := url.Values{}
	params.Set("client_id", "zero-test")
	params.Set("issuer", "https://accounts.google.com")
	params.Set("redirect_uri", "http://127.0.0.1:8089/auth-callback")
	params.Set("response_type", "code")
	params.Set("scope", "register:client")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)
	params.Set("nonce", nonce)
	authURL := "http://localhost:8080/as/auth?" + params.Encode()

	go func() {
		time.Sleep(15 * time.Microsecond)
		fmt.Println(authURL)
		util.OpenBrowser(authURL)
	}()

	root := echo.New()
	root.GET("/auth-callback", func(c echo.Context) error {
		go func() {
			time.Sleep(25 * time.Microsecond)
			root.Shutdown(context.Background())
		}()

		code := c.QueryParam("code")
		state := c.QueryParam("state")

		return c.String(200, fmt.Sprintf("code: %s, state: %s", code, state))
	})

	root.Start(":8089")
}
