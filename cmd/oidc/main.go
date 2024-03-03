package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
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
	params.Set("client_id", "zero-test2")
	params.Set("redirect_uri", "http://127.0.0.1:8089/as-callback")
	params.Set("op_issuer", "https://accounts.google.com")
	params.Set("op_intermediary_redirect_uri", "http://127.0.0.1:8089/op-callback")
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
	root.GET("/op-callback", func(c echo.Context) error {
		slog.Info("callback", "queryString", c.QueryString())

		// client without redirects
		httpClient := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		callbackUrl := "http://localhost:8080/as/op-callback?" + c.QueryString()
		resp, err := httpClient.Get(callbackUrl)

		go func() {
			time.Sleep(3 * time.Second)
			root.Shutdown(context.Background())
		}()

		if err != nil {
			return echo.NewHTTPError(500, err)
		}

		return c.String(200, fmt.Sprintf("callback: %s", util.ResponseToText(resp)))
	})

	root.GET("/as-callback", func(c echo.Context) error {
		go func() {
			time.Sleep(1 * time.Second)
			root.Shutdown(context.Background())
		}()
		if errorCode := c.QueryParam("error"); errorCode != "" {
			return c.String(http.StatusOK, fmt.Sprintf("Error: %s, Details: %s", errorCode, c.QueryParam("error_description")))
		}
		return c.String(http.StatusOK, "OK")
	})

	root.Start(":8089")
}
