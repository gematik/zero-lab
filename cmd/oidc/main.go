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
	"github.com/goccy/go-json"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
)

var clientId = "zero-test-software"

var opIssuer = "https://accounts.google.com"

//var opIssuer = "https://idbroker.tk.ru2.nonprod-ehealth-id.de"

// var authBaseUrl = "http://127.0.0.1:8080/auth?"
var asUrl = "https://dms-01.zt.dev.ccs.gematik.solutions"

func main() {
	godotenv.Load()

	verifier := oauth2.GenerateCodeVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	state := oauth2.GenerateCodeVerifier()
	nonce := oauth2.GenerateCodeVerifier()

	params := url.Values{}
	params.Set("client_id", clientId)
	params.Set("redirect_uri", "http://127.0.0.1:8089/as-callback")
	params.Set("op_issuer", opIssuer)
	params.Set("op_intermediary_redirect_uri", "http://127.0.0.1:8089/op-intermediary-callback")
	params.Set("response_type", "code")
	params.Set("scope", "register:client")
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("state", state)
	params.Set("nonce", nonce)
	authURL := fmt.Sprintf("%s/auth?%s", asUrl, params.Encode())

	go func() {
		time.Sleep(15 * time.Microsecond)
		slog.Info("Opening browser", "url", authURL)
		util.OpenBrowser(authURL)
	}()

	root := echo.New()
	srv := http.Server{}
	srv.Addr = ":8089"
	srv.Handler = root

	root.GET("/op-intermediary-callback", func(c echo.Context) error {
		slog.Info("OP callback", "queryString", c.QueryString())

		// TODO: get this URL from AS metadata
		callbackUrl := fmt.Sprintf("%s/op-callback?%s", asUrl, c.QueryString())
		_, err := http.Get(callbackUrl)

		if err != nil {
			return echo.NewHTTPError(500, err)
		}

		return c.String(http.StatusOK, "OP callback successful, continue on command line")
	})

	root.GET("/as-callback", func(c echo.Context) error {
		slog.Info("AS callback", "queryString", c.QueryString())
		go func() {
			time.Sleep(1 * time.Second)
			srv.Shutdown(context.Background())
		}()
		if errorCode := c.QueryParam("error"); errorCode != "" {
			return c.String(http.StatusOK, fmt.Sprintf("Error: %s, Details: %s", errorCode, c.QueryParam("error_description")))
		}

		code := c.QueryParam("code")
		stateFromAS := c.QueryParam("state")

		if stateFromAS != state {
			return c.String(http.StatusOK, "State mismatch")
		}

		params := url.Values{}
		params.Set("grant_type", "authorization_code")
		params.Set("client_id", "zero-test-software")
		params.Set("code", code)
		params.Set("code_verifier", verifier)
		params.Set("redirect_uri", "http://127.0.0.1:8089/as-callback")

		resp, err := http.PostForm(fmt.Sprintf("%s/token", asUrl), params)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error: %s", err))
		}

		var tokenResp oauth2.TokenResponse
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Error: %s", err))
		}

		slog.Info("Token response", "response", tokenResp, "accessToken", tokenResp.AccessToken)

		fmt.Println(tokenResp.AccessToken)

		return c.String(http.StatusOK, util.ResponseToText(resp))
	})

	slog.Info("Starting server", "address", ":8089")
	srv.ListenAndServe()
}
