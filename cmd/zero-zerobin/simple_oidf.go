package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

type authSession struct {
	idpUrl        string
	nonce         string
	state         string
	codeVerifier  string
	clientId      string
	deviceCode    string
	tokenResponse *oauth2.TokenResponse
}

type simpleOidfClient struct {
	rp           *oidf.RelyingParty
	authSessions map[string]*authSession
}

type HandoverMessageType string

const (
	HandoverErrorMessageType = "HandoverError"
	HandoverAuthMessageType  = "HandoverAuth"
	HandoverTokenMessageType = "HandoverToken"
)

type HandoverErrorMessage struct {
	Error string `json:"error"`
}

type HandoverAuthMessage struct {
	AuthURL string `json:"auth_url"`
}

type HandoverTokenMessage struct {
	TokenResponse *oauth2.TokenResponse `json:"token_response"`
}

func NewOidfClient(rp *oidf.RelyingParty, idpUrl string) (*simpleOidfClient, error) {
	return &simpleOidfClient{
		rp:           rp,
		authSessions: make(map[string]*authSession),
	}, nil
}

func (o *simpleOidfClient) auth(c echo.Context) error {
	iss := c.Request().URL.Query().Get("iss")
	if iss == "" {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no iss provided"))
	}

	session := &authSession{
		idpUrl:       iss,
		nonce:        util.GenerateRandomString(32),
		state:        util.GenerateRandomString(32),
		codeVerifier: oauth2.GenerateCodeVerifier(),
	}
	o.authSessions[session.state] = session
	client, err := o.rp.NewClient(session.idpUrl)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Error creating client: %s", err))
	}
	authUrl, err := client.AuthCodeURL(session.state, session.nonce, session.codeVerifier)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Error pushing authorization request: %s", err))
	}

	slog.Info("authUrl", "authUrl", authUrl)

	return c.Redirect(http.StatusFound, authUrl)
}

func (o *simpleOidfClient) callback(c echo.Context) error {
	code := c.Request().URL.Query().Get("code")
	if code == "" {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no code provided"))
	}
	state := c.Request().URL.Query().Get("state")
	if state == "" {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no state provided"))
	}

	session, ok := o.authSessions[state]
	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no session found for state"))
	}
	client, err := o.rp.NewClient(session.idpUrl)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error creating client: %w", err))
	}
	tokenResp, err := client.Exchange(code, session.codeVerifier)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error exchanging code for token: %w", err))
	}

	session.tokenResponse = tokenResp

	return c.Render(http.StatusOK, "callback-success.html", nil)
}

func (o *simpleOidfClient) handoverListener(c echo.Context) error {
	iss := c.Request().URL.Query().Get("iss")
	if iss == "" {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no iss provided"))
	}

	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 10240,
	}
	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	slog.Info("upgraded to web socket")

	sessionState := util.GenerateRandomString(32)
	session := &authSession{
		idpUrl:       iss,
		nonce:        util.GenerateRandomString(32),
		state:        sessionState,
		codeVerifier: oauth2.GenerateCodeVerifier(),
	}
	o.authSessions[session.state] = session
	client, err := o.rp.NewClient(session.idpUrl)
	if err != nil {
		slog.Error("error creating client", "error", err)
		sendMessage(conn, HandoverErrorMessageType, HandoverErrorMessage{Error: fmt.Sprintf("Error creating client: %s", err)})
		return err
	}
	authUrl, err := client.AuthCodeURL(session.state, session.nonce, session.codeVerifier)
	if err != nil {
		slog.Error("error pushing authorization request", "error", err)
		sendMessage(conn, HandoverErrorMessageType, HandoverErrorMessage{Error: fmt.Sprintf("Error pushing authorization request: %s", err)})
		return err
	}

	authMessage := HandoverAuthMessage{
		AuthURL: authUrl,
	}

	err = sendMessage(conn, HandoverAuthMessageType, authMessage)
	if err != nil {
		slog.Error("error sending auth message", "error", err)
		return err
	}

	for {
		time.Sleep(200 * time.Millisecond)
		updatedSession, ok := o.authSessions[sessionState]
		if !ok {
			slog.Error("session not found", "sessionState", sessionState)
		}
		if updatedSession.tokenResponse != nil {
			slog.Info("token response", "tokenResponse", updatedSession.tokenResponse)
			err := sendMessage(conn, HandoverTokenMessageType, HandoverTokenMessage{TokenResponse: updatedSession.tokenResponse})
			if err != nil {
				slog.Error("error sending token message", "error", err)
			}
			break
		}
	}

	return nil
}

func sendMessage(conn *websocket.Conn, messageType HandoverMessageType, message interface{}) error {
	payload := struct {
		Type    HandoverMessageType `json:"type"`
		Payload interface{}         `json:"payload"`
	}{
		Type:    messageType,
		Payload: message,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

type IdentityProviderOutput struct {
	Issuer  string `json:"iss"`
	Title   string `json:"title"`
	LogoURI string `json:"logo_uri"`
}

func (o *simpleOidfClient) getIdentityProviders(c echo.Context) error {
	idps := []IdentityProviderOutput{
		{
			Issuer:  "https://idbroker.tk.ru2.nonprod-ehealth-id.de",
			Title:   "Techniker Krankenkasse",
			LogoURI: "https://idbroker.tk.ru2.nonprod-ehealth-id.de/logo.png",
		},
	}
	/*
		allIdps, err := o.rp.Federation().ListIdpUrls()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("Error fetching idp list: %s", err))
		}

		for _, idp := range allIdps {
			if idp.Issuer == "https://idbroker.tk.ru2.nonprod-ehealth-id.de" {
				continue
			}
			idps = append(idps, IdentityProviderOutput{
				Issuer: idp.Issuer,
				Title:  idp.Issuer,
			})
		}
	*/

	return c.JSON(http.StatusOK, idps)
}

func (o *simpleOidfClient) getHandoverDemo(c echo.Context) error {
	return c.Render(http.StatusOK, "handover-demo.html", nil)
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (o *simpleOidfClient) deviceCode(c echo.Context) error {

	iss := c.Request().FormValue("iss")
	if iss == "" {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no iss provided"))
	}

	clientId := c.Request().FormValue("client_id")
	if clientId == "" {
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("no client_id provided"))
	}

	deviceCode := util.GenerateRandomString(32)

	sessionState := util.GenerateRandomString(32)
	session := &authSession{
		idpUrl:       iss,
		nonce:        util.GenerateRandomString(32),
		state:        sessionState,
		deviceCode:   deviceCode,
		clientId:     clientId,
		codeVerifier: oauth2.GenerateCodeVerifier(),
	}
	o.authSessions[session.state] = session
	client, err := o.rp.NewClient(session.idpUrl)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error creating client: %s", err))
	}

	authUrl, err := client.AuthCodeURL(session.state, session.nonce, session.codeVerifier)
	if err != nil {
		slog.Error("error pushing authorization request", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf("error pushing authorization request: %s", err))
	}

	output := DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                "not used",
		VerificationURI:         authUrl,
		VerificationURIComplete: authUrl,
		ExpiresIn:               300,
		Interval:                1,
	}
	return c.JSON(http.StatusOK, output)
}

type DeviceAccessTokenRequest struct {
	GrantType  string `json:"grant_type" validate:"required,oneof=urn:ietf:params:oauth:grant-type:device_code"`
	DeviceCode string `form:"device_code" validate:"required"`
	ClientId   string `form:"client_id" validate:"required"`
}

type DeviceAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	TmpIDToken  string `json:"tmp_id_token"`
}

type DeviceAccessTokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (o *simpleOidfClient) deviceToken(c echo.Context) error {
	var deviceAccessTokenRequest DeviceAccessTokenRequest
	err := c.Bind(&deviceAccessTokenRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Errorf("Error parsing request: %w", err))
	}

	// TODO: validate request
	deviceCode := c.Request().FormValue("device_code")

	// find session by device code
	var session *authSession
	for _, s := range o.authSessions {
		if s.deviceCode == deviceCode {
			session = s
			break
		}
	}
	if session == nil {
		return echo.NewHTTPError(http.StatusBadRequest, DeviceAccessTokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid device code",
		})
	}

	// TODO: create proper access token
	if session.tokenResponse != nil {
		return c.JSON(http.StatusOK, DeviceAccessTokenResponse{
			AccessToken: "not implemented",
			TokenType:   "Bearer",
			ExpiresIn:   session.tokenResponse.ExpiresIn,
			TmpIDToken:  session.tokenResponse.IDToken,
		})
	}

	return echo.NewHTTPError(http.StatusBadRequest, DeviceAccessTokenErrorResponse{
		Error:            "authorization_pending",
		ErrorDescription: "The authorization request is still pending",
	})

}
