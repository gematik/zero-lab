package zasweb

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/zas"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/segmentio/ksuid"
)

var (
	//go:embed *.html
	templatesFS embed.FS
)

func New() *Client {
	return &Client{
		ClientID:    "zero-web",
		RedirectURI: "http://127.0.0.1:8080/web/login/callback",
		Scopes:      []string{"zero-web"},
		Metadata: Metadata{
			AuthorizationEndpoint: "http://127.0.0.1:8080/auth",
			TokenEndpoint:         "http://127.0.0.1:8080/token",
		},
		authzSessionStore:         oauth2.NewMockAuthzClientSessionStore(),
		templateError:             template.Must(template.ParseFS(templatesFS, "error.html", "layout.html")),
		templateAuthenticatorWait: template.Must(template.ParseFS(templatesFS, "authenticator_wait.html", "layout.html")),
		templateUserInfo:          template.Must(template.ParseFS(templatesFS, "userinfo.html", "layout.html")),
		templateLogin:             template.Must(template.ParseFS(templatesFS, "login.html", "layout.html")),
	}
}

type Metadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}
type Client struct {
	ClientID                  string
	RedirectURI               string
	Scopes                    []string
	Metadata                  Metadata
	authzSessionStore         oauth2.AuthzClientSessionStore
	templateError             *template.Template
	templateAuthenticatorWait *template.Template
	templateUserInfo          *template.Template
	templateLogin             *template.Template
}

func (cl *Client) MountRoutes(g *echo.Group) {
	g.Use(
		zas.ErrorLogMiddleware,
		// TODO: make secret configurable
		session.Middleware(sessions.NewCookieStore([]byte("secret"))),
	)
	g.GET("/error", cl.showError)
	g.GET("/login", cl.login)
	g.GET("/login/start", cl.loginStart)
	g.GET("/login/authenticator", cl.authenticatorWait)
	g.GET("/login/callback", cl.loginCallback)
	g.POST("/login/poll", cl.loginPoll)
	protected := g.Group("/protected")
	protected.GET("/userinfo", cl.userInfo)
}

func (cl *Client) AuthCodeURL(state, nonce, verifier string, opts ...oauth2.ParameterOption) (string, error) {
	params := url.Values{
		"client_id":             {cl.ClientID},
		"redirect_uri":          {cl.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(cl.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"},
	}

	for _, opt := range opts {
		opt(params)
	}

	url := fmt.Sprintf("%s?%s", cl.Metadata.AuthorizationEndpoint, params.Encode())

	return url, nil
}

func (cl *Client) Exchange(code, verifier string, opts ...oauth2.ParameterOption) (*oauth2.TokenResponse, error) {
	params := url.Values{}
	params.Set("client_id", cl.ClientID)
	params.Set("code", code)
	params.Set("redirect_uri", cl.RedirectURI)
	params.Set("grant_type", "authorization_code")
	params.Set("code_verifier", verifier)

	for _, opt := range opts {
		opt(params)
	}

	slog.Debug("Exchanging code for token", "url", cl.Metadata.TokenEndpoint, "params", params)

	resp, err := http.PostForm(cl.Metadata.TokenEndpoint, params)
	if err != nil {
		return nil, fmt.Errorf("unable to exchange code for token: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oidcErr oauth2.Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil {
			return nil, fmt.Errorf("unable to decode error: %w", err)
		}
		slog.Error("unable to exchange code for token", "error", oidcErr)
		return nil, &oidcErr
	}

	var tokenResponse oauth2.TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("unable to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

func redirectWithError(c echo.Context, err *oauth2.Error) error {

	slog.Error("Redirecting with error", "error", err)
	return c.Redirect(http.StatusFound, fmt.Sprintf("/web/error?error=%s&error_description=%s", err.Code, err.Description))
}

func (cl *Client) showError(c echo.Context) error {
	return cl.templateError.Execute(c.Response().Writer, map[string]interface{}{
		"error": oauth2.Error{
			Code:        c.QueryParam("error"),
			Description: c.QueryParam("error_description"),
		},
	})
}
func (cl *Client) login(c echo.Context) error {
	subUrl := fmt.Sprintf("%s://%s/openid-providers", c.Scheme(), c.Request().Host)
	resp, err := http.Get(subUrl)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get openid providers",
		})
	}
	defer resp.Body.Close()

	var openidProviders []zas.OpenidProviderInfo
	err = json.NewDecoder(resp.Body).Decode(&openidProviders)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to parse openid providers",
		})
	}

	return cl.templateLogin.Execute(c.Response().Writer, map[string]interface{}{
		"openidProviders": openidProviders,
	})
}

func (cl *Client) loginStart(c echo.Context) error {
	issuer := c.QueryParam("op_issuer")
	if issuer == "" {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "missing op_issuer parameter",
		})
	}

	authzSession := oauth2.AuthzClientSession{
		ID:       ksuid.New().String(),
		OPIssuer: issuer,
		State:    ksuid.New().String(),
		Nonce:    ksuid.New().String(),
		Verifier: oauth2.GenerateCodeVerifier(),
	}

	var err error
	authzSession.AuthURL, err = cl.AuthCodeURL(
		authzSession.State,
		authzSession.Nonce,
		authzSession.Verifier,
		oauth2.WithOpenidProviderIssuer(issuer),
	)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to generate auth URL",
		})
	}

	slog.Info("Starting authn session", "session", c.Request().RequestURI)

	err = cl.authzSessionStore.SaveAuthzClientSession(&authzSession)
	if err != nil {
		return err
	}

	httpSession, err := session.Get("session", c)
	if err != nil {
		// redirect to error page
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get session",
		})
	}
	httpSession.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}
	httpSession.Values["authz_session_id"] = authzSession.ID
	httpSession.Values["auth_url"] = authzSession.AuthURL
	httpSession.Save(c.Request(), c.Response())

	if c.QueryParam("type") == "gemidp" {
		return c.Redirect(http.StatusFound, "/web/login/authenticator")
	} else {
		return c.Redirect(http.StatusFound, authzSession.AuthURL)
	}
}

func (cl *Client) loginCallback(c echo.Context) error {
	if c.QueryParam("error") != "" {
		return redirectWithError(c, &oauth2.Error{
			Code:        c.QueryParam("error"),
			Description: c.QueryParam("error_description"),
		})
	}
	httpSession, err := session.Get("session", c)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get session",
		})
	}

	state := c.QueryParam("state")
	if state == "" {
		return redirectWithError(c, &oauth2.Error{
			Code:        "invalid_request",
			Description: "missing state parameter",
		})
	}

	authzSession, err := cl.authzSessionStore.GetAuthzClientSessionByState(state)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "invalid_request",
			Description: "session not found",
		})
	}

	code := c.QueryParam("code")
	if code == "" {
		return redirectWithError(c, &oauth2.Error{
			Code:        "invalid_request",
			Description: "missing code parameter",
		})
	}

	tokenResponse, err := cl.Exchange(code, authzSession.Verifier)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to exchange code for token",
		})
	}

	authzSession.TokenResponse = tokenResponse
	err = cl.authzSessionStore.SaveAuthzClientSession(authzSession)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to save authz session",
		})
	}

	claimBytes, err := parseClaims(tokenResponse)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to parse claims",
		})
	}

	if !httpSession.IsNew {
		httpSession.Values["claims"] = string(claimBytes)
		httpSession.Save(c.Request(), c.Response())
	} else {
		// no session found, respond with OK
		return c.String(http.StatusOK, "OK")
	}

	return c.Redirect(http.StatusFound, "/web/protected/userinfo")
}

func parseClaims(tokenResponse *oauth2.TokenResponse) ([]byte, error) {
	parts := strings.Split(tokenResponse.AccessToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid access token format")
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("unable to decode claims: %w", err)
	}

	return claimBytes, nil
}

func (cl *Client) authenticatorWait(c echo.Context) error {
	httpSession, err := session.Get("session", c)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get session",
		})
	}

	return cl.templateAuthenticatorWait.Execute(c.Response().Writer, map[string]interface{}{
		"authURL": httpSession.Values["auth_url"],
	})
}

func (cl *Client) loginPoll(c echo.Context) error {
	httpSession, err := session.Get("session", c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, &oauth2.Error{
			Code:        "invalid_request",
			Description: "failed to get session",
		})
	}

	authzSessionID, ok := httpSession.Values["authz_session_id"]
	if !ok {
		return c.JSON(http.StatusBadRequest, &oauth2.Error{
			Code:        "invalid_request",
			Description: "failed to get authz session ID",
		})
	}

	authzSession, err := cl.authzSessionStore.GetAuthzClientSessionByID(authzSessionID.(string))
	if err != nil {
		return c.JSON(http.StatusBadRequest, &oauth2.Error{
			Code:        "invalid_request",
			Description: "failed to get authz session",
		})
	}

	if authzSession.TokenResponse != nil {
		claimBytes, err := parseClaims(authzSession.TokenResponse)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &oauth2.Error{
				Code:        "server_error",
				Description: "failed to parse claims",
			})
		}
		httpSession.Values["claims"] = string(claimBytes)
		httpSession.Save(c.Request(), c.Response())
		return c.JSON(http.StatusOK, authzSession.TokenResponse)
	}

	return c.JSON(http.StatusAccepted, map[string]string{
		"error": "authorization_pending",
	})
}

type userInfo struct {
	Issuer          string
	Identifier      string
	Name            string
	AccessTokenJson string
}

func (cl *Client) userInfo(c echo.Context) error {
	httpSession, err := session.Get("session", c)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get session",
		})
	}

	claimsJson, ok := httpSession.Values["claims"]
	if !ok {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "not logged in",
		})
	}

	claims := make(map[string]interface{})
	err = json.Unmarshal([]byte(claimsJson.(string)), &claims)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to parse claims",
		})
	}

	act := claims["act"].(map[string]interface{})

	userInfo := &userInfo{
		Issuer: act["iss"].(string),
	}
	if idNummer, ok := act["idNummer"]; ok {
		userInfo.Identifier = idNummer.(string)
	} else if mail, ok := act["email"]; ok {
		userInfo.Identifier = mail.(string)
	}

	if name, ok := act["organizationName"]; ok {
		userInfo.Name = name.(string)
	} else if name, ok := act["name"]; ok {
		userInfo.Name = name.(string)
	}

	jsonBytes, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to marshal claims",
		})
	}

	userInfo.AccessTokenJson = string(jsonBytes)

	return cl.templateUserInfo.Execute(c.Response().Writer, map[string]interface{}{
		"userInfo": userInfo,
	})
}
