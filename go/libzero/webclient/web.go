package webclient

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

	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/gematik/zero-lab/go/libzero/oidc"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/segmentio/ksuid"
)

var (
	//go:embed *.html
	templatesFS embed.FS
)

func NewFromServerMetadata(serverMetadata oauth2.ServerMetadata) (*Client, error) {

	return &Client{
		ClientID:                  "zero-web",
		RedirectURI:               fmt.Sprint(serverMetadata.Issuer, "/web/login/callback"),
		Scopes:                    []string{"zero:register"},
		ServerMetadata:            serverMetadata,
		authzSessionStore:         NewMockAuthzClientSessionStore(),
		templateError:             template.Must(template.ParseFS(templatesFS, "error.html", "layout.html")),
		templateAuthenticatorWait: template.Must(template.ParseFS(templatesFS, "authenticator-wait.html", "layout.html")),
		templateUserInfo:          template.Must(template.ParseFS(templatesFS, "userinfo.html", "layout.html")),
		templateLogin:             template.Must(template.ParseFS(templatesFS, "login.html", "layout.html")),
		templateChoose:            template.Must(template.ParseFS(templatesFS, "choose-openid-provider.html", "layout.html")),
		templateDecoupledWait:     template.Must(template.ParseFS(templatesFS, "decoupled-wait.html", "layout.html")),
		templateDecoupledSuccess:  template.Must(template.ParseFS(templatesFS, "decoupled-success.html", "layout.html")),
	}, nil
}

type Client struct {
	ClientID                  string
	RedirectURI               string
	Scopes                    []string
	ServerMetadata            oauth2.ServerMetadata
	authzSessionStore         AuthzClientSessionStore
	templateError             *template.Template
	templateAuthenticatorWait *template.Template
	templateUserInfo          *template.Template
	templateLogin             *template.Template
	templateChoose            *template.Template
	templateDecoupledWait     *template.Template
	templateDecoupledSuccess  *template.Template
	cachedOpenidProviders     []oidc.OpenidProviderInfo
}

func (cl *Client) MountRoutes(g *echo.Group) {
	g.Use(
		// TODO: make secret configurable
		session.Middleware(sessions.NewCookieStore([]byte("secret"))),
	)
	g.GET("/error", cl.showError)
	g.GET("/login/choose-openid-provider", cl.chooseOpenidProvider)
	g.GET("/login", cl.login)
	g.GET("/login/start", cl.start)
	g.GET("/login/decoupled", cl.loginDecoupled)
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

	url := fmt.Sprintf("%s?%s", cl.ServerMetadata.AuthorizationEndpoint, params.Encode())

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

	slog.Debug("Exchanging code for token", "url", cl.ServerMetadata.TokenEndpoint, "params", params)

	resp, err := http.PostForm(cl.ServerMetadata.TokenEndpoint, params)
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

func (cl *Client) fetchOpenidProviders() ([]oidc.OpenidProviderInfo, error) {
	subUrl := fmt.Sprint(cl.ServerMetadata.Issuer, "/openid-providers")
	resp, err := http.Get(subUrl)
	if err != nil {
		return nil, fmt.Errorf("fetching openid providers: %w", err)
	}
	defer resp.Body.Close()

	var openidProviders []oidc.OpenidProviderInfo
	err = json.NewDecoder(resp.Body).Decode(&openidProviders)
	if err != nil {
		return nil, fmt.Errorf("parsing openid providers: %w", err)
	}

	if cl.cachedOpenidProviders == nil {
		cl.cachedOpenidProviders = openidProviders
	}

	return openidProviders, nil
}

func (cl *Client) fetchOpenidProvider(issuer string) (*oidc.OpenidProviderInfo, error) {
	openidProviders, err := cl.fetchOpenidProviders()
	if err != nil {
		return nil, err
	}

	for _, op := range openidProviders {
		if op.Issuer == issuer {
			return &op, nil
		}
	}

	return nil, fmt.Errorf("openid provider not found")
}

func (cl *Client) chooseOpenidProvider(c echo.Context) error {
	openidProviders, err := cl.fetchOpenidProviders()
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to fetch openid providers",
		})
	}
	return cl.templateChoose.Execute(c.Response().Writer, map[string]interface{}{
		"openidProviders": openidProviders,
	})
}

func (cl *Client) login(c echo.Context) error {

	return cl.templateLogin.Execute(c.Response().Writer, nil)
}

func (cl *Client) start(c echo.Context) error {
	issuer := c.QueryParam("op_issuer")
	if issuer == "" {
		return c.JSON(http.StatusBadRequest, &oauth2.Error{
			Code:        "invalid_request",
			Description: "missing op_issuer parameter",
		})
	}

	authzSession := AuthzClientSession{
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
		return c.JSON(http.StatusInternalServerError, &oauth2.Error{
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
		return c.JSON(http.StatusInternalServerError, &oauth2.Error{
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

	op, err := cl.fetchOpenidProvider(issuer)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to fetch openid provider",
		})
	}

	authURL := authzSession.AuthURL

	if op.Type == "oidf" {
		authURL = fmt.Sprintf("/web/login/decoupled?auth_url=%s", authzSession.AuthURL)
	} else if op.Type == "gemidp" {
		authURL = fmt.Sprintf("/web/login/authenticator?auth_url=%s", authzSession.AuthURL)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"auth_url": authURL,
		"op":       op,
	})

}

func (cl *Client) loginDecoupled(c echo.Context) error {
	issuer := c.QueryParam("op_issuer")
	if issuer == "" {
		return redirectWithError(c, &oauth2.Error{
			Code:        "invalid_request",
			Description: "missing op_issuer parameter",
		})
	}

	op, err := cl.fetchOpenidProvider(issuer)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to fetch openid provider",
		})
	}

	httpSession, err := session.Get("session", c)
	if err != nil || httpSession.IsNew {
		return c.JSON(http.StatusInternalServerError, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get session",
		})
	}

	qrCodeURL := ""

	if op.Type == "oidf" {
		// http client without redirect
		httpClient := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := httpClient.Get(httpSession.Values["auth_url"].(string))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &oauth2.Error{
				Code:        "server_error",
				Description: "failed to fetch auth URL",
			})
		}

		redirectUrl, err := resp.Location()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, &oauth2.Error{
				Code:        "server_error",
				Description: "failed to get location header",
			})
		}

		qrCodeURL = redirectUrl.String()
	}

	return cl.templateDecoupledWait.Execute(c.Response().Writer, map[string]interface{}{
		"op":        op,
		"qrCodeURL": qrCodeURL,
	})
}

func (cl *Client) loginCallback(c echo.Context) error {
	if c.QueryParam("error") != "" {
		return redirectWithError(c, &oauth2.Error{
			Code:        c.QueryParam("error"),
			Description: c.QueryParam("error_description"),
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

	httpSession, err := session.Get("session", c)
	if err != nil {
		return redirectWithError(c, &oauth2.Error{
			Code:        "server_error",
			Description: "failed to get session",
		})
	}

	slog.Info("Got me session", "session", fmt.Sprintf("%+v", httpSession))

	if !httpSession.IsNew {
		httpSession.Values["claims"] = string(claimBytes)
		httpSession.Save(c.Request(), c.Response())
	} else {
		// no session found, seems to be decoupled login
		return cl.templateDecoupledSuccess.Execute(c.Response().Writer, map[string]interface{}{})
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

	act := claims["urn:telematik:zta:subject"].(map[string]interface{})

	userInfo := &userInfo{
		Issuer: act["iss"].(string),
	}

	if id, ok := act["idNummer"]; ok { // gematik IDP-Dienst
		userInfo.Identifier = id.(string)
	} else if id, ok := act["urn:telematik:claims:id"]; ok { // GesundheitsID
		userInfo.Identifier = id.(string)
	} else if id, ok := act["unique_name"]; ok { // Azure EntraID
		userInfo.Identifier = id.(string)
	} else if id, ok := act["email"]; ok { // generic fallback, e.g. Google
		userInfo.Identifier = id.(string)
	}

	if name, ok := act["organizationName"]; ok {
		userInfo.Name = name.(string)
	} else if name, ok := act["urn:telematik:claims:display_name"]; ok {
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
