package zasweb

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"

	"github.com/gematik/zero-lab/pkg/gemidp"
	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/zas"
	"github.com/labstack/echo/v4"
)

var (
	//go:embed *.html
	templatesFS embed.FS
)

func MountRoutes(g *echo.Group, as *zas.Server) {
	g.Use(zas.ErrorLogMiddleware)
	g.GET("/error", showError())
	g.GET("/login", login(as))
	g.GET("/login/authenticator", authenticator(as))
	g.POST("/auth-decoupled", authDecoupled(as))
}

func showError() echo.HandlerFunc {
	template := template.Must(template.ParseFS(templatesFS, "error.html", "layout.html"))

	return func(c echo.Context) error {
		return template.Execute(c.Response().Writer, map[string]interface{}{
			"error": oauth2.Error{
				Code:        c.QueryParam("error"),
				Description: c.QueryParam("error_description"),
			},
		})
	}
}

func authenticator(as *zas.Server) echo.HandlerFunc {
	template := template.Must(template.ParseFS(templatesFS, "authenticator.html", "layout.html"))

	return func(c echo.Context) error {
		return template.Execute(c.Response().Writer, nil)
	}
}

func login(as *zas.Server) echo.HandlerFunc {
	template := template.Must(template.ParseFS(templatesFS, "login.html", "layout.html"))

	return func(c echo.Context) error {
		issuer := c.QueryParam("op_issuer")
		if issuer != "" {
			op, err := as.OpenidProvider(issuer)
			if err != nil {
				// todo redirect to error page
				return err
			}
			if _, ok := op.(*gemidp.Client); ok {
				slog.Info("gemidp login")
				return c.Redirect(http.StatusFound, "/web/login/authenticator?op_issuer="+url.QueryEscape(issuer))
			}

			session, err := as.StartOpenidProviderSession(issuer)
			if err != nil {
				// todo redirect to error page
				return err
			}
			err = as.SessionStore.SaveAuthnSession(session)
			if err != nil {
				// todo redirect to error page
				return err
			}
			return c.Redirect(http.StatusFound, session.AuthURL)
		}

		ops, err := as.OpenidProviders()
		if err != nil {
			return err
		}

		return template.Execute(c.Response().Writer, map[string]interface{}{
			"openidProviders": ops,
		})
	}
}

type decoupledAuthRequest struct {
	GrantType    string `form:"grant_type"`
	OpIssuer     string `form:"op_issuer"`
	AuthReqID    string `form:"auth_req_id"`
	ResponseType string `form:"response_type"`
}

type decoupledAuthResponse struct {
	AuthReqID   string `json:"auth_req_id"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	PollURI     string `json:"poll_uri,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	Interval    int    `json:"interval,omitempty"`
}

func authDecoupled(as *zas.Server) echo.HandlerFunc {
	return func(c echo.Context) error {
		var req decoupledAuthRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
				Code:        "invalid_request",
				Description: fmt.Sprintf("unable to bind request: %s", err),
			})
		}

		slog.Info("Decoupled auth request", "request", req)

		if req.AuthReqID != "" {
			session, err := as.SessionStore.GetAuthnSessionByID(req.AuthReqID)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
					Code:        "invalid_request",
					Description: fmt.Sprintf("unable to get session: %s", err),
				})
			}

			if session.Claims != nil {
				return c.JSON(http.StatusOK, session.Claims)
			} else {
				return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
					Code:        "authorization_pending",
					Description: "authorization not yet completed",
				})
			}

		} else if req.GrantType == "urn:telematik:params:grant-type:decoupled" {
			if req.OpIssuer == "" {
				return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
					Code:        "invalid_request",
					Description: "missing op_issuer parameter",
				})
			}
			op, err := as.OpenidProvider(req.OpIssuer)
			if err != nil {
				return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
					Code:        "invalid_request",
					Description: fmt.Sprintf("unknown op_issuer: %s", req.OpIssuer),
				})
			}
			slog.Info("Starting decoupled auth session", "op", reflect.TypeOf(op))
			authnSession, err := as.StartOpenidProviderSession(req.OpIssuer)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
					Code:        "server_error",
					Description: fmt.Sprintf("unable to start authn session: %s", err),
				})
			}

			as.SessionStore.SaveAuthnSession(authnSession)

			return c.JSON(http.StatusOK, decoupledAuthResponse{
				AuthReqID:   authnSession.ID,
				RedirectURI: authnSession.AuthURL,
				ExpiresIn:   3600,
				Interval:    3,
			})

		}

		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "invalid parameters",
		})

	}
}
