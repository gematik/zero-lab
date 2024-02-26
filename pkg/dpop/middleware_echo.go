package dpop

import (
	"fmt"

	"github.com/labstack/echo/v4"
)

func (m *Middleware) VerifyDPoPHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		fullUrl := fmt.Sprintf("%s://%s%s", c.Scheme(), c.Request().Host, c.Request().RequestURI)
		dpop, err := m.VerifyRequest(c.Request(), c.Response(), fullUrl)
		if err != nil {
			return err
		}
		// set the dpop object in the context
		c.Set("dpop", dpop)

		return next(c)
	}
}
