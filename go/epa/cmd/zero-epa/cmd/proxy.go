package cmd

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/portal"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	routerCmd.Flags().StringP("addr", "a", ":8082", "Address to listen on")
	viper.BindPFlag("addr", routerCmd.Flags().Lookup("addr"))

	rootCmd.AddCommand(routerCmd)
}

var routerCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run ePA Client as Proxy",
	Run: func(cmd *cobra.Command, args []string) {
		proxies := make([]*epa.Proxy, len(config.ProxyConfigs))
		proxyInfos := make([]*epa.ProxyInfo, 0, len(config.ProxyConfigs))
		for num, proxyConfig := range config.ProxyConfigs {
			proxy, err := createProxy(&proxyConfig)
			cobra.CheckErr(err)
			info, err := proxy.GetProxyInfo()
			cobra.CheckErr(err)
			proxyInfos = append(proxyInfos, info)
			proxies[num] = proxy
		}

		e, err := buildRouter(proxies, proxyInfos)
		cobra.CheckErr(err)

		addr := viper.GetString("addr")
		slog.Info(fmt.Sprintf("starting Proxy at %s", addr))

		log.Fatal(e.Start(addr))

	},
}

// buildRouter mounts the proxies under /api and the developer portal as
// catch-all. proxies and proxyInfos are parallel slices; the first proxy is
// additionally reachable without the /api/proxies/{name} prefix.
func buildRouter(proxies []*epa.Proxy, proxyInfos []*epa.ProxyInfo) (*echo.Echo, error) {
	if len(proxies) != len(proxyInfos) {
		return nil, fmt.Errorf("got %d proxies but %d proxy infos", len(proxies), len(proxyInfos))
	}

	e := echo.New()
	e.Use(middleware.Recover())

	for num, proxy := range proxies {
		if num == 0 {
			api := e.Group("/api")
			api.Any("/*", echo.WrapHandler(http.StripPrefix("/api", proxy)))
		}

		proxyRouteName := "/api/proxies/" + proxyInfos[num].Name
		proxyRoute := e.Group(proxyRouteName)
		proxyRoute.Any("/*", echo.WrapHandler(http.StripPrefix(proxyRouteName, proxy)))

		slog.Info("Registered proxy", "name", proxyInfos[num].Name, "route", proxyRouteName)
	}

	e.GET("/api/proxies", func(c echo.Context) error {
		var infos []*epa.ProxyInfo
		for _, proxy := range proxies {
			info, err := proxy.GetProxyInfo()
			if err != nil {
				slog.Error("Failed to get proxy info", "error", err)
				continue
			}
			infos = append(infos, info)
		}
		return c.JSON(http.StatusOK, infos)
	})

	webPortal, err := portal.New(proxyInfos)
	if err != nil {
		return nil, err
	}
	e.GET("/*", echo.WrapHandler(webPortal))

	return e, nil
}

func createProxy(proxyConfig *epa.ProxyConfig) (*epa.Proxy, error) {
	err := proxyConfig.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security functions: %w", err)
	}
	return epa.NewProxy(proxyConfig)
}
