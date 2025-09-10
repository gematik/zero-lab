package cmd

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/gematik/zero-lab/go/epa"
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

		e := echo.New()
		e.Use(middleware.Recover())
		proxies := make([]*epa.Proxy, len(config.ProxyConfigs))
		proxyInfos := make([]*epa.ProxyInfo, 0, len(config.ProxyConfigs))
		for num, proxyConfig := range config.ProxyConfigs {
			proxy, err := createProxy(&proxyConfig)
			cobra.CheckErr(err)
			info, err := proxy.GetProxyInfo()
			cobra.CheckErr(err)
			proxyInfos = append(proxyInfos, info)
			proxies[num] = proxy
			if num == 0 {
				api := e.Group("/api")
				api.Any("/*", echo.WrapHandler(http.StripPrefix("/api", proxy)))
			}

			proxyRouteName := "/api/proxies/" + proxyConfig.Name
			proxyRoute := e.Group(proxyRouteName)
			proxyRoute.Any("/*", echo.WrapHandler(http.StripPrefix(proxyRouteName, proxy)))

			slog.Info("Registered proxy", "name", proxyConfig.Name, "route", proxyRouteName)
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
		e.GET("/", echo.WrapHandler(epa.HandleReadmeFunc(proxyInfos)))
		addr := viper.GetString("addr")
		slog.Info(fmt.Sprintf("starting Proxy at %s", addr))

		log.Fatal(e.Start(addr))

	},
}

func createProxy(proxyConfig *epa.ProxyConfig) (*epa.Proxy, error) {
	err := proxyConfig.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize security functions: %w", err)
	}
	return epa.NewProxy(proxyConfig)
}
