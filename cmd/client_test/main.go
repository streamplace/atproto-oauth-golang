package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
	slogecho "github.com/samber/slog-echo"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:   "atproto-oauth-golang-tester",
		Action: run,
	}

	app.RunAndExitOnError()
}

func run(cmd *cli.Context) error {
	e := echo.New()

	e.Use(slogecho.New(slog.Default()))

	fmt.Println("atproto oauth golang tester server")

	e.GET("/oauth/client-metadata.json", handleClientMetadata)

	httpd := http.Server{
		Addr:    ":7070",
		Handler: e,
	}

	fmt.Println("starting http server...")

	if err := httpd.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func handleClientMetadata(e echo.Context) error {
	e.Response().Header().Add("Content-Type", "application/json")

	metadata := map[string]any{
		"client_id":                  "http://localhost:7070/oauth/oauth-metadata.json",
		"client_name":                "Atproto Oauth Golang Tester",
		"client_uri":                 "http://localhost:7070",
		"logo_uri":                   "http://localhost:7070/logo.png",
		"tos_uri":                    "http://localhost:7070/tos",
		"policy_url":                 "http://localhost:7070/policy",
		"redirect_uris":              []string{"http://localhost:7070/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"application_type":           "web",
		"token_endpoint_auth_method": "private_key_jwt",
		"dpop_bound_accesss_tokens":  true,
		"jwks_uri":                   "http://localhost:7070/jwks.json",
	}

	return e.JSON(200, metadata)
}
