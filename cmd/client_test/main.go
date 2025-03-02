package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	oauth "github.com/haileyok/atproto-oauth-golang"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	slogecho "github.com/samber/slog-echo"
	"github.com/urfave/cli/v2"
)

var (
	ctx               = context.Background()
	serverAddr        = os.Getenv("OAUTH_TEST_SERVER_ADDR")
	serverUrlRoot     = os.Getenv("OAUTH_TEST_SERVER_URL_ROOT")
	serverMetadataUrl = fmt.Sprintf("%s/oauth/client-metadata.json", serverUrlRoot)
	serverCallbackUrl = fmt.Sprintf("%s/callback", serverUrlRoot)
	pdsUrl            = os.Getenv("OAUTH_TEST_PDS_URL")
)

func main() {
	app := &cli.App{
		Name:   "atproto-oauth-golang-tester",
		Action: run,
	}

	if serverUrlRoot == "" {
		panic(fmt.Errorf("no server url root set in env file"))
	}

	app.RunAndExitOnError()
}

type TestServer struct {
	httpd        *http.Server
	e            *echo.Echo
	jwksResponse *oauth.JwksResponseObject
}

func run(cmd *cli.Context) error {
	s, err := NewServer()
	if err != nil {
		panic(err)
	}

	s.run()

	return nil
}

func NewServer() (*TestServer, error) {
	e := echo.New()

	e.Use(slogecho.New(slog.Default()))

	fmt.Println("atproto oauth golang tester server")

	b, err := os.ReadFile("./jwks.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("could not find jwks.json. does it exist? hint: run `go run ./cmd/cmd generate-jwks --prefix demo` to create one.")
		}
		return nil, err
	}

	k, err := jwk.ParseKey(b)
	if err != nil {
		return nil, err
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	httpd := &http.Server{
		Addr:    serverAddr,
		Handler: e,
	}

	fmt.Println("starting http server...")

	return &TestServer{
		httpd:        httpd,
		e:            e,
		jwksResponse: oauth.CreateJwksResponseObject(pubKey),
	}, nil
}

func (s *TestServer) run() error {
	s.e.GET("/oauth/client-metadata.json", s.handleClientMetadata)
	s.e.GET("/oauth/jwks.json", s.handleJwks)

	if err := s.httpd.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (s *TestServer) handleClientMetadata(e echo.Context) error {
	metadata := map[string]any{
		"client_id":                       serverMetadataUrl,
		"client_name":                     "Atproto Oauth Golang Tester",
		"client_uri":                      serverUrlRoot,
		"logo_uri":                        fmt.Sprintf("%s/logo.png", serverUrlRoot),
		"tos_uri":                         fmt.Sprintf("%s/tos", serverUrlRoot),
		"policy_url":                      fmt.Sprintf("%s/policy", serverUrlRoot),
		"redirect_uris":                   []string{serverCallbackUrl},
		"grant_types":                     []string{"authorization_code", "refresh_token"},
		"response_types":                  []string{"code"},
		"application_type":                "web",
		"dpop_bound_access_tokens":        true,
		"jwks_uri":                        fmt.Sprintf("%s/oauth/jwks.json", serverUrlRoot),
		"scope":                           "atproto transition:generic",
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
	}

	return e.JSON(200, metadata)
}

func (s *TestServer) handleJwks(e echo.Context) error {
	return e.JSON(200, s.jwksResponse)
}
