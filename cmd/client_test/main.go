package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	oauth "github.com/haileyok/atproto-oauth-golang"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	slogecho "github.com/samber/slog-echo"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	ctx               = context.Background()
	serverAddr        = os.Getenv("OAUTH_TEST_SERVER_ADDR")
	serverUrlRoot     = os.Getenv("OAUTH_TEST_SERVER_URL_ROOT")
	staticFilePath    = os.Getenv("OAUTH_TEST_SERVER_STATIC_PATH")
	sessionSecret     = os.Getenv("OAUTH_TEST_SESSION_SECRET")
	serverMetadataUrl = fmt.Sprintf("%s/oauth/client-metadata.json", serverUrlRoot)
	serverCallbackUrl = fmt.Sprintf("%s/callback", serverUrlRoot)
	pdsUrl            = os.Getenv("OAUTH_TEST_PDS_URL")
	scope             = "atproto transition:generic"
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
	db           *gorm.DB
	oauthClient  *oauth.Client
	xrpcCli      *oauth.XrpcClient
	jwksResponse *oauth.JwksResponseObject
}

type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
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
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(sessionSecret))))

	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob(getFilePath("*.html"))),
	}
	e.Renderer = renderer

	fmt.Println("atproto oauth golang tester server")

	b, err := os.ReadFile("./jwks.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"could not find jwks.json. does it exist? hint: run `go run ./cmd/cmd generate-jwks --prefix demo` to create one.",
			)
		}
		return nil, err
	}

	k, err := oauth.ParseJWKFromBytes(b)
	if err != nil {
		return nil, err
	}

	pubKey, err := k.PublicKey()
	if err != nil {
		return nil, err
	}

	c, err := oauth.NewClient(oauth.ClientArgs{
		ClientJwk:   k,
		ClientId:    serverMetadataUrl,
		RedirectUri: serverCallbackUrl,
	})
	if err != nil {
		return nil, err
	}

	httpd := &http.Server{
		Addr:    serverAddr,
		Handler: e,
	}

	db, err := gorm.Open(sqlite.Open("oauth.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&OauthRequest{}, &OauthSession{})

	xrpcCli := &oauth.XrpcClient{
		OnDpopPdsNonceChanged: func(did, newNonce string) {
			if err := db.Exec("UPDATE oauth_sessions SET dpop_pds_nonce = ? WHERE did = ?", newNonce, did).Error; err != nil {
				slog.Default().Error("error updating pds nonce", "err", err)
			}
		},
	}

	return &TestServer{
		httpd:        httpd,
		e:            e,
		db:           db,
		oauthClient:  c,
		xrpcCli:      xrpcCli,
		jwksResponse: oauth.CreateJwksResponseObject(pubKey),
	}, nil
}

func (s *TestServer) run() error {
	s.e.GET("/", s.handleHome)
	s.e.File("/login", getFilePath("login.html"))
	s.e.POST("/login", s.handleLoginSubmit)
	s.e.GET("/logout", s.handleLogout)
	s.e.GET("/profile", s.handleProfile)
	s.e.GET("/make-post", s.handleMakePost)
	s.e.GET("/callback", s.handleCallback)
	s.e.GET("/oauth/client-metadata.json", s.handleClientMetadata)
	s.e.GET("/oauth/jwks.json", s.handleJwks)

	if err := s.httpd.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (s *TestServer) handleHome(e echo.Context) error {
	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	return e.Render(200, "index.html", map[string]any{
		"Did": sess.Values["did"],
	})
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

func getFilePath(file string) string {
	return fmt.Sprintf("%s/%s", staticFilePath, file)
}
