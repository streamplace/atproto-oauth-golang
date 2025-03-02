package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bluesky-social/indigo/atproto/syntax"
	oauth "github.com/haileyok/atproto-oauth-golang"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
	oauthClient  *oauth.OauthClient
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
			return nil, fmt.Errorf(
				"could not find jwks.json. does it exist? hint: run `go run ./cmd/cmd generate-jwks --prefix demo` to create one.",
			)
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

	c, err := oauth.NewOauthClient(oauth.OauthClientArgs{
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

	db.AutoMigrate(&OauthRequest{})

	return &TestServer{
		httpd:        httpd,
		e:            e,
		db:           db,
		oauthClient:  c,
		jwksResponse: oauth.CreateJwksResponseObject(pubKey),
	}, nil
}

func (s *TestServer) run() error {
	s.e.File("/", s.getFilePath("index.html"))
	s.e.File("/login", s.getFilePath("login.html"))
	s.e.POST("/login", s.handleLoginSubmit)
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

func (s *TestServer) handleLoginSubmit(e echo.Context) error {
	handle := e.FormValue("handle")
	if handle == "" {
		return e.Redirect(302, "/login?e=handle-empty")
	}

	_, herr := syntax.ParseHandle(handle)
	_, derr := syntax.ParseDID(handle)

	if herr != nil && derr != nil {
		return e.Redirect(302, "/login?e=handle-invalid")
	}

	var did string

	if derr == nil {
		did = handle
	} else {
		maybeDid, err := resolveHandle(e.Request().Context(), handle)
		if err != nil {
			return err
		}

		did = maybeDid
	}

	service, err := resolveService(ctx, did)
	if err != nil {
		return err
	}

	authserver, err := s.oauthClient.ResolvePDSAuthServer(ctx, service)
	if err != nil {
		return err
	}

	meta, err := s.oauthClient.FetchAuthServerMetadata(ctx, authserver)
	if err != nil {
		return err
	}

	dpopPrivateKey, err := oauth.GenerateKey(nil)
	if err != nil {
		return err
	}

	dpopPrivateKeyJson, err := json.Marshal(dpopPrivateKey)
	if err != nil {
		return err
	}

	parResp, err := s.oauthClient.SendParAuthRequest(
		ctx,
		authserver,
		meta,
		"",
		scope,
		dpopPrivateKey,
	)

	oauthRequest := OauthRequest{
		State:               "",
		AuthserverIss:       meta.Issuer,
		Did:                 did,
		PdsUrl:              service,
		PkceVerifier:        parResp.PkceVerifier,
		DpopAuthserverNonce: parResp.DpopAuthserverNonce,
		DpopPrivateJwk:      string(dpopPrivateKeyJson),
	}

	if err := s.db.Create(&oauthRequest).Error; err != nil {
		return err
	}

	u, _ := url.Parse(meta.AuthorizationEndpoint)
	u.RawQuery = fmt.Sprintf(
		"client_id=%s&request_uri=%s",
		url.QueryEscape(serverMetadataUrl),
		parResp.Resp["request_uri"].(string),
	)

	return e.Redirect(302, u.String())
}

func resolveHandle(ctx context.Context, handle string) (string, error) {
	var did string

	_, err := syntax.ParseHandle(handle)
	if err != nil {
		return "", err
	}

	recs, err := net.LookupTXT(fmt.Sprintf("_atproto.%s", handle))
	if err != nil {
		return "", err
	}

	for _, rec := range recs {
		if strings.HasPrefix(rec, "did=") {
			did = strings.Split(rec, "did=")[1]
			break
		}
	}

	if did == "" {
		req, err := http.NewRequestWithContext(
			ctx,
			"GET",
			fmt.Sprintf("https://%s/.well-known/atproto-did", handle),
			nil,
		)
		if err != nil {
			return "", err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			return "", fmt.Errorf("unable to resolve handle")
		}

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		maybeDid := string(b)

		if _, err := syntax.ParseDID(maybeDid); err != nil {
			return "", fmt.Errorf("unable to resolve handle")
		}

		did = maybeDid
	}

	// TODO: we can also support did:web here

	if did == "" {
		return "", fmt.Errorf("unable to resolve handle")
	}

	return did, nil
}

func resolveService(ctx context.Context, did string) (string, error) {
	type Identity struct {
		Service []struct {
			ID              string `json:"id"`
			Type            string `json:"type"`
			ServiceEndpoint string `json:"serviceEndpoint"`
		} `json:"service"`
	}

	if strings.HasPrefix(did, "did:plc:") {
		req, err := http.NewRequestWithContext(
			ctx,
			"GET",
			fmt.Sprintf("https://plc.directory/%s", did),
			nil,
		)
		if err != nil {
			return "", err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			return "", fmt.Errorf("could not find identity in plc registry")
		}

		var identity Identity
		if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
			return "", err
		}

		var service string
		for _, svc := range identity.Service {
			if svc.ID == "#atproto_pds" {
				service = svc.ServiceEndpoint
			}
		}

		if service == "" {
			return "", fmt.Errorf("could not find atproto_pds service in identity services")
		}

		return service, nil
	} else if strings.HasPrefix(did, "did:web:") {
		// TODO: needs more work
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/.well-known/did.json", did), nil)
		if err != nil {
			return "", err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			return "", fmt.Errorf("could not find identity in plc registry")
		}

		var identity Identity
		if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
			return "", err
		}

		var service string
		for _, svc := range identity.Service {
			if svc.ID == "#atproto_pds" {
				service = svc.ServiceEndpoint
			}
		}

		if service == "" {
			return "", fmt.Errorf("could not find atproto_pds service in identity services")
		}

		return service, nil
	} else {
		return "", fmt.Errorf("did was not a supported did type")
	}
}

func (s *TestServer) getFilePath(file string) string {
	return fmt.Sprintf("%s/%s", staticFilePath, file)
}
