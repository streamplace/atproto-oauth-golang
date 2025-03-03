package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/gorilla/sessions"
	oauth "github.com/haileyok/atproto-oauth-golang"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
	slogecho "github.com/samber/slog-echo"
	"github.com/urfave/cli/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	oauthClient  *oauth.OauthClient
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

	db.AutoMigrate(&OauthRequest{}, &OauthSession{})

	xrpcCli := &oauth.XrpcClient{
		OnDPoPNonceChanged: func(did, newNonce string) {
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

	oauthRequest := &OauthRequest{
		State:               parResp.State,
		AuthserverIss:       meta.Issuer,
		Did:                 did,
		PdsUrl:              service,
		PkceVerifier:        parResp.PkceVerifier,
		DpopAuthserverNonce: parResp.DpopAuthserverNonce,
		DpopPrivateJwk:      string(dpopPrivateKeyJson),
	}

	if err := s.db.Create(oauthRequest).Error; err != nil {
		return err
	}

	u, _ := url.Parse(meta.AuthorizationEndpoint)
	u.RawQuery = fmt.Sprintf(
		"client_id=%s&request_uri=%s",
		url.QueryEscape(serverMetadataUrl),
		parResp.Resp["request_uri"].(string),
	)

	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   300, // save for five minutes
		HttpOnly: true,
	}

	// make sure the session is empty
	sess.Values = map[interface{}]interface{}{}
	sess.Values["oauth_state"] = parResp.State
	sess.Values["oauth_did"] = did

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	return e.Redirect(302, u.String())
}

func (s *TestServer) handleCallback(e echo.Context) error {
	resState := e.QueryParam("state")
	resIss := e.QueryParam("iss")
	resCode := e.QueryParam("code")

	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sessState := sess.Values["oauth_state"]
	sessDid := sess.Values["oauth_did"]

	if resState == "" || resIss == "" || resCode == "" || sessState == "" || sessDid == "" {
		return fmt.Errorf("request missing needed parameters")
	}

	if resState != sessState {
		return fmt.Errorf("session state does not match response state")
	}

	var oauthRequest OauthRequest
	if err := s.db.Raw("SELECT * FROM oauth_requests WHERE state = ? AND did = ?", sessState, sessDid).Scan(&oauthRequest).Error; err != nil {
		return err
	}

	if err := s.db.Exec("DELETE FROM oauth_requests WHERE state = ? AND did = ?", sessState, sessDid).Error; err != nil {
		return err
	}

	if resIss != oauthRequest.AuthserverIss {
		return fmt.Errorf("incoming iss did not match authserver iss")
	}

	jwk, err := oauth.ParseKeyFromBytes([]byte(oauthRequest.DpopPrivateJwk))
	if err != nil {
		return err
	}

	initialTokenResp, err := s.oauthClient.InitialTokenRequest(
		e.Request().Context(),
		resCode,
		resIss,
		resIss,
		oauthRequest.PkceVerifier,
		oauthRequest.DpopAuthserverNonce,
		jwk,
	)
	if err != nil {
		return err
	}

	// TODO: resolve if needed

	if initialTokenResp.Resp["scope"] != scope {
		return fmt.Errorf("did not receive correct scopes from token request")
	}

	oauthSession := &OauthSession{
		Did:                 oauthRequest.Did,
		PdsUrl:              oauthRequest.PdsUrl,
		AuthserverIss:       oauthRequest.AuthserverIss,
		AccessToken:         initialTokenResp.Resp["access_token"].(string),
		RefreshToken:        initialTokenResp.Resp["refresh_token"].(string),
		DpopAuthserverNonce: initialTokenResp.DpopAuthserverNonce,
		DpopPrivateJwk:      oauthRequest.DpopPrivateJwk,
	}

	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "did"}},
		UpdateAll: true,
	}).Create(oauthSession).Error; err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	// make sure the session is empty
	sess.Values = map[interface{}]interface{}{}
	sess.Values["did"] = oauthRequest.Did

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	return e.Redirect(302, "/")
}

func (s *TestServer) handleLogout(e echo.Context) error {
	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	return e.Redirect(302, "/")
}

func (s *TestServer) handleMakePost(e echo.Context) error {
	sess, err := session.Get("session", e)
	if err != nil {
		return err
	}

	did, ok := sess.Values["did"]
	if !ok {
		return e.Redirect(302, "/login")
	}

	var oauthSession OauthSession
	if err := s.db.Raw("SELECT * FROM oauth_sessions WHERE did = ?", did).Scan(&oauthSession).Error; err != nil {
		return err
	}

	args, err := authedReqArgsFromSession(&oauthSession)
	if err != nil {
		return err
	}

	post := bsky.FeedPost{
		Text:      "hello from atproto golang oauth client",
		CreatedAt: syntax.DatetimeNow().String(),
	}

	input := atproto.RepoCreateRecord_Input{
		Collection: "app.bsky.feed.post",
		Repo:       oauthSession.Did,
		Record:     &util.LexiconTypeDecoder{Val: &post},
	}

	var out atproto.RepoCreateRecord_Output
	if err := s.xrpcCli.Do(e.Request().Context(), args, xrpc.Procedure, "application/json", "com.atproto.repo.createRecord", nil, input, &out); err != nil {
		return err
	}

	return e.File(getFilePath("make-post.html"))
}

func authedReqArgsFromSession(session *OauthSession) (*oauth.XrpcAuthedRequestArgs, error) {
	privateJwk, err := oauth.ParseKeyFromBytes([]byte(session.DpopPrivateJwk))
	if err != nil {
		return nil, err
	}

	return &oauth.XrpcAuthedRequestArgs{
		Did:            session.Did,
		AccessToken:    session.AccessToken,
		PdsUrl:         session.PdsUrl,
		Issuer:         session.AuthserverIss,
		DpopPdsNonce:   session.DpopPdsNonce,
		DpopPrivateJwk: privateJwk,
	}, nil
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

	var ustr string
	if strings.HasPrefix(did, "did:plc:") {
		ustr = fmt.Sprintf("https://plc.directory/%s", did)
	} else if strings.HasPrefix(did, "did:web:") {
		ustr = fmt.Sprintf("https://%s/.well-known/did.json", did)
	} else {
		return "", fmt.Errorf("did was not a supported did type")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", ustr, nil)
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
}

func getFilePath(file string) string {
	return fmt.Sprintf("%s/%s", staticFilePath, file)
}
