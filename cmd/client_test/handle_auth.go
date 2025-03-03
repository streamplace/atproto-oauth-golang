package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	oauth "github.com/haileyok/atproto-oauth-golang"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm/clause"
)

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
