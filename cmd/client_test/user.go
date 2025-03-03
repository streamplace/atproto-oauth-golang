package main

import (
	"context"
	"fmt"
	"time"

	oauth "github.com/haileyok/atproto-oauth-golang"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func (s *TestServer) getOauthSession(ctx context.Context, did string) (*OauthSession, error) {
	var oauthSession OauthSession
	if err := s.db.Raw("SELECT * FROM oauth_sessions WHERE did = ?", did).Scan(&oauthSession).Error; err != nil {
		return nil, err
	}

	if oauthSession.Did == "" {
		return nil, fmt.Errorf("did not find session in database")
	}

	if oauthSession.Expiration.Sub(time.Now()) <= 5*time.Minute {
		privateJwk, err := oauth.ParseKeyFromBytes([]byte(oauthSession.DpopPrivateJwk))
		if err != nil {
			return nil, err
		}

		resp, err := s.oauthClient.RefreshTokenRequest(ctx, oauthSession.RefreshToken, oauthSession.AuthserverIss, oauthSession.DpopAuthserverNonce, privateJwk)
		if err != nil {
			return nil, err
		}

		expiration := time.Now().Add(time.Duration(int(time.Second) * int(resp.ExpiresIn)))

		if err := s.db.Exec("UPDATE oauth_sessions SET access_token = ?, refresh_token = ?, dpop_authserver_nonce = ?, expiration  = ? WHERE did = ?", resp.AccessToken, resp.RefreshToken, resp.DpopAuthserverNonce, expiration, oauthSession.Did).Error; err != nil {
			return nil, err
		}

		oauthSession.AccessToken = resp.AccessToken
		oauthSession.RefreshToken = resp.RefreshToken
		oauthSession.DpopAuthserverNonce = resp.DpopAuthserverNonce
		oauthSession.Expiration = expiration
	}

	return &oauthSession, nil
}

func (s *TestServer) getOauthSessionAuthArgs(e echo.Context) (*oauth.XrpcAuthedRequestArgs, bool, error) {
	sess, err := session.Get("session", e)
	if err != nil {
		return nil, false, err
	}

	did, ok := sess.Values["did"]
	if !ok {
		return nil, false, nil
	}

	oauthSession, err := s.getOauthSession(e.Request().Context(), did.(string))

	privateJwk, err := oauth.ParseKeyFromBytes([]byte(oauthSession.DpopPrivateJwk))
	if err != nil {
		return nil, false, err
	}

	return &oauth.XrpcAuthedRequestArgs{
		Did:            oauthSession.Did,
		AccessToken:    oauthSession.AccessToken,
		PdsUrl:         oauthSession.PdsUrl,
		Issuer:         oauthSession.AuthserverIss,
		DpopPdsNonce:   oauthSession.DpopPdsNonce,
		DpopPrivateJwk: privateJwk,
	}, true, nil
}
