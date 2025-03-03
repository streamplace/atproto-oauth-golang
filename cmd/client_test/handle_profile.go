package main

import (
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func (s *TestServer) handleProfile(e echo.Context) error {
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

	var out bsky.ActorDefs_ProfileViewDetailed
	if err := s.xrpcCli.Do(e.Request().Context(), args, xrpc.Query, "", "app.bsky.actor.getProfile", map[string]any{"actor": oauthSession.Did}, nil, &out); err != nil {
		return err
	}

	var dn string
	if out.DisplayName != nil {
		dn = *out.DisplayName
	}

	var desc string
	if out.Description != nil {
		desc = *out.Description
	}

	return e.Render(200, "profile.html", map[any]any{
		"DisplayName": dn,
		"Description": desc,
		"Handle":      out.Handle,
	})
}
