package main

import (
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/labstack/echo/v4"
)

func (s *TestServer) handleProfile(e echo.Context) error {
	authArgs, authed, err := s.getOauthSessionAuthArgs(e)
	if err != nil {
		return err
	}

	if !authed {
		return e.Redirect(302, "/login")
	}

	var out bsky.ActorDefs_ProfileViewDetailed
	if err := s.xrpcCli.Do(e.Request().Context(), authArgs, xrpc.Query, "", "app.bsky.actor.getProfile", map[string]any{"actor": authArgs.Did}, nil, &out); err != nil {
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
