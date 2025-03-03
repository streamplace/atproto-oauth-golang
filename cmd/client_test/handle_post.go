package main

import (
	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

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
