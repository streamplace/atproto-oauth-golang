package oauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	ctx         = context.Background()
	oauthClient = NewOauthClient(OauthClientArgs{})
)

func TestResolvePDSAuthServer(t *testing.T) {
	assert := assert.New(t)

	authServer, err := oauthClient.ResolvePDSAuthServer(ctx, "https://pds.haileyok.com")

	assert.NoError(err)
	assert.NotEmpty(authServer)
	assert.Equal("https://pds.haileyok.com", authServer)
}

func TestFetchAuthServerMetadata(t *testing.T) {
	assert := assert.New(t)

	meta, err := oauthClient.FetchAuthServerMetadata(ctx, "https://pds.haileyok.com")

	assert.NoError(err)
	assert.IsType(OauthAuthorizationMetadata{}, meta)
}
