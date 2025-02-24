package oauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	ctx         = context.Background()
	oauthClient = newTestOauthClient()
)

func newTestOauthClient() *OauthClient {
	prefix := "testing"
	testKey, err := GenerateKey(&prefix)
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(testKey)
	if err != nil {
		panic(err)
	}

	c, err := NewOauthClient(OauthClientArgs{
		ClientJwk: b,
	})
	if err != nil {
		panic(err)
	}

	return c
}

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

func TestGenerateKey(t *testing.T) {
	assert := assert.New(t)

	prefix := "testing"
	_, err := GenerateKey(&prefix)
	assert.NoError(err)
}
