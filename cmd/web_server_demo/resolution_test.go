package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveHandle(t *testing.T) {
	assert := assert.New(t)

	handle, err := resolveHandle(context.TODO(), "bsky.app")
	if err != nil {
		panic(err)
	}

	assert.NoError(err)
	assert.Equal("did:plc:z72i7hdynmk6r22z27h6tvur", handle)
}

func TestResolveService(t *testing.T) {
	assert := assert.New(t)

	svc, err := resolveService(context.TODO(), "did:plc:z72i7hdynmk6r22z27h6tvur")
	assert.NoError(err)
	assert.Equal("https://puffball.us-east.host.bsky.network", svc)

	svc, err = resolveService(context.TODO(), "did:plc:oisofpd7lj26yvgiivf3lxsi")
	assert.NoError(err)
	assert.Equal("https://pds.haileyok.com", svc)

	svc, err = resolveService(context.TODO(), "did:web:juli.ee")
	assert.NoError(err)
	assert.Equal("https://milli.juli.ee", svc)
}
