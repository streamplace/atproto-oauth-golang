package oauth

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- decodeJSONResponse unit tests ---

func TestDecodeJSONResponse_ValidJSON(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"key":"value"}`)),
	}

	var dest map[string]string
	err := decodeJSONResponse(resp, &dest)

	assert.NoError(t, err)
	assert.Equal(t, "value", dest["key"])
}

func TestDecodeJSONResponse_ValidJSON_WithCharset(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(`{"foo":"bar"}`)),
	}

	var dest map[string]string
	err := decodeJSONResponse(resp, &dest)

	assert.NoError(t, err)
	assert.Equal(t, "bar", dest["foo"])
}

func TestDecodeJSONResponse_HTMLResponse(t *testing.T) {
	htmlBody := `<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>`
	resp := &http.Response{
		StatusCode: 404,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	var dest map[string]string
	err := decodeJSONResponse(resp, &dest)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected application/json")
	assert.Contains(t, err.Error(), "text/html")
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), "Not Found")
}

func TestDecodeJSONResponse_HTMLResponse_LargeBody(t *testing.T) {
	// Body larger than maxErrorBodyPreview should be truncated
	largeHTML := strings.Repeat("<p>lots of content</p>", 100)
	resp := &http.Response{
		StatusCode: 500,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(largeHTML)),
	}

	var dest map[string]string
	err := decodeJSONResponse(resp, &dest)

	require.Error(t, err)
	// The body preview should be capped at maxErrorBodyPreview bytes
	assert.Contains(t, err.Error(), "expected application/json")
	assert.LessOrEqual(t, len(err.Error()), maxErrorBodyPreview+200) // some margin for the error format string
}

func TestDecodeJSONResponse_InvalidJSON_CorrectContentType(t *testing.T) {
	// Server says JSON but sends garbage
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`this is not json`)),
	}

	var dest map[string]string
	err := decodeJSONResponse(resp, &dest)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JSON response")
	assert.Contains(t, err.Error(), "status 200")
	assert.Contains(t, err.Error(), "application/json")
}

func TestDecodeJSONResponse_EmptyContentType(t *testing.T) {
	// No Content-Type header — should attempt JSON decode (permissive)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}

	var dest map[string]any
	err := decodeJSONResponse(resp, &dest)

	assert.NoError(t, err)
	assert.Equal(t, true, dest["ok"])
}

func TestDecodeJSONResponse_EmptyContentType_InvalidJSON(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`<html>oops</html>`)),
	}

	var dest map[string]any
	err := decodeJSONResponse(resp, &dest)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JSON response")
}

// --- buildParResponse unit tests ---

func TestBuildParResponse_Valid(t *testing.T) {
	rmap := map[string]any{
		"expires_in":  float64(299),
		"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
	}

	resp, err := buildParResponse("pkce", "state", "nonce", rmap)

	require.NoError(t, err)
	assert.Equal(t, "pkce", resp.PkceVerifier)
	assert.Equal(t, "state", resp.State)
	assert.Equal(t, "nonce", resp.DpopAuthserverNonce)
	assert.Equal(t, float64(299), resp.ExpiresIn)
	assert.Equal(t, "urn:ietf:params:oauth:request_uri:abc123", resp.RequestUri)
}

func TestBuildParResponse_MissingExpiresIn(t *testing.T) {
	rmap := map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:abc123",
	}

	_, err := buildParResponse("pkce", "state", "nonce", rmap)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expires_in")
}

func TestBuildParResponse_MissingRequestUri(t *testing.T) {
	rmap := map[string]any{
		"expires_in": float64(299),
	}

	_, err := buildParResponse("pkce", "state", "nonce", rmap)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "request_uri")
}

func TestBuildParResponse_WrongTypes(t *testing.T) {
	rmap := map[string]any{
		"expires_in":  "not a number",
		"request_uri": 12345,
	}

	_, err := buildParResponse("pkce", "state", "nonce", rmap)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expires_in")
}

// --- Regression test: simulates the exact error from the issue ---

func TestDecodeJSONResponse_CloudflareHTMLPage(t *testing.T) {
	// This is the exact scenario that produced the confusing error:
	// "invalid character '<' looking for beginning of value"
	// when a misconfigured server returned an HTML page instead of JSON.
	cloudflareHTML := `<!DOCTYPE html>
<html><head><title>Just a moment...</title></head>
<body><h1>Checking your browser before accessing arcnode.xyz</h1></body></html>`

	resp := &http.Response{
		StatusCode: 403,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=UTF-8"}},
		Body:       io.NopCloser(strings.NewReader(cloudflareHTML)),
	}

	var dest map[string]any
	err := decodeJSONResponse(resp, &dest)

	require.Error(t, err)
	// The error should now be descriptive instead of "invalid character '<'"
	assert.Contains(t, err.Error(), "expected application/json")
	assert.Contains(t, err.Error(), "text/html")
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "arcnode.xyz")
	assert.NotContains(t, err.Error(), "invalid character")
}
