package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type OauthClient struct {
	h *http.Client
}

type OauthClientArgs struct {
	h *http.Client
}

func NewOauthClient(args OauthClientArgs) *OauthClient {
	if args.h == nil {
		args.h = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	return &OauthClient{
		h: args.h,
	}
}

func (o *OauthClient) ResolvePDSAuthServer(ctx context.Context, ustr string) (string, error) {
	u, err := isSafeAndParsed(ustr)
	if err != nil {
		return "", err
	}

	u.Path = "/.well-known/oauth-protected-resource"

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request for oauth protected resource: %w", err)
	}

	resp, err := o.h.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not get response from server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("received non-200 response from pds. code was %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read body: %w", err)
	}

	var resource OauthProtectedResource
	if err := resource.UnmarshalJSON(b); err != nil {
		return "", fmt.Errorf("could not unmarshal json: %w", err)
	}

	if len(resource.AuthorizationServers) == 0 {
		return "", fmt.Errorf("oauth protected resource contained no authorization servers")
	}

	return resource.AuthorizationServers[0], nil
}

func (o *OauthClient) FetchAuthServerMetadata(ctx context.Context, ustr string) (any, error) {
	u, err := isSafeAndParsed(ustr)
	if err != nil {
		return nil, err
	}

	u.Path = "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to fetch auth metadata: %w", err)
	}

	resp, err := o.h.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting response for auth metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("received non-200 response from pds. status code was %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read body for metadata response: %w", err)
	}

	var metadata OauthAuthorizationMetadata
	if err := metadata.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("could not unmarshal metadata: %w", err)
	}

	if err := metadata.Validate(u); err != nil {
		return nil, fmt.Errorf("could not validate metadata: %w", err)
	}

	return metadata, nil
}

// func ClientAssertionJwt(clientId, authServerUrl string, clientSecretJwk jwk.Key) {
// 	clientAssertion := jwt.NewBuilder().Issuer(clientId).Subject(clientId).Audience(authServerUrl).IssuedAt(time.Now().Add()
// }

func isSafeAndParsed(ustr string) (*url.URL, error) {
	u, err := url.Parse(ustr)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("input url is not https")
	}

	return u, nil
}
