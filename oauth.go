package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type OauthClient struct {
	h                *http.Client
	clientPrivateKey *ecdsa.PrivateKey
	clientKid        string
	clientId         string
	redirectUri      string
}

type OauthClientArgs struct {
	H           *http.Client
	ClientJwk   []byte
	ClientId    string
	RedirectUri string
}

func NewOauthClient(args OauthClientArgs) (*OauthClient, error) {
	if args.ClientId == "" {
		return nil, fmt.Errorf("no client id provided")
	}

	if args.RedirectUri == "" {
		return nil, fmt.Errorf("no redirect uri provided")
	}

	if args.H == nil {
		args.H = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	clientJwk, err := jwk.ParseKey(args.ClientJwk)
	if err != nil {
		return nil, err
	}

	clientPkey, err := getPrivateKey(clientJwk)
	if err != nil {
		return nil, fmt.Errorf("could not load private key from provided client jwk: %w", err)
	}

	kid := clientJwk.KeyID()

	return &OauthClient{
		h:                args.H,
		clientKid:        kid,
		clientPrivateKey: clientPkey,
		clientId:         args.ClientId,
		redirectUri:      args.RedirectUri,
	}, nil
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

func (o *OauthClient) ClientAssertionJwt(authServerUrl string) (string, error) {
	claims := jwt.MapClaims{
		"iss": o.clientId,
		"sub": o.clientId,
		"aud": authServerUrl,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = o.clientKid

	tokenString, err := token.SignedString(o.clientPrivateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (o *OauthClient) AuthServerDpopJwt(method, url, nonce string, privateJwk jwk.Key) (string, error) {
	raw, err := jwk.PublicKeyOf(privateJwk)
	if err != nil {
		return "", err
	}

	pubJwk, err := jwk.FromRaw(raw)
	if err != nil {
		return "", err
	}

	b, err := json.Marshal(pubJwk)
	if err != nil {
		return "", err
	}

	var pubMap map[string]interface{}
	if err := json.Unmarshal(b, &pubMap); err != nil {
		return "", err
	}

	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"jti": uuid.NewString(),
		"htm": method,
		"htu": url,
		"iat": now,
		"exp": now + 30,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["alg"] = "ES256"
	token.Header["jwk"] = pubMap

	var rawKey interface{}
	if err := privateJwk.Raw(&rawKey); err != nil {
		return "", err
	}

	tokenString, err := token.SignedString(rawKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (o *OauthClient) SendParAuthRequest(ctx context.Context, authServerUrl string, authServerMeta *OauthAuthorizationMetadata, loginHint, scope string, dpopPrivateKey jwk.Key) (any, error) {
	if authServerMeta == nil {
		return nil, fmt.Errorf("nil metadata provided")
	}

	parUrl := authServerMeta.PushedAuthorizationRequestEndpoint

	state, err := generateToken(10)
	if err != nil {
		return nil, fmt.Errorf("could not generate state token: %w", err)
	}

	pkceVerifier, err := generateToken(48)
	if err != nil {
		return nil, fmt.Errorf("could not generate pkce verifier: %w", err)
	}

	codeChallenge := generateCodeChallenge(pkceVerifier)
	codeChallengeMethod := "S256"

	clientAssertion, err := o.ClientAssertionJwt(authServerUrl)
	if err != nil {
		return nil, err
	}

	// TODO: ??
	nonce := ""
	dpopProof, err := o.AuthServerDpopJwt("POST", parUrl, nonce, dpopPrivateKey)
	if err != nil {
		return nil, err
	}

	parBody := map[string]string{
		"response_type":         "code",
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
		"client_id":             o.clientId,
		"state":                 state,
		"redirect_uri":          o.redirectUri,
		"scope":                 scope,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      clientAssertion,
	}

	if loginHint != "" {
		parBody["login_hint"] = loginHint
	}

	_, err = isSafeAndParsed(parUrl)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(parBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", parUrl, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("DPoP", dpopProof)

	return nil, nil
}

func generateToken(len int) (string, error) {
	b := make([]byte, len)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func generateCodeChallenge(pkceVerifier string) string {
	h := sha256.New()
	h.Write([]byte(pkceVerifier))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}
