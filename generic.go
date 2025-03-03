package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func GenerateKey(kidPrefix *string) (jwk.Key, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	key, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, err
	}

	var kid string
	if kidPrefix != nil {
		kid = fmt.Sprintf("%s-%d", *kidPrefix, time.Now().Unix())

	} else {
		kid = fmt.Sprintf("%d", time.Now().Unix())
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	return key, nil
}

func isSafeAndParsed(ustr string) (*url.URL, error) {
	u, err := url.Parse(ustr)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("input url is not https")
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("url hostname was empty")
	}

	if u.User != nil {
		return nil, fmt.Errorf("url user was not empty")
	}

	if u.Port() != "" {
		return nil, fmt.Errorf("url port was not empty")
	}

	return u, nil
}

func getPrivateKey(key jwk.Key) (*ecdsa.PrivateKey, error) {
	var pkey ecdsa.PrivateKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	return &pkey, nil
}

func getPublicKey(key jwk.Key) (*ecdsa.PublicKey, error) {
	var pkey ecdsa.PublicKey
	if err := key.Raw(&pkey); err != nil {
		return nil, err
	}

	return &pkey, nil
}

type JwksResponseObject struct {
	Keys []jwk.Key `json:"keys"`
}

func CreateJwksResponseObject(key jwk.Key) *JwksResponseObject {
	return &JwksResponseObject{
		Keys: []jwk.Key{key},
	}
}

func ParseJWKFromBytes(b []byte) (jwk.Key, error) {
	return jwk.ParseKey(b)
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
