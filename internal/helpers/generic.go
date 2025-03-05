package helpers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func GenerateToken(len int) (string, error) {
	b := make([]byte, len)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func GenerateCodeChallenge(pkceVerifier string) string {
	h := sha256.New()
	h.Write([]byte(pkceVerifier))
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash)
}
