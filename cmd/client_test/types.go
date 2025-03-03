package main

type OauthRequest struct {
	ID                  uint
	AuthserverIss       string
	State               string `gorm:"index"`
	Did                 string `gorm:"index"`
	PdsUrl              string
	PkceVerifier        string
	DpopAuthserverNonce string
	DpopPrivateJwk      string
}

type OauthSession struct {
	ID                  uint
	Did                 string `gorm:"uniqueIndex"`
	PdsUrl              string
	AuthserverIss       string
	AccessToken         string
	RefreshToken        string
	DpopPdsNonce        string
	DpopAuthserverNonce string
	DpopPrivateJwk      string
}
