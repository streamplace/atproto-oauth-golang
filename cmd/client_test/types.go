package main

type OauthRequest struct {
	ID                  uint
	AuthserverIss       string
	State               string
	Did                 string `gorm:"index"`
	PdsUrl              string
	PkceVerifier        string
	DpopAuthserverNonce string
	DpopPrivateJwk      string
}
