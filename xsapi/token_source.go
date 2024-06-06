package xsapi

import (
	"net/http"
)

type TokenSource interface {
	Token() (Token, error)
}

type Token interface {
	SetAuthHeader(req *http.Request)
}

type DisplayClaims struct {
	GamerTag string `json:"gtg"`
	XUID     string `json:"xid"`
	UserHash string `json:"uhs"`
}

type DisplayClaimer interface {
	DisplayClaims() DisplayClaims
}
