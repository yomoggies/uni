package xal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/uni/xsapi"
	"golang.org/x/oauth2"
	"net/http"
	"sync"
)

func TokenSource(x *auth.XBLToken) xsapi.TokenSource {
	return &tokenSource{x: x}
}

type tokenSource struct {
	x *auth.XBLToken
}

func (t *tokenSource) Token() (xsapi.Token, error) {
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &token{
		XBLToken: t.x,
		key:      sk,
	}, nil
}

func RefreshTokenSource(underlying oauth2.TokenSource, relyingParty string) xsapi.TokenSource {
	return RefreshTokenSourceContext(context.Background(), underlying, relyingParty)
}

func RefreshTokenSourceContext(ctx context.Context, underlying oauth2.TokenSource, relyingParty string) xsapi.TokenSource {
	return &refreshTokenSource{
		ctx:          ctx,
		relyingParty: relyingParty,
		underlying:   underlying,
	}
}

type refreshTokenSource struct {
	ctx          context.Context
	relyingParty string
	underlying   oauth2.TokenSource

	tok *oauth2.Token
	x   *auth.XBLToken
	mu  sync.RWMutex
}

func (t *refreshTokenSource) Token() (_ xsapi.Token, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.tok == nil || !t.tok.Valid() || t.x == nil {
		t.tok, err = t.underlying.Token()
		if err != nil {
			return nil, fmt.Errorf("request underlying token: %w", err)
		}
		t.x, err = auth.RequestXBLToken(t.ctx, t.tok, t.relyingParty)
		if err != nil {
			return nil, fmt.Errorf("request xbox live token: %w", err)
		}
	}
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &token{
		XBLToken: t.x,
		key:      sk,
	}, nil
}

type token struct {
	key *ecdsa.PrivateKey
	*auth.XBLToken
}

func (t *token) SetAuthHeader(req *http.Request) {
	t.XBLToken.SetAuthHeader(req)
}

func (t *token) DisplayClaims() xsapi.DisplayClaims {
	return t.XBLToken.AuthorizationToken.DisplayClaims.UserInfo[0]
}
