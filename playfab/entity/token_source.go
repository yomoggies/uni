package entity

import (
	"context"
	"fmt"
	"github.com/yomoggies/uni/playfab/title"
	"sync"
	"time"
)

type TokenSource interface {
	Token() (*Token, error)
}

func ExchangeTokenSource(ctx context.Context, tok *Token, t title.Title, masterID string) TokenSource {
	src := &exchangeTokenSource{
		tok: tok,

		ctx:      ctx,
		title:    t,
		masterID: masterID,
	}
	go src.background()
	return src
}

// Of course, we can guess the interval for exchanging tokens at background of ExchangeTokenSource from [Token.Expiration]. However, this code only
// considers the behaviour, and the PlayFab SDK included in the GDK used in Minecraft Marketplace also exchanges entity tokens in this way, regardless
// of the token expiration, so we set the same value from the GDK.
const exchangeInterval = time.Minute * 15

type exchangeTokenSource struct {
	tok *Token
	err error

	mux      sync.Mutex
	ctx      context.Context
	title    title.Title
	masterID string
}

func (src *exchangeTokenSource) background() {
	t := time.NewTicker(exchangeInterval) // see the comments above.
	defer t.Stop()
	for {
		select {
		case <-t.C:
			src.mux.Lock()
			src.tok, src.err = src.tok.Exchange(src.title, src.masterID)
			if src.err != nil {
				src.mux.Unlock()
				return
			}
			src.mux.Unlock()
		case <-src.ctx.Done():
			src.mux.Lock()
			src.err = src.ctx.Err()
			src.mux.Unlock()
		}
	}
}

func (src *exchangeTokenSource) Token() (tok *Token, err error) {
	src.mux.Lock()
	defer src.mux.Unlock()
	if src.err != nil {
		return nil, fmt.Errorf("exchange token in background: %w", err)
	}

	if src.tok.Expired() || src.tok.Entity.Type != TypeMasterPlayerAccount {
		tok, err = src.tok.Exchange(src.title, src.masterID)
		if err != nil {
			return nil, fmt.Errorf("exchange: %w", err)
		}
		src.tok = tok
	}
	return src.tok, nil
}
