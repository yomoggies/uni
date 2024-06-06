package rta

import (
	"context"
	"encoding/json"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/uni/xsapi/internal/test"
	"github.com/yomoggies/uni/xsapi/xal"
	"golang.org/x/oauth2"
	"nhooyr.io/websocket"
	"testing"
	"time"
)

func TestConn_Reconnect(t *testing.T) {
	_, _, conn := testDial(t)
	sub := testSubscribe(t, conn, "https://sessiondirectory.xboxlive.com/connections/")
	sub.Handle(&subscriptionHandler{t})
	_ = conn.conn.Close(websocket.StatusBadGateway, "")
}

type subscriptionHandler struct{ *testing.T }

func (h subscriptionHandler) HandleEvent(custom json.RawMessage) {
	h.T.Logf("subscriptionHandler: HandleEvent(%s)", custom)
}

func (h subscriptionHandler) HandleReconnect(c *Conn) {
	h.T.Logf("subscriptionHandler: HandleReconnect(%p)", c)
}

func TestConn_Subscribe(t *testing.T) {
	_, _, conn := testDial(t)
	testSubscribe(t, conn, "https://sessiondirectory.xboxlive.com/connections/")
}

func testSubscribe(t *testing.T, conn *Conn, resourceURI string) *Subscription {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	sub, err := conn.Subscribe(ctx, resourceURI)
	if err != nil {
		t.Fatalf("error subscribing with %s: %s", resourceURI, err)
	}
	t.Logf("subscription: id: %d", sub.ID)
	t.Logf("subscription: custom: %s", sub.Custom)
	return sub
}

func TestDial(t *testing.T) { testDial(t) }

func testDial(t *testing.T) (*oauth2.Token, *auth.XBLToken, *Conn) {
	tok, err := test.ReadTokenSource("../auth.tok", auth.TokenSource)
	if err != nil {
		t.Fatalf("error reading token source: %s", err)
	}
	src := auth.RefreshTokenSource(tok)
	if tok, err = src.Token(); err != nil {
		t.Fatalf("error refreshing token: %s", err)
	}
	x, err := test.Try(4, time.Second*5, func(int) (*auth.XBLToken, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		defer cancel()
		return auth.RequestXBLToken(ctx, tok, "http://xboxlive.com")
	})
	if err != nil {
		t.Fatalf("error requesting xbox live token: %s", err)
	}
	conn, err := Dialer{}.DialContext(context.Background(), xal.TokenSource(x))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("error closing connection: %s", err)
		}
	})
	return tok, x, conn
}
