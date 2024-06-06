package signaling

import (
	"context"
	"fmt"
	"github.com/yomoggies/uni/franchise"
	"github.com/yomoggies/uni/nethernet"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"nhooyr.io/websocket"
	"path"
	"strconv"
)

type Dialer struct {
	Options *websocket.DialOptions
	Logger  *slog.Logger

	NetworkID uint64
}

func (d *Dialer) DialContext(ctx context.Context, src franchise.TokenConfigSource, env Environment) (*Conn, error) {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Options == nil {
		d.Options = &websocket.DialOptions{}
	}
	if d.Options.HTTPHeader == nil {
		d.Options.HTTPHeader = make(http.Header)
	}
	if d.NetworkID == 0 {
		d.NetworkID = rand.Uint64()
	}

	cfg, err := src.TokenConfig()
	if err != nil {
		return nil, fmt.Errorf("request token config: %w", err)
	}
	tok, err := cfg.Token()
	if err != nil {
		return nil, fmt.Errorf("request token: %w", err)
	}
	fmt.Println(strconv.Quote(tok.AuthorizationHeader))

	d.Options.HTTPHeader.Set("Authorization", tok.AuthorizationHeader)

	u, err := url.Parse(env.ServiceURI)
	if err != nil {
		return nil, fmt.Errorf("parse service URI: %w", err)
	}
	u.Path = path.Join("/ws/v1.0/signaling/", strconv.FormatUint(d.NetworkID, 10))
	c, resp, err := websocket.Dial(ctx, u.String(), d.Options)
	if err != nil {
		return nil, err
	}
	fmt.Println("WebSocket responded with", resp.Status)

	read, cancel := context.WithCancelCause(context.Background())
	conn := &Conn{
		conn:    c,
		log:     d.Logger,
		signals: make(chan *nethernet.Signal),
		ctx:     read,
	}
	go conn.read(cancel)
	go conn.ping()

	return conn, nil
}

type Environment struct {
	ServiceURI string `json:"serviceUri,omitempty"`
	StunURI    string `json:"stunUri,omitempty"`
	TurnURI    string `json:"turnUri,omitempty"`
}

var Treatments = []string{"mc-signaling-usewebsockets", "mc-signaling-useturn"}
