package signaling

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yomoggies/uni/nethernet"
	"log/slog"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
	"strconv"
	"sync/atomic"
	"time"
)

type Conn struct {
	conn *websocket.Conn

	signals chan *nethernet.Signal
	ctx     context.Context

	credentials atomic.Pointer[nethernet.Credentials]

	log *slog.Logger
}

func (c *Conn) ping() {
	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b, err := json.Marshal(&Message{
				Type: MessageTypePing,
			})
			_ = err
			fmt.Println("Ping", string(b))
			if err := wsjson.Write(context.Background(), c.conn, &Message{
				Type: MessageTypePing,
			}); err != nil {
				c.log.Error("error writing ping", "err", err)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Conn) read(cancel context.CancelCauseFunc) {
	for {
		var message Message
		if err := wsjson.Read(context.Background(), c.conn, &message); err != nil {
			cancel(err)
			return
		}
		fmt.Println("WebSocket", message.Data)
		switch message.Type {
		case MessageTypeSignal:
			s := &nethernet.Signal{}
			if err := s.UnmarshalText([]byte(message.Data)); err != nil {
				c.log.Error("error decoding signal", "err", err)
				continue
			}
			var err error
			s.NetworkID, err = strconv.ParseUint(message.From, 10, 64)
			if err != nil {
				c.log.Error("error parsing recipient ConnectionID", "err", err)
			}
			c.signals <- s
		case MessageTypeCredentials:
			if message.From != "Server" {
				c.log.Error("received credentials from non-server")
				continue
			}
			var credentials nethernet.Credentials
			if err := json.Unmarshal([]byte(message.Data), &credentials); err != nil {
				c.log.Error("error decoding credentials", "err", err)
				continue
			}
			c.credentials.Store(&credentials)
		default:
			c.log.Error("received message with unknown type", "type", message.Type, "sender", message.From, "data", message.Data)
		}
	}
}

func (c *Conn) ReadSignal() (*nethernet.Signal, error) {
	select {
	case s := <-c.signals:
		return s, nil
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

func (c *Conn) WriteSignal(s *nethernet.Signal) error {
	return wsjson.Write(context.Background(), c.conn, &Message{
		Type: MessageTypeSignal,
		To:   json.Number(strconv.FormatUint(s.NetworkID, 10)),
		Data: s.String(),
	})
}

func (c *Conn) Credentials() (*nethernet.Credentials, error) {
	if c.ctx.Err() != nil {
		return nil, context.Cause(c.ctx)
	}
	return c.credentials.Load(), nil
}

type Message struct {
	Type MessageType `json:"Type"`
	To   json.Number `json:"To,omitempty"`
	From string      `json:"From,omitempty"`
	Data string      `json:"Message,omitempty"`
}

type MessageType uint32

const (
	MessageTypePing MessageType = iota
	MessageTypeSignal
	MessageTypeCredentials
)
