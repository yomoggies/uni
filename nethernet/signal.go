package nethernet

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type Signal struct {
	NetworkID uint64

	Type         SignalType
	ConnectionID uint64
	Data         string
}

func (s *Signal) UnmarshalText(b []byte) (err error) {
	segments := bytes.SplitN(b, []byte{' '}, 3)
	if len(segments) < 3 {
		return fmt.Errorf("unexpected segmenations: expected 3, got %d", len(segments))
	}
	s.Type = SignalType(segments[0])
	s.ConnectionID, err = strconv.ParseUint(string(segments[1]), 10, 64)
	if err != nil {
		return fmt.Errorf("parse ConnectionID: %w", err)
	}
	s.Data = string(segments[2])
	return nil
}

func (s *Signal) String() string {
	b := &strings.Builder{}
	b.WriteString(string(s.Type))
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(s.ConnectionID, 10))
	b.WriteByte(' ')
	b.WriteString(s.Data)
	return b.String()
}

type SignalType string

const (
	SignalTypeOffer     SignalType = "CONNECTREQUEST"
	SignalTypeAnswer    SignalType = "CONNECTRESPONSE"
	SignalTypeCandidate SignalType = "CANDIDATEADD"
)

type Signaling interface {
	ReadSignal() (*Signal, error)
	WriteSignal(s *Signal) error
	Credentials() (*Credentials, error)
}

type Credentials struct {
	ICEServers []ICEServer `json:"TurnAuthServers,omitempty"`
}

type ICEServer struct {
	Username string   `json:"Username,omitempty"`
	Password string   `json:"Password,omitempty"`
	URLs     []string `json:"Urls,omitempty"`
}
