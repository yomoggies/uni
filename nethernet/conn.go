package nethernet

import (
	"fmt"
	"github.com/pion/ice/v3"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
)

type Conn struct {
	ice  *webrtc.ICETransport
	dtls *webrtc.DTLSTransport
	sctp *webrtc.SCTPTransport

	localParams  parameters
	remoteParams parameters

	localCandidates  []*webrtc.ICECandidate
	remoteCandidates atomic.Uint64

	signaling Signaling

	id, networkID uint64

	controlling bool
	log         *slog.Logger
}

func (c *Conn) answer() {
	fingerprint := c.localParams.dtls.Fingerprints[0]
	sctpCapabilities := c.localParams.sctp
	d := sdp.SessionDescription{
		Origin:      sdp.Origin{Username: "-", SessionID: rand.Uint64(), SessionVersion: 0x2, NetworkType: "IN", AddressType: "IP4", UnicastAddress: "127.0.0.1"},
		SessionName: "-",
		TimeDescriptions: []sdp.TimeDescription{
			{},
		},
		Attributes: []sdp.Attribute{
			{Key: "group", Value: "BUNDLE 0"},
			{Key: "extmap-allow-mixed", Value: ""},
			{Key: "msid-semantic", Value: " WMS"},
		},
		MediaDescriptions: []*sdp.MediaDescription{
			{
				MediaName: sdp.MediaName{
					Media: "application",
					Port: sdp.RangedPort{
						Value: 9,
					},
					Protos:  []string{"UDP", "DTLS", "SCTP"},
					Formats: []string{"webrtc-datachannel"},
				},
				ConnectionInformation: &sdp.ConnectionInformation{
					NetworkType: "IN",
					AddressType: "IP4",
					Address: &sdp.Address{
						Address: "0.0.0.0",
					},
				},
				Attributes: []sdp.Attribute{
					{Key: "ice-ufrag", Value: c.localParams.ice.UsernameFragment},
					{Key: "ice-pwd", Value: c.localParams.ice.Password},
					{Key: "ice-options", Value: "trickle"},
					{Key: "fingerprint", Value: fmt.Sprintf("%s %s", fingerprint.Algorithm, fingerprint.Value)},
					{Key: "setup", Value: "active"},
					{Key: "mid", Value: "0"},
					{Key: "sctp-port", Value: "5000"},
					{Key: "max-message-size", Value: strconv.Itoa(int(sctpCapabilities.MaxMessageSize))},
				},
			},
		},
	}

	answer, err := d.Marshal()
	if err != nil {
		panic(err)
	}

	if err := c.signaling.WriteSignal(&Signal{
		Type:         SignalTypeAnswer,
		ConnectionID: c.id,
		Data:         string(answer),
		NetworkID:    c.networkID,
	}); err != nil {
		panic(err)
	}

	for i, candidate := range c.localCandidates {
		if err := c.signaling.WriteSignal(&Signal{
			Type:         SignalTypeCandidate,
			ConnectionID: c.id,
			Data:         formatICECandidate(i, *candidate, c.localParams.ice),
			NetworkID:    c.networkID,
		}); err != nil {
			panic(err)
		}
	}

	fmt.Println("starting ICE transport")
	if err := c.ice.Start(nil, c.remoteParams.ice, nil); err != nil {
		panic(err)
	}
	fmt.Println("started ICE transport")
}

func (c *Conn) handleSignal(sig *Signal) {
	if sig.Type != SignalTypeCandidate {
		return
	}
	ic, err := ice.UnmarshalCandidate(sig.Data)
	if err != nil {
		c.log.Error("error decoding candidate", "err", err)
		return
	}
	if err := c.ice.AddRemoteCandidate(&webrtc.ICECandidate{
		Foundation:     ic.Foundation(),
		Priority:       ic.Priority(),
		Address:        ic.Address(),
		Protocol:       webrtc.ICEProtocolUDP,
		Port:           uint16(ic.Port()),
		Typ:            webrtc.ICECandidateType(ic.Type()),
		Component:      ic.Component(),
		RelatedAddress: ic.RelatedAddress().Address,
		RelatedPort:    uint16(ic.RelatedAddress().Port),
		TCPType:        ic.TCPType().String(),
	}); err != nil {
		c.log.Error("error adding remote candidate", "err", err)
		return
	}
	if c.remoteCandidates.Add(1) == 5 && !c.controlling {
		c.answer()
	}
	fmt.Println("remoteCandidates:", c.remoteCandidates.Load())
}

type parameters struct {
	ice  webrtc.ICEParameters
	dtls webrtc.DTLSParameters
	sctp webrtc.SCTPCapabilities
}

func formatICECandidate(networkId int, candidate webrtc.ICECandidate, iceParams webrtc.ICEParameters) string {
	sb := strings.Builder{}
	sb.WriteString("candidate:")
	sb.WriteString(candidate.Foundation)
	sb.WriteRune(' ')
	sb.WriteRune('1')
	sb.WriteRune(' ')
	sb.WriteString("udp")
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(int(candidate.Priority)))
	sb.WriteRune(' ')
	sb.WriteString(candidate.Address)
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(int(candidate.Port)))
	sb.WriteRune(' ')
	sb.WriteString("typ")
	sb.WriteRune(' ')
	sb.WriteString(candidate.Typ.String())
	sb.WriteRune(' ')
	if candidate.Typ == webrtc.ICECandidateTypeRelay || candidate.Typ == webrtc.ICECandidateTypeSrflx {
		sb.WriteString("raddr")
		sb.WriteRune(' ')
		sb.WriteString(candidate.RelatedAddress)
		sb.WriteRune(' ')
		sb.WriteString("rport")
		sb.WriteRune(' ')
		sb.WriteString(strconv.Itoa(int(candidate.RelatedPort)))
		sb.WriteRune(' ')
	}
	sb.WriteString("generation")
	sb.WriteRune(' ')
	sb.WriteRune('0')
	sb.WriteRune(' ')
	sb.WriteString("ufrag")
	sb.WriteRune(' ')
	sb.WriteString(iceParams.UsernameFragment)
	sb.WriteRune(' ')
	sb.WriteString("network-id")
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(networkId))
	sb.WriteRune(' ')
	sb.WriteString("network-cost")
	sb.WriteRune(' ')
	sb.WriteRune('0') // TODO: Actually calculate this?
	return sb.String()
}
