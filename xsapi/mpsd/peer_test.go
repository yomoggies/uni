package mpsd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/pion/ice/v3"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/uni/franchise"
	"github.com/yomoggies/uni/franchise/signaling"
	"github.com/yomoggies/uni/nethernet"
	"github.com/yomoggies/uni/playfab/login"
	"github.com/yomoggies/uni/xsapi/internal/test"
	"github.com/yomoggies/uni/xsapi/xal"
	"golang.org/x/text/language"
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeer(t *testing.T) {
	tok, err := test.ReadTokenSource("../auth.tok", auth.TokenSource)
	if err != nil {
		t.Fatalf("error reading token source: %s", err)
	}
	src := auth.RefreshTokenSource(tok)
	if tok, err = src.Token(); err != nil {
		t.Fatalf("error refreshing token: %s", err)
	}
	// Try to request an auth.XBLToken 4 times with a 5 seconds interval.
	x, err := test.Try(4, time.Second*5, func(int) (*auth.XBLToken, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		defer cancel()
		return auth.RequestXBLToken(ctx, tok, "http://xboxlive.com")
	})
	if err != nil {
		t.Fatalf("error requesting xbox live token: %s", err)
	}

	discovery, err := franchise.Discover("1.20.81")
	if err != nil {
		t.Fatalf("error discoverying: %s", err)
	}

	env, ok := discovery.Environment("signaling", franchise.EnvironmentTypeProduction)
	if !ok {
		t.Fatalf("no environment was found for %q", "signaling")
	}
	var signalingEnv signaling.Environment
	if err := json.Unmarshal(env, &signalingEnv); err != nil {
		t.Fatalf("error decoding environment for %q: %s", "signaling", err)
	}

	signalingDialer := &signaling.Dialer{
		NetworkID: rand.Uint64(),
	}

	name := strings.ToUpper(uuid.NewString())

	displayClaims := x.AuthorizationToken.DisplayClaims.UserInfo[0]
	customProperties, err := json.Marshal(map[string]any{
		"Joinability":             "joinable_by_friends",
		"hostName":                displayClaims.GamerTag,
		"ownerId":                 displayClaims.XUID,
		"rakNetGUID":              "",
		"version":                 "1.20.81",
		"levelId":                 "lhhPZjgNAQA=",
		"worldName":               name,
		"worldType":               "Creative",
		"protocol":                671,
		"MemberCount":             1,
		"MaxMemberCount":          8,
		"BroadcastSetting":        3,
		"LanGame":                 true,
		"isEditorWorld":           false,
		"TransportLayer":          2, // Zero means RakNet, and two means NetherNet.
		"WebRTCNetworkId":         signalingDialer.NetworkID,
		"OnlineCrossPlatformGame": true,
		"CrossPlayDisabled":       false,
		"TitleId":                 0,
		"SupportedConnections": []map[string]any{
			{
				"ConnectionType":  3,
				"HostIpAddress":   "",
				"HostPort":        0,
				"NetherNetId":     signalingDialer.NetworkID,
				"WebRTCNetworkId": signalingDialer.NetworkID,
				"RakNetGUID":      "UNASSIGNED_RAKNET_GUID",
			},
		},
	})
	s, err := PublishConfig{
		Description: &SessionDescription{
			Properties: &SessionProperties{
				System: &SessionPropertiesSystem{
					JoinRestriction: SessionRestrictionFollowed,
					ReadRestriction: SessionRestrictionFollowed,
				},
				Custom: customProperties,
			},
		},
	}.PublishContext(context.Background(), xal.TokenSource(x), SessionReference{
		ServiceConfigID: uuid.MustParse("4fc10100-5f7a-4470-899b-280835760c07"),
		TemplateName:    "MinecraftLobby",
		Name:            name,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("error closing session: %s", err)
		}
	})

	signalingConn, err := signalingDialer.DialContext(context.Background(), tokenConfigSource(func() (*franchise.TokenConfig, error) {
		if tok, err = src.Token(); err != nil {
			return nil, fmt.Errorf("refresh token: %w", err)
		}
		// Try to request an auth.XBLToken 4 times with a 5 seconds interval.
		playfabXBL, err := test.Try(4, time.Second*5, func(int) (*auth.XBLToken, error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
			defer cancel()
			return auth.RequestXBLToken(ctx, tok, "http://playfab.xboxlive.com/")
		})
		if err != nil {
			return nil, fmt.Errorf("request xbox live token: %w", err)
		}
		identity, err := login.Request{
			Title:         playfabTitle,
			CreateAccount: true,
			InfoRequestParameters: &login.RequestParameters{
				PlayerProfile:   true,
				UserAccountInfo: true,
			},
		}.WithXBLToken(playfabXBL).Login()
		if err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}

		fmt.Println("SessionTicket:", strconv.Quote(identity.SessionTicket))
		env, ok := discovery.Environment("auth", franchise.EnvironmentTypeProduction)
		if !ok {
			return nil, fmt.Errorf("no environment found for %q", "auth")
		}
		var authorizationEnv franchise.AuthorizationEnvironment
		if err := json.Unmarshal(env, &authorizationEnv); err != nil {
			return nil, fmt.Errorf("decode environment for %q: %w", "auth", err)
		}
		return &franchise.TokenConfig{
			Device: &franchise.DeviceConfig{
				ApplicationType:    franchise.ApplicationTypeMinecraftPE,
				Capabilities:       []franchise.Capability{franchise.CapabilityRayTracing},
				GameVersion:        "1.20.81",
				ID:                 uuid.New(),
				Memory:             strconv.FormatUint(16849256448, 10),
				Platform:           franchise.PlatformWindows10,
				PlayFabTitleID:     strings.ToUpper(playfabTitle.String()),
				StorePlatform:      franchise.StorePlatformUWPStore,
				TreatmentOverrides: signaling.Treatments,
				Type:               franchise.DeviceTypeWindows10,
			},
			User: &franchise.UserConfig{
				Language:     language.English,
				LanguageCode: language.AmericanEnglish,
				RegionCode:   "US",
				Token:        identity.SessionTicket,
				TokenType:    franchise.TokenTypePlayFab,
			},
			Environment: authorizationEnv,
		}, nil
	}), signalingEnv)
	if err != nil {
		t.Fatalf("error dialing signaling conn: %s", err)
	}

	t.Log(signalingDialer.NetworkID)
	t.Log(name)

	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelDebug
	var setting webrtc.SettingEngine
	setting.LoggerFactory = loggerFactory
	api := webrtc.NewAPI(webrtc.WithSettingEngine(setting))

	_ = api

	for {
		signal, err := signalingConn.ReadSignal()
		if err != nil {
			t.Fatal(err)
		}
		switch signal.Type {
		case nethernet.SignalTypeOffer:
			/*credentials, err := signalingConn.Credentials()
			if err != nil {
				t.Fatal(err)
			}
			gatherOptions := webrtc.ICEGatherOptions{
				ICEServers: make([]webrtc.ICEServer, len(credentials.ICEServers)),
			}
			for i, server := range credentials.ICEServers {
				gatherOptions.ICEServers[i] = webrtc.ICEServer{
					Username:       server.Username,
					Credential:     server.Password,
					CredentialType: webrtc.ICECredentialTypePassword,
					URLs:           server.URLs,
				}
			}
			gatherer, err := api.NewICEGatherer(gatherOptions)
			if err != nil {
				t.Fatal(err)
			}
			var (
				candidates     []*webrtc.ICECandidate
				gatherFinished = make(chan struct{})
			)
			gatherer.OnLocalCandidate(func(candidate *webrtc.ICECandidate) {
				if candidate == nil {
					close(gatherFinished)
					return
				}
				candidates = append(candidates, candidate)
			})
			if err := gatherer.Gather(); err != nil {
				t.Fatal(err)
			}
			<-gatherFinished

			ice := api.NewICETransport(gatherer)
			dtls, err := api.NewDTLSTransport(ice, nil)
			if err != nil {
				t.Fatal(err)
			}
			sctp := api.NewSCTPTransport(dtls)

			d := &sdp.SessionDescription{}
			if err := d.Unmarshal([]byte(signal.Data)); err != nil {
				t.Fatal(err)
			}
			if len(d.MediaDescriptions) != 1 {
				t.Fatalf("unexpected number of media descriptions: %d", len(d.MediaDescriptions))
			}
			media := d.MediaDescriptions[0]

			remoteUfrag, ok := media.Attribute("ice-ufrag")
			if !ok {
				t.Fatalf("missing ice-ufrag attribute")
			}
			remotePwd, ok := media.Attribute("ice-pwd")
			if !ok {
				t.Fatalf("missing ice-pwd attribute")
			}

			fingerprintAlgorithm, fingerprintValue, err := webrtc.ExtractFingerprint(d)
			if err != nil {
				t.Fatalf("extract fingerprint: %s", err)
			}

			attribute, ok := media.Attribute("max-message-size")
			if !ok {
				t.Fatalf("missing max-message-size attribute")
			}
			maxMessageSize, err := strconv.ParseUint(attribute, 10, 32)
			if err != nil {
				t.Fatalf("parse max-message-size attribute: %s", err)
			}

			p := &Peer{
				remoteICEParams: webrtc.ICEParameters{
					UsernameFragment: remoteUfrag,
					Password:         remotePwd,
				},,

				id:        rand.Uint64(),
				networkID: signal.NetworkID,
			}

			// sctpCapabilities := c.sctp.GetCapabilities()
			d = &sdp.SessionDescription{
				Version:               0,
				Origin:                sdp.Origin{Username: "-", SessionID: 0xd7d839b743308e0, SessionVersion: 0x2, NetworkType: "IN", AddressType: "IP4", UnicastAddress: "127.0.0.1"},
				SessionName:           "-",
				SessionInformation:    (*sdp.Information)(nil),
				URI:                   (*url.URL)(nil),
				EmailAddress:          (*sdp.EmailAddress)(nil),
				PhoneNumber:           (*sdp.PhoneNumber)(nil),
				ConnectionInformation: (*sdp.ConnectionInformation)(nil),
				Bandwidth:             nil,
				TimeDescriptions: []sdp.TimeDescription{
					{},
				},
				TimeZones:     nil,
				EncryptionKey: (*sdp.EncryptionKey)(nil),
				Attributes: []sdp.Attribute{
					{Key: "group", Value: "BUNDLE 0"},
					{Key: "extmap-allow-mixed", Value: ""},
					{Key: "msid-semantic", Value: " WMS"},
				},
				MediaDescriptions: []*sdp.MediaDescription{
					&sdp.MediaDescription{
						MediaName: sdp.MediaName{
							Media: "application",
							Port: sdp.RangedPort{
								Value: 9,
								Range: (*int)(nil),
							},
							Protos:  []string{"UDP", "DTLS", "SCTP"},
							Formats: []string{"webrtc-datachannel"},
						},
						MediaTitle: (*sdp.Information)(nil),
						ConnectionInformation: &sdp.ConnectionInformation{
							NetworkType: "IN",
							AddressType: "IP4",
							Address: &sdp.Address{
								Address: "0.0.0.0",
								TTL:     (*int)(nil),
								Range:   (*int)(nil),
							},
						},
						Bandwidth:     nil,
						EncryptionKey: (*sdp.EncryptionKey)(nil),
						Attributes: []sdp.Attribute{
							{Key: "ice-ufrag", Value: localUfrag},
							{Key: "ice-pwd", Value: localPwd},
							{Key: "ice-options", Value: "trickle"},
							{Key: "fingerprint", Value: fmt.Sprintf("%s %s", "sha256", "")},
							{Key: "setup", Value: "active"},
							{Key: "mid", Value: "0"},
							{Key: "sctp-port", Value: "5000"},
							{Key: "max-message-size", Value: "262144"},
						},
					},
				},
			}

			answer, err := d.Marshal()
			if err != nil {
				panic(err)
			}
			if err := signalingConn.WriteSignal(&nethernet.Signal{
				Type:         nethernet.SignalTypeAnswer,
				Data:         string(answer),
				ConnectionID: p.id,
				NetworkID:    p.networkID,
			}); err != nil {
				panic(err)
			}

			for i, candidate := range candidates {
				ic := p.formatICECandidate(i, candidate, localUfrag, localPwd)
				fmt.Println("Local Candidate:", strconv.Quote(ic))
				if err := signalingConn.WriteSignal(&nethernet.Signal{
					Type:         nethernet.SignalTypeCandidate,
					Data:         ic,
					ConnectionID: p.id,
					NetworkID:    p.networkID,
				}); err != nil {
					panic(err)
				}
			}

			connections.Store(signal.ConnectionID, c)*/
		case nethernet.SignalTypeCandidate:
			c, ok := connections.Load(signal.ConnectionID)
			if !ok {
				t.Fatalf("received signal for unknown connection ID: %d", signal.ConnectionID)
			}
			go c.(*Conn).handleSignal(signal)
		}
	}
}

type Peer struct {
	agent *ice.Agent

	remoteICEParams webrtc.ICEParameters

	candidatesReceived atomic.Uint64

	id, networkID uint64
}

func (p *Peer) start() {
	p.agent.Accept(context.Background(), p.remoteICEParams.UsernameFragment, p.remoteICEParams.Password)
}

func (p *Peer) formatICECandidate(networkId int, candidate ice.Candidate, ufrag, pwd string) string {
	sb := strings.Builder{}
	sb.WriteString("candidate:")
	sb.WriteString(candidate.Foundation())
	sb.WriteRune(' ')
	sb.WriteRune('1')
	sb.WriteRune(' ')
	sb.WriteString("udp")
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(int(candidate.Priority())))
	sb.WriteRune(' ')
	sb.WriteString(candidate.Address())
	sb.WriteRune(' ')
	sb.WriteString(strconv.Itoa(int(candidate.Port())))
	sb.WriteRune(' ')
	sb.WriteString("typ")
	sb.WriteRune(' ')
	sb.WriteString(candidate.Type().String())
	sb.WriteRune(' ')
	if candidate.RelatedAddress() != nil {
		sb.WriteString("raddr")
		sb.WriteRune(' ')
		sb.WriteString(candidate.RelatedAddress().Address)
		sb.WriteRune(' ')
		sb.WriteString("rport")
		sb.WriteRune(' ')
		sb.WriteString(strconv.Itoa(candidate.RelatedAddress().Port))
		sb.WriteRune(' ')
	}
	sb.WriteString("generation")
	sb.WriteRune(' ')
	sb.WriteRune('0')
	sb.WriteRune(' ')
	sb.WriteString("ufrag")
	sb.WriteRune(' ')
	sb.WriteString(ufrag)
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

func (p *Peer) handleSignal(sig *nethernet.Signal) {
	i, err := ice.UnmarshalCandidate(sig.Data)
	if err != nil {
		panic(err)
	}
	if err := p.agent.AddRemoteCandidate(i); err != nil {
		panic(err)
	}
	if p.candidatesReceived.Add(1) == 5 {
		p.start()
	}
	fmt.Println(p.candidatesReceived.Load())
}
