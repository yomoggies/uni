package mpsd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	ice2 "github.com/pion/ice/v3"
	"github.com/pion/logging"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/uni/franchise"
	"github.com/yomoggies/uni/franchise/signaling"
	"github.com/yomoggies/uni/nethernet"
	"github.com/yomoggies/uni/playfab/entity"
	"github.com/yomoggies/uni/playfab/login"
	"github.com/yomoggies/uni/xsapi/internal/test"
	"golang.org/x/text/language"
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestNetherNet(t *testing.T) {
	tok, err := test.ReadTokenSource("../auth.tok", auth.TokenSource)
	if err != nil {
		t.Fatalf("error reading token source: %s", err)
	}
	src := auth.RefreshTokenSource(tok)
	if tok, err = src.Token(); err != nil {
		t.Fatalf("error refreshing token: %s", err)
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

	signalingDialer := signaling.Dialer{}
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
		}.WithXBLToken(playfabXBL).Login()
		if err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}
		master, err := entity.ExchangeTokenSource(
			context.Background(), identity.EntityToken, playfabTitle, identity.PlayFabID,
		).Token()
		if err != nil {
			return nil, fmt.Errorf("exchange entity token: %w", err)
		}
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
				ApplicationType: franchise.ApplicationTypeMinecraftPE,
				Capabilities:    []franchise.Capability{franchise.CapabilityRayTracing},
				GameVersion:     "1.20.81",
				ID:              uuid.New(),
				Memory:          strconv.FormatUint(rand.Uint64(), 10),
				Platform:        franchise.PlatformWindows10,
				PlayFabTitleID:  playfabTitle.String(),
				StorePlatform:   franchise.StorePlatformUWPStore,
				TreatmentOverrides: []string{
					"mc-sunsetting_1",
					"mc-disable-legacypatchnotes",
					"mc-oneds-prod",
					"mc-nps-spender-free240402",
					"mc-enable-feedback-landing-page",
					"mc-aatest-evergreencf",
					"mc-rp-hero-row-timer-6",
					"mc-persona-realms",
					"mc-en-ic",
					"mc-maelstrom-disable",
					"mc-reco-mbc_p400_20240514",
					"mc-store-new-morebycreator-exp2",
					"mc-pf-retry-enabled",
					"mc-signaling-useturn",
					"mc-rp-morelicensedsidebar",
					"mc-rp-icons",
					"mc-15-year-giveaway-2024",
					"mc-enable-service-entitlements-manager",
					"mcmktvlt-offerids-recos_lgbm3c",
					"mc-signaling-usewebsockets",
					"mc-rp-en15yraddon",
					"mc-reco-algo13_p200_20240424",
				},
				Type: franchise.DeviceTypeWindows10,
			},
			User: &franchise.UserConfig{
				Language:     language.English,
				LanguageCode: language.AmericanEnglish,
				RegionCode:   "US",
				Token:        master.Token,
				TokenType:    franchise.TokenTypePlayFab,
			},
			Environment: authorizationEnv,
		}, nil
	}), signalingEnv)
	if err != nil {
		t.Fatalf("error dialing signaling conn: %s", err)
	}

	time.Sleep(time.Second)

	credentials, err := signalingConn.Credentials()
	if err != nil {
		t.Fatal(err)
	}

	loggerFactory := logging.NewDefaultLoggerFactory()
	loggerFactory.DefaultLogLevel = logging.LogLevelDebug
	var setting webrtc.SettingEngine
	setting.LoggerFactory = loggerFactory
	api := webrtc.NewAPI(webrtc.WithSettingEngine(setting))

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
		gatherFinished = make(chan struct{})
		candidates     []*webrtc.ICECandidate
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

	iceParams, err := ice.GetLocalParameters()
	if err != nil {
		t.Fatal(err)
	}
	dtlsParams, err := dtls.GetLocalParameters()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := dtlsParams.Fingerprints[0]
	sctpCapabilities := sctp.GetCapabilities()

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
					{Key: "ice-ufrag", Value: iceParams.UsernameFragment},
					{Key: "ice-pwd", Value: iceParams.Password},
					{Key: "ice-options", Value: "trickle"},
					{Key: "fingerprint", Value: fmt.Sprintf("%s %s", fingerprint.Algorithm, fingerprint.Value)},
					{Key: "setup", Value: "actpass"},
					{Key: "mid", Value: "0"},
					{Key: "sctp-port", Value: "5000"},
					{Key: "max-message-size", Value: strconv.Itoa(int(sctpCapabilities.MaxMessageSize))},
				},
			},
		},
	}

	offer, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var (
		networkID uint64 = 14372200213826914901
		connID           = rand.Uint64()
	)
	if err := signalingConn.WriteSignal(&nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		Data:         string(offer),
		ConnectionID: connID,
		NetworkID:    networkID,
	}); err != nil {
		t.Fatal(err)
	}

	for i, candidate := range candidates {
		if err := signalingConn.WriteSignal(&nethernet.Signal{
			Type:         nethernet.SignalTypeCandidate,
			Data:         formatICECandidate(i, *candidate, iceParams),
			ConnectionID: connID,
			NetworkID:    networkID,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var (
		remoteICEParams        webrtc.ICEParameters
		remoteDTLSParams       webrtc.DTLSParameters
		remoteSCTPCapabilities webrtc.SCTPCapabilities

		candidatesReceived uint32
	)

	for {
		signal, err := signalingConn.ReadSignal()
		if err != nil {
			t.Fatal(err)
		}
		switch signal.Type {
		case nethernet.SignalTypeAnswer:
			d := &sdp.SessionDescription{}
			if err := d.Unmarshal([]byte(signal.Data)); err != nil {
				t.Fatal(err)
			}
			if len(d.MediaDescriptions) != 1 {
				t.Fatalf("unexpected number of media descriptions: %d", len(d.MediaDescriptions))
			}
			media := d.MediaDescriptions[0]

			remoteICEParams.UsernameFragment, ok = media.Attribute("ice-ufrag")
			if !ok {
				t.Fatalf("missing ice-ufrag attribute")
			}
			remoteICEParams.Password, ok = media.Attribute("ice-pwd")
			if !ok {
				t.Fatalf("missing ice-pwd attribute")
			}

			fingerprintValue, fingerprintAlgorithm, err := webrtc.ExtractFingerprint(d)
			if err != nil {
				t.Fatalf("extract fingerprint: %s", err)
			}

			remoteDTLSParams.Fingerprints = append(remoteDTLSParams.Fingerprints, webrtc.DTLSFingerprint{
				Algorithm: fingerprintAlgorithm,
				Value:     fingerprintValue,
			})

			attribute, ok := media.Attribute("max-message-size")
			if !ok {
				t.Fatalf("missing max-message-size attribute")
			}
			maxMessageSize, err := strconv.ParseUint(attribute, 10, 32)
			if err != nil {
				t.Fatalf("parse max-message-size attribute: %s", err)
			}
			remoteSCTPCapabilities.MaxMessageSize = uint32(maxMessageSize)
		case nethernet.SignalTypeCandidate:
			candidate, err := ice2.UnmarshalCandidate(signal.Data)
			if err != nil {
				t.Fatal(err)
			}
			i, err := webrtc.NewICECandidateFromICE(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := ice.AddRemoteCandidate(&i); err != nil {
				t.Fatal(err)
			}
			candidatesReceived++
			if candidatesReceived == 5 {
				t.Log("starting ICE transport")
				role := webrtc.ICERoleControlling
				if err := ice.Start(nil, remoteICEParams, &role); err != nil {
					t.Fatal(err)
				}
				t.Log("started ICE transport")
				remoteDTLSParams.Role = webrtc.DTLSRoleClient
				if err := dtls.Start(remoteDTLSParams); err != nil {
					t.Fatal(err)
				}
				t.Log("started DTLS transport")
				if err := sctp.Start(remoteSCTPCapabilities); err != nil {
					t.Fatal(err)
				}
				t.Fatal("started SCTP transport")
			}
		}
	}
}
