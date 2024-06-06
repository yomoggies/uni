package mpsd

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/uni/xsapi/internal/test"
	"github.com/yomoggies/uni/xsapi/xal"
	"strings"
	"testing"
	"time"
)

// TestPublish demonstrates a Minecraft session that is visible
// through the in-game friends list menu.
//
// It publishes a session that has "MinecraftLobby" set to its template name and
// a randomly-generated GUID set to its reference name. The session has both
// [SessionPropertiesSystem.JoinRestriction] and
// [SessionPropertiesSystem.ReadRestriction] set to SessionRestrictionFollowed,
// which means that reading and joining this session requires to be followed
// each-other. Please note that you may not use the same account as used here,
// because the game omits a session that have the same XUID of its logged-in
// account from the friends list.
func TestPublish(t *testing.T) {
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

	displayClaims := x.AuthorizationToken.DisplayClaims.UserInfo[0]
	customProperties, err := json.Marshal(map[string]any{
		"Joinability":             "joinable_by_friends",
		"hostName":                "Yomogi",
		"ownerId":                 displayClaims.XUID,
		"rakNetGUID":              "",
		"version":                 "1.20.81",
		"levelId":                 "lhhPZjgNAQA=",
		"worldName":               "TestPublish",
		"worldType":               "Creative",
		"protocol":                671,
		"MemberCount":             1,
		"MaxMemberCount":          8,
		"BroadcastSetting":        3,
		"LanGame":                 true,
		"isEditorWorld":           false,
		"TransportLayer":          0, // Zero means RakNet, and two means NetherNet.
		"WebRTCNetworkId":         0,
		"OnlineCrossPlatformGame": true,
		"CrossPlayDisabled":       false,
		"TitleId":                 0,
		"SupportedConnections": []map[string]any{
			{
				"ConnectionType": 6,
				// This test has been tested with my friends on a ZeroTier network.
				"HostIpAddress":   "192.168.191.228",
				"HostPort":        19132,
				"NetherNetId":     0,
				"WebRTCNetworkID": 0,
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
		Name:            strings.ToUpper(uuid.NewString()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("error closing session: %s", err)
		}
	})

	// Since tests does not accept any interrupt signals to be notified, we can't
	// tell the actual program to stop the testing, so we need to wait 1 minute to
	// confirm it is published via the friends list menu.
	time.Sleep(time.Hour)
}
