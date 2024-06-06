package login

import (
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/yomoggies/uni/playfab/internal"
	"github.com/yomoggies/uni/playfab/title"
)

type Request struct {
	Title                 title.Title        `json:"TitleId,omitempty"`
	CreateAccount         bool               `json:"CreateAccount,omitempty"`
	CustomTags            map[string]any     `json:"CustomTags,omitempty"`
	EncryptedRequest      []byte             `json:"EncryptedRequest,omitempty"`
	InfoRequestParameters *RequestParameters `json:"InfoRequestParameters,omitempty"`
	PlayerSecret          string             `json:"PlayerSecret,omitempty"`
	XboxToken             string             `json:"XboxToken,omitempty"`

	Route string `json:"-"`
}

type RequestParameters struct {
	CharacterInventories bool               `json:"GetCharacterInventories,omitempty"`
	CharacterList        bool               `json:"GetCharacterList,omitempty"`
	PlayerProfile        bool               `json:"GetPlayerProfile,omitempty"`
	PlayerStatistics     bool               `json:"GetPlayerStatistics,omitempty"`
	TitleData            bool               `json:"GetTitleData,omitempty"`
	UserAccountInfo      bool               `json:"GetUserAccountInfo,omitempty"`
	UserData             bool               `json:"GetUserData,omitempty"`
	UserInventory        bool               `json:"GetUserInventory,omitempty"`
	UserReadOnlyData     bool               `json:"GetUserReadOnlyData,omitempty"`
	UserVirtualCurrency  bool               `json:"GetUserVirtualCurrency,omitempty"`
	PlayerStatisticNames []string           `json:"PlayerStatisticNames,omitempty"`
	ProfileConstraints   ProfileConstraints `json:"ProfileConstraints,omitempty"`
	TitleDataKeys        []string           `json:"TitleDataKeys,omitempty"`
	UserDataKeys         []string           `json:"UserDataKeys,omitempty"`
	UserReadOnlyDataKeys []string           `json:"UserReadOnlyDataKeys,omitempty"`
}

type ProfileConstraints struct {
	ShowAvatarURL                     bool `json:"ShowAvatarUrl,omitempty"`
	ShowBannedUntil                   bool `json:"ShowBannedUntil,omitempty"`
	ShowCampaignAttributions          bool `json:"ShowCampaignAttributions,omitempty"`
	ShowContactEmailAddresses         bool `json:"ShowContactEmailAddresses,omitempty"`
	ShowCreated                       bool `json:"ShowCreated,omitempty"`
	ShowDisplayName                   bool `json:"ShowDisplayName,omitempty"`
	ShowExperimentVariants            bool `json:"ShowExperimentVariants,omitempty"`
	ShowLastLogin                     bool `json:"ShowLastLogin,omitempty"`
	ShowLinkedAccounts                bool `json:"ShowLinkedAccounts,omitempty"`
	ShowLocations                     bool `json:"ShowLocations,omitempty"`
	ShowMemberships                   bool `json:"ShowMemberships,omitempty"`
	ShowOrigination                   bool `json:"ShowOrigination,omitempty"`
	ShowPushNotificationRegistrations bool `json:"ShowPushNotificationRegistrations,omitempty"`
	ShowStatistics                    bool `json:"ShowStatistics,omitempty"`
	ShowTags                          bool `json:"ShowTags,omitempty"`
	ShowTotalValueToDateInUSD         bool `json:"ShowTotalValueToDateInUsd,omitempty"`
	ShowValuesToDate                  bool `json:"ShowValuesToDate,omitempty"`
}

func (r Request) WithXBLToken(x *auth.XBLToken) Request {
	if r.Route == "" {
		r.Route = "/Client/LoginWithXbox"
	}
	r.XboxToken = "XBL3.0 x=" + x.AuthorizationToken.DisplayClaims.UserInfo[0].UserHash + ";" + x.AuthorizationToken.Token
	return r
}

func (r Request) Login() (*Identity, error) {
	if r.Route == "" {
		panic("playfab/login: must provide a method/route")
	}
	return internal.Do[*Identity](r.Title, r.Route, r)
}
