package login

import (
	"encoding/json"
	"github.com/yomoggies/uni/playfab/entity"
	"github.com/yomoggies/uni/playfab/title"
	"time"
)

type Identity struct {
	EntityToken         *entity.Token       `json:"EntityToken,omitempty"`
	ResponseParameters  ResponseParameters  `json:"InfoResultPayload,omitempty"`
	LastLoginTime       time.Time           `json:"LastLoginTime,omitempty"`
	NewlyCreated        bool                `json:"NewlyCreated,omitempty"`
	PlayFabID           string              `json:"PlayFabId,omitempty"`
	SessionTicket       string              `json:"SessionTicket,omitempty"`
	SettingsForUser     UserSettings        `json:"SettingsForUser,omitempty"`
	TreatmentAssignment TreatmentAssignment `json:"TreatmentAssignment,omitempty"`
}

type ResponseParameters struct {
	Account                         UserAccount                 `json:"AccountInfo,omitempty"`
	CharacterInventories            []CharacterInventory        `json:"CharacterInventories,omitempty"`
	CharacterList                   []Character                 `json:"CharacterList,omitempty"`
	PlayerProfile                   PlayerProfile               `json:"PlayerProfile,omitempty"`
	PlayerStatistics                []StatisticValue            `json:"PlayerStatistics,omitempty"`
	TitleData                       map[string]json.RawMessage  `json:"TitleData,omitempty"`
	UserData                        UserDataRecord              `json:"UserData,omitempty"`
	UserDataVersion                 int                         `json:"UserDataVersion,omitempty"`
	UserInventory                   []ItemInstance              `json:"UserInventory,omitempty"`
	UserReadOnlyData                UserDataRecord              `json:"UserReadOnlyData,omitempty"`
	UserReadOnlyDataVersion         int                         `json:"UserReadOnlyDataVersion,omitempty"`
	UserVirtualCurrency             map[string]json.RawMessage  `json:"UserVirtualCurrency,omitempty"`
	UserVirtualCurrencyRechargeTime VirtualCurrencyRechargeTime `json:"UserVirtualCurrencyRechargeTimes"`
}

type UserAccount struct {
	AndroidDevice          UserAndroidDevice          `json:"AndroidDeviceInfo,omitempty"`
	AppleAccount           UserAppleAccount           `json:"AppleAccountInfo,omitempty"`
	Created                time.Time                  `json:"Created,omitempty"`
	CustomID               UserCustomID               `json:"CustomIdInfo,omitempty"`
	Facebook               UserFacebook               `json:"FacebookInfo,omitempty"`
	FacebookInstantGamesID UserFacebookInstantGamesID `json:"FacebookInstantGamesIdInfo,omitempty"`
	GameCenter             UserGameCenter             `json:"GameCenterInfo,omitempty"`
	Google                 UserGoogle                 `json:"GoogleInfo,omitempty"`
	GooglePlayGames        UserGooglePlayGames        `json:"GooglePlayGamesInfo,omitempty"`
	IOSDevice              UserIOSDevice              `json:"IosDeviceInfo,omitempty"`
	Kongregate             UserKongregate             `json:"KongregateInfo,omitempty"`
	NintendoSwitchAccount  UserNintendoSwitchAccount  `json:"NintendoSwitchAccountInfo,omitempty"`
	NintendoSwitchDeviceID UserNintendoSwitchDeviceID `json:"NintendoSwitchDeviceIdInfo,omitempty"`
	OpenID                 UserOpenID                 `json:"OpenIdInfo,omitempty"`
	PlayFabID              string                     `json:"PlayFabId,omitempty"`
	Private                UserPrivate                `json:"PrivateInfo,omitempty"`
	PSN                    UserPSN                    `json:"PsnInfo,omitempty"`
	Steam                  UserSteam                  `json:"SteamInfo,omitempty"`
	Title                  UserTitle                  `json:"TitleInfo,omitempty"`
	Twitch                 UserTwitch                 `json:"TwitchInfo,omitempty"`
	Username               string                     `json:"Username,omitempty"`
	Xbox                   UserXbox                   `json:"Xbox,omitempty"`
}

type UserAndroidDevice struct {
	DeviceID string `json:"AndroidDeviceId,omitempty"`
}

type UserAppleAccount struct {
	SubjectID string `json:"AppleSubjectId,omitempty"`
}

type UserCustomID struct {
	ID string `json:"CustomId,omitempty"`
}

type UserFacebook struct {
	ID       string `json:"FacebookId,omitempty"`
	FullName string `json:"FullName,omitempty"`
}

type UserFacebookInstantGamesID struct {
	ID string `json:"FacebookInstantGamesId,omitempty"`
}

type UserGameCenter struct {
	ID string `json:"GameCenterId,omitempty"`
}

type UserGoogle struct {
	Email  string `json:"GoogleEmail,omitempty"`
	Gender string `json:"GoogleGender,omitempty"`
	ID     string `json:"GoogleId,omitempty"`
	Locale string `json:"GoogleLocale,omitempty"`
	Name   string `json:"GoogleName,omitempty"`
}

type UserGooglePlayGames struct {
	PlayerAvatarImageURL string `json:"GooglePlayGamesPlayerAvatarImageUrl,omitempty"`
	PlayerDisplayName    string `json:"GooglePlayGamesPlayerDisplayName,omitempty"`
	PlayerID             string `json:"GooglePlayGamesPlayerId,omitempty"`
}

type UserIOSDevice struct {
	ID string `json:"IosDeviceId,omitempty"`
}

type UserKongregate struct {
	ID   string `json:"KongregateId,omitempty"`
	Name string `json:"KongregateName,omitempty"`
}

type UserNintendoSwitchAccount struct {
	SubjectID string `json:"NintendoSwitchAccountSubjectId,omitempty"`
}

type UserNintendoSwitchDeviceID struct {
	ID string `json:"NintendoSwitchDeviceId,omitempty"`
}

type UserOpenID struct {
	ConnectionID string `json:"ConnectionId,omitempty"`
	Issuer       string `json:"Issuer,omitempty"`
	Subject      string `json:"Subject,omitempty"`
}

type UserPrivate struct {
	Email string `json:"Email,omitempty"`
}

type UserPSN struct {
	AccountID string `json:"PsnAccountId,omitempty"`
	OnlineID  string `json:"PsnOnlineId,omitempty"`
}

type UserSteam struct {
	ActivationStatus TitleActivationStatus `json:"SteamActivationStatus,omitempty"`
	Country          string                `json:"SteamCountry,omitempty"`
	Currency         string                `json:"Currency,omitempty"` // TODO: Currency enum?
	ID               string                `json:"SteamId,omitempty"`
	Name             string                `json:"SteamName,omitempty"`
}

type TitleActivationStatus string

const (
	TitleActivationStatusActivatedSteam    TitleActivationStatus = "ActivatedSteam"
	TitleActivationStatusActivatedTitleKey TitleActivationStatus = "ActivatedTitleKey"
	TitleActivationStatusNone              TitleActivationStatus = "None"
	TitleActivationStatusPendingSteam      TitleActivationStatus = "PendingSteam"
	TitleActivationStatusRevokedSteam      TitleActivationStatus = "RevokedSteam"
)

type UserTitle struct {
	AvatarURL          string          `json:"AvatarUrl,omitempty"`
	Created            time.Time       `json:"Created,omitempty"`
	DisplayName        string          `json:"DisplayName,omitempty"`
	FirstLogin         time.Time       `json:"FirstLogin,omitempty"`
	LastLogin          time.Time       `json:"LastLogin,omitempty"`
	Origination        UserOrigination `json:"Origination,omitempty"`
	TitlePlayerAccount entity.Key      `json:"TitlePlayerAccount,omitempty"`
	Banned             bool            `json:"isBanned,omitempty"`
}

type UserOrigination string

const (
	UserOriginationAmazon                 UserOrigination = "Amazon"
	UserOriginationAndroid                UserOrigination = "Android"
	UserOriginationApple                  UserOrigination = "Apple"
	UserOriginationCustomID               UserOrigination = "CustomId"
	UserOriginationFacebook               UserOrigination = "Facebook"
	UserOriginationFacebookInstantGamesID UserOrigination = "FacebookInstantGamesId"
	UserOriginationGameCenter             UserOrigination = "GameCenter"
	UserOriginationGamersFirst            UserOrigination = "GamersFirst"
	UserOriginationGoogle                 UserOrigination = "Google"
	UserOriginationGooglePlayGames        UserOrigination = "GooglePlayGames"
	UserOriginationIOS                    UserOrigination = "IOS"
	UserOriginationKongregate             UserOrigination = "Kongregate"
	UserOriginationLoadTest               UserOrigination = "LoadTest"
	UserOriginationNintendoSwitchAccount  UserOrigination = "NintendoSwitchAccount"
	UserOriginationNintendoSwitchDeviceID UserOrigination = "NintendoSwitchDeviceID"
	UserOriginationOpenIDConnect          UserOrigination = "OpenIdConnect"
	UserOriginationOrganic                UserOrigination = "Organic"
	UserOriginationPSN                    UserOrigination = "PSN"
	UserOriginationParse                  UserOrigination = "Parse"
	UserOriginationServerCustomID         UserOrigination = "ServerCustomId"
	UserOriginationSteam                  UserOrigination = "Steam"
	UserOriginationTwitch                 UserOrigination = "Twitch"
	UserOriginationUnknown                UserOrigination = "Unknown"
	UserOriginationXboxLive               UserOrigination = "XboxLive"
)

type UserTwitch struct {
	ID       string `json:"TwitchId,omitempty"`
	UserName string `json:"TwitchUserName,omitempty"`
}

type UserXbox struct {
	UserID      string `json:"XboxUserId,omitempty"`
	UserSandbox string `json:"XboxUserSandbox,omitempty"`
}

type CharacterInventory struct {
	ID        string         `json:"CharacterId,omitempty"`
	Inventory []ItemInstance `json:"Inventory,omitempty"`
}

type ItemInstance struct {
	Annotation        string                     `json:"Annotation,omitempty"`
	BundleContents    []string                   `json:"BundleContents,omitempty"`
	BundleParent      string                     `json:"BundleParent,omitempty"`
	CatalogVersion    string                     `json:"CatalogVersion,omitempty"`
	CustomData        map[string]json.RawMessage `json:"CustomData,omitempty"`
	DisplayName       string                     `json:"DisplayName,omitempty"`
	Expiration        time.Time                  `json:"Expiration,omitempty"`
	Class             string                     `json:"ItemClass,omitempty"`
	ID                string                     `json:"ItemId,omitempty"`
	InstanceID        string                     `json:"ItemInstanceId,omitempty"`
	PurchaseDate      time.Time                  `json:"PurchaseDate,omitempty"`
	RemainingUses     int                        `json:"RemainingUses,omitempty"`
	UnitCurrency      string                     `json:"UnitCurrency,omitempty"`
	UnitPrice         int                        `json:"UnitPrice,omitempty"`
	UsesIncrementedBy int                        `json:"UsesIncrementedBy,omitempty"`
}

type Character struct {
	ID   string `json:"CharacterId,omitempty"`
	Name string `json:"CharacterName,omitempty"`
	Type string `json:"CharacterType,omitempty"`
}

type PlayerProfile struct {
	AdCampaignAttributions        []AdCampaignAttribution        `json:"AdCampaignAttributions,omitempty"`
	AvatarURL                     string                         `json:"AvatarUrl,omitempty"`
	BannedUntil                   time.Time                      `json:"BannedUntil,omitempty"`
	ContactEmailAddresses         []ContactEmailAddress          `json:"ContactEmailAddresses,omitempty"`
	Created                       time.Time                      `json:"Created,omitempty"`
	DisplayName                   string                         `json:"DisplayName,omitempty"`
	ExperimentVariants            []string                       `json:"ExperimentVariants,omitempty"`
	LastLogin                     time.Time                      `json:"LastLogin,omitempty"`
	LinkedAccounts                []LinkedPlatformAccount        `json:"LinkedAccounts,omitempty"`
	Locations                     []Location                     `json:"Locations,omitempty"`
	Memberships                   []Membership                   `json:"Memberships,omitempty"`
	Origination                   IdentityProvider               `json:"Origination,omitempty"`
	PlayerID                      string                         `json:"PlayerId,omitempty"`
	PublisherID                   string                         `json:"PublisherId,omitempty"`
	PushNotificationRegistrations []PushNotificationRegistration `json:"PushNotificationRegistrations,omitempty"`
	Statistics                    []Statistic                    `json:"Statistics,omitempty"`
	Tags                          []Tag                          `json:"Tags,omitempty"`
	Title                         title.Title                    `json:"TitleId,omitempty"`
	TotalValueToDateInUSD         int                            `json:"TotalValueToDateInUSD,omitempty"`
	ValuesToDates                 []ValuesToDate                 `json:"ValuesToDate,omitempty"`
}

type AdCampaignAttribution struct {
	AttributedAt time.Time `json:"AttributedAt,omitempty"`
	CampaignID   string    `json:"CampaignId,omitempty"`
	Platform     string    `json:"Platform,omitempty"`
}

type ContactEmailAddress struct {
	Address            string                  `json:"EmailAddress,omitempty"`
	Name               string                  `json:"Name,omitempty"`
	VerificationStatus EmailVerificationStatus `json:"VerificationStatus,omitempty"`
}

type EmailVerificationStatus string

const (
	EmailVerificationStatusConfirmed  EmailVerificationStatus = "Confirmed"
	EmailVerificationStatusPending    EmailVerificationStatus = "Pending"
	EmailVerificationStatusUnverified EmailVerificationStatus = "Unverified"
)

type LinkedPlatformAccount struct {
	Email          string           `json:"Email,omitempty"`
	Platform       IdentityProvider `json:"Platform,omitempty"`
	PlatformUserID string           `json:"PlatformUserId,omitempty"`
	Username       string           `json:"Username,omitempty"`
}

type IdentityProvider string

const (
	IdentityProviderAndroidDevice         IdentityProvider = "AndroidDevice"
	IdentityProviderApple                 IdentityProvider = "Apple"
	IdentityProviderCustom                IdentityProvider = "Custom"
	IdentityProviderCustomServer          IdentityProvider = "CustomServer"
	IdentityProviderFacebook              IdentityProvider = "Facebook"
	IdentityProviderFacebookInstantGames  IdentityProvider = "FacebookInstantGames"
	IdentityProviderGameCenter            IdentityProvider = "GameCenter"
	IdentityProviderGameServer            IdentityProvider = "GameServer"
	IdentityProviderGooglePlay            IdentityProvider = "GooglePlay"
	IdentityProviderGooglePlayGames       IdentityProvider = "GooglePlayerGames"
	IdentityProviderIOSDevice             IdentityProvider = "IOSDevice"
	IdentityProviderKongregate            IdentityProvider = "Kongregate"
	IdentityProviderNintendoSwitch        IdentityProvider = "NintendoSwitch"
	IdentityProviderNintendoSwitchAccount IdentityProvider = "NintendoSwitchAccount"
	IdentityProviderOpenIDConnect         IdentityProvider = "OpenIdConnect"
	IdentityProviderPSN                   IdentityProvider = "PSN"
	IdentityProviderPlayFab               IdentityProvider = "PlayFab"
	IdentityProviderSteam                 IdentityProvider = "Steam"
	IdentityProviderTwitch                IdentityProvider = "Twitch"
	IdentityProviderUnknown               IdentityProvider = "Unknown"
	IdentityProviderWindowsHello          IdentityProvider = "WindowsHello"
	IdentityProviderXboxLive              IdentityProvider = "XBoxLive"
)

type Location struct {
	City          string `json:"City,omitempty"`
	ContinentCode string `json:"ContinentCode,omitempty"`
	CountryCode   string `json:"CountryCode,omitempty"`
	Latitude      int    `json:"Latitude,omitempty"`
	Longitude     int    `json:"Longitude,omitempty"`
}

type Membership struct {
	Active             bool           `json:"IsActive,omitempty"`
	Expiration         time.Time      `json:"MembershipExpiration,omitempty"`
	ID                 string         `json:"MembershipId,omitempty"`
	OverrideExpiration time.Time      `json:"OverrideExpiration,omitempty"`
	OverrideSet        bool           `json:"OverrideIsSet,omitempty"`
	Subscriptions      []Subscription `json:"Subscriptions,omitempty"`
}

type Subscription struct {
	Expiration              time.Time          `json:"Expiration,omitempty"`
	InitialSubscriptionTime time.Time          `json:"InitialSubscriptionTime,omitempty"`
	Active                  bool               `json:"IsActive,omitempty"`
	Status                  SubscriptionStatus `json:"Status,omitempty"`
	ID                      string             `json:"SubscriptionId,omitempty"`
	ItemID                  string             `json:"SubscriptionItemId,omitempty"`
	Provider                string             `json:"SubscriptionProvider,omitempty"`
}

type SubscriptionStatus string

const (
	SubscriptionStatusBillingError                    SubscriptionStatus = "BillingError"
	SubscriptionStatusCancelled                       SubscriptionStatus = "Cancelled"
	SubscriptionStatusCustomerDidNotAcceptPriceChange SubscriptionStatus = "CustomerDidNotAcceptPriceChange"
	SubscriptionStatusFreeTrial                       SubscriptionStatus = "FreeTrial"
	SubscriptionStatusNoError                         SubscriptionStatus = "NoError"
	SubscriptionStatusPaymentPending                  SubscriptionStatus = "PaymentPending"
	SubscriptionStatusProductUnavailable              SubscriptionStatus = "ProductUnavailable"
	SubscriptionStatusUnknownError                    SubscriptionStatus = "UnknownError"
)

type PushNotificationRegistration struct {
	NotificationEndpointARN string                   `json:"NotificationEndpointARN,omitempty"`
	Platform                PushNotificationPlatform `json:"Platform,omitempty"`
}

type PushNotificationPlatform string

const (
	PushNotificationPlatformApplePushNotificationService PushNotificationPlatform = "ApplePushNotificationService"
	PushNotificationPlatformGoogleCloudMessaging         PushNotificationPlatform = "GoogleCloudMessaging"
)

type Statistic struct {
	Name    string `json:"Name,omitempty"`
	Value   int    `json:"Value,omitempty"`
	Version int    `json:"Version,omitempty"`
}

type Tag struct {
	Value string `json:"TagValue,omitempty"`
}

type ValuesToDate struct {
	Currency            string `json:"Currency,omitempty"`
	TotalValue          int    `json:"TotalValue,omitempty"`
	TotalValueAsDecimal string `json:"TotalValueAsDecimal,omitempty"`
}

type StatisticValue struct {
	Name    string `json:"StatisticName"`
	Value   int    `json:"Value,omitempty"`
	Version int    `json:"Version,omitempty"`
}

type UserDataRecord struct {
	LastUpdated time.Time          `json:"LastUpdated,omitempty"`
	Permission  UserDataPermission `json:"Permission,omitempty"`
	Value       string             `json:"Value,omitempty"`
}

type UserDataPermission string

const (
	UserDataPermissionPrivate UserDataPermission = "Private"
	UserDataPermissionPublic  UserDataPermission = "Public"
)

type VirtualCurrencyRechargeTime struct {
	Max               int       `json:"RechargeMax,omitempty"`
	Time              time.Time `json:"RechargeTime,omitempty"`
	SecondsToRecharge int       `json:"SecondsToRecharge,omitempty"`
}

type UserSettings struct {
	GatherDevice     bool `json:"GatherDeviceInfo,omitempty"`
	GatherFocus      bool `json:"GatherFocusInfo,omitempty"`
	NeedsAttribution bool `json:"NeedsAttribution,omitempty"`
}

type TreatmentAssignment struct {
	Variables []Variable `json:"Variables,omitempty"`
	Variants  []string   `json:"Variants,omitempty"`
}

type Variable struct {
	Name  string `json:"Name,omitempty"`
	Value string `json:"Value,omitempty"`
}
