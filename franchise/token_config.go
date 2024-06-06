package franchise

import (
	"github.com/google/uuid"
	"golang.org/x/text/language"
)

type TokenConfigSource interface {
	TokenConfig() (*TokenConfig, error)
}

type TokenConfig struct {
	Device *DeviceConfig `json:"device,omitempty"`
	User   *UserConfig   `json:"user,omitempty"`

	Environment AuthorizationEnvironment `json:"-"`
}

type UserConfig struct {
	Language     language.Tag `json:"language,omitempty"`
	LanguageCode language.Tag `json:"languageCode,omitempty"`
	RegionCode   string       `json:"regionCode,omitempty"`
	Token        string       `json:"token,omitempty"`
	TokenType    TokenType    `json:"tokenType,omitempty"`
}

type TokenType string

const (
	TokenTypePlayFab TokenType = "PlayFab"
)

type DeviceConfig struct {
	ApplicationType    ApplicationType `json:"applicationType,omitempty"`
	Capabilities       []Capability    `json:"capabilities,omitempty"`
	GameVersion        string          `json:"gameVersion,omitempty"`
	ID                 uuid.UUID       `json:"id,omitempty"`
	Memory             string          `json:"memory,omitempty"`
	Platform           Platform        `json:"platform,omitempty"`
	PlayFabTitleID     string          `json:"playFabTitleId,omitempty"`
	StorePlatform      StorePlatform   `json:"storePlatform,omitempty"`
	TreatmentOverrides []string        `json:"treatmentOverrides,omitempty"`
	Type               DeviceType      `json:"type,omitempty"`
}

type DeviceType string

const (
	DeviceTypeWindows10 DeviceType = "Windows10"
)

type StorePlatform string

const (
	StorePlatformUWPStore StorePlatform = "uwp.store"
)

type Platform string

const (
	PlatformWindows10 Platform = "Windows10"
)

type Capability string

const (
	CapabilityRayTracing Capability = "Raytracing"
)

type ApplicationType string

const (
	ApplicationTypeMinecraftPE ApplicationType = "MinecraftPE"
)

type AuthorizationEnvironment struct {
	ServiceURI        string `json:"serviceUri,omitempty"`
	Issuer            string `json:"issuer,omitempty"`
	PlayFabTitleID    string `json:"playfabTitleId,omitempty"`
	EduPlayFabTitleID string `json:"eduPlayFabTitleId,omitempty"`
}
