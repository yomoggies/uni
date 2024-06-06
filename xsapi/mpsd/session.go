package mpsd

import (
	"context"
	"encoding/json"
	"github.com/yomoggies/uni/xsapi/rta"
	"log/slog"
)

type Session struct {
	ref  SessionReference
	conf PublishConfig
	rta  *rta.Conn
	sub  *rta.Subscription
	log  *slog.Logger
}

func (s *Session) Close() error {
	if err := s.rta.Unsubscribe(context.Background(), s.sub); err != nil {
		s.log.Error("error unsubscribing with RTA", "err", err)
	}
	_, err := s.CommitContext(context.Background(), &SessionDescription{
		Members: map[string]*MemberDescription{
			"me": nil,
		},
	})
	return err
}

type SessionDescription struct {
	Constants  *SessionConstants             `json:"constants,omitempty"`
	RoleTypes  json.RawMessage               `json:"roleTypes,omitempty"`
	Properties *SessionProperties            `json:"properties,omitempty"`
	Members    map[string]*MemberDescription `json:"members,omitempty"`
}

type SessionProperties struct {
	System *SessionPropertiesSystem `json:"system,omitempty"`
	Custom json.RawMessage          `json:"custom,omitempty"`
}

type SessionPropertiesSystem struct {
	Keywords                         []string                            `json:"keywords,omitempty"`
	Turn                             []uint32                            `json:"turn,omitempty"`
	JoinRestriction                  SessionRestriction                  `json:"joinRestriction,omitempty"`
	ReadRestriction                  SessionRestriction                  `json:"readRestriction,omitempty"`
	Closed                           bool                                `json:"closed"`
	Locked                           bool                                `json:"locked,omitempty"`
	Matchmaking                      *SessionPropertiesSystemMatchmaking `json:"matchmaking,omitempty"`
	MatchmakingResubmit              bool                                `json:"matchmakingResubmit,omitempty"`
	InitializationSucceeded          bool                                `json:"initializationSucceeded,omitempty"`
	Host                             string                              `json:"host,omitempty"`
	ServerConnectionStringCandidates json.RawMessage                     `json:"serverConnectionStringCandidates,omitempty"`
}

type SessionPropertiesSystemMatchmaking struct {
	TargetSessionConstants json.RawMessage `json:"targetSessionConstants,omitempty"`
	ServerConnectionString string          `json:"serverConnectionString,omitempty"`
}

type SessionRestriction string

const (
	SessionRestrictionNone     SessionRestriction = "none"
	SessionRestrictionLocal    SessionRestriction = "local"
	SessionRestrictionFollowed SessionRestriction = "followed"
)

type SessionConstants struct {
	System *SessionConstantsSystem `json:"system,omitempty"`
	Custom json.RawMessage         `json:"custom,omitempty"`
}

type SessionConstantsSystem struct {
	MaxMembersCount            uint32                         `json:"maxMembersCount,omitempty"`
	Capabilities               *SessionCapabilities           `json:"capabilities,omitempty"`
	Visibility                 SessionVisibility              `json:"visibility,omitempty"`
	Initiators                 []string                       `json:"initiators,omitempty"`
	ReservedRemovalTimeout     uint64                         `json:"reservedRemovalTimeout,omitempty"`
	InactiveRemovalTimeout     uint64                         `json:"inactiveRemovalTimeout,omitempty"`
	ReadyRemovalTimeout        uint64                         `json:"readyRemovalTimeout,omitempty"`
	SessionEmptyTimeout        uint64                         `json:"sessionEmptyTimeout,omitempty"`
	Metrics                    *SessionConstantsSystemMetrics `json:"metrics,omitempty"`
	MemberInitialization       *MemberInitialization          `json:"memberInitialization,omitempty"`
	PeerToPeerRequirements     *PeerToPeerRequirements        `json:"peerToPeerRequirements,omitempty"`
	PeerToHostRequirements     *PeerToHostRequirements        `json:"peerToHostRequirements,omitempty"`
	MeasurementServerAddresses json.RawMessage                `json:"measurementServerAddresses,omitempty"`
	CloudComputePackage        json.RawMessage                `json:"cloudComputePackage,omitempty"`
}

type PeerToHostRequirements struct {
	LatencyMaximum       uint64              `json:"latencyMaximum,omitempty"`
	BandwidthDownMinimum uint64              `json:"bandwidthDownMinimum,omitempty"`
	BandwidthUpMinimum   uint64              `json:"bandwidthUpMinimum,omitempty"`
	HostSelectionMetric  HostSelectionMetric `json:"hostSelectionMetric,omitempty"`
}

type HostSelectionMetric string

const (
	HostSelectionMetricBandwidthUp   HostSelectionMetric = "bandwidthUp"
	HostSelectionMetricBandwidthDown HostSelectionMetric = "bandwidthDown"
	HostSelectionMetricBandwidth     HostSelectionMetric = "bandwidth"
	HostSelectionMetricLatency       HostSelectionMetric = "latency"
)

type PeerToPeerRequirements struct {
	LatencyMaximum   uint64 `json:"latencyMaximum,omitempty"`
	BandwidthMinimum uint64 `json:"bandwidthMinimum,omitempty"`
}

type MemberInitialization struct {
	JoinTimeout          uint64 `json:"joinTimeout,omitempty"`
	MeasurementTimeout   uint64 `json:"measurementTimeout,omitempty"`
	EvaluationTimeout    uint64 `json:"evaluationTimeout,omitempty"`
	ExternalEvaluation   bool   `json:"externalEvaluation,omitempty"`
	MembersNeededToStart uint32 `json:"membersNeededToStart,omitempty"`
}

type SessionConstantsSystemMetrics struct {
	Latency       bool `json:"latency,omitempty"`
	BandwidthDown bool `json:"bandwidthDown,omitempty"`
	BandwidthUp   bool `json:"bandwidthUp,omitempty"`
	Custom        bool `json:"custom,omitempty"`
}

type SessionCapabilities struct {
	Connectivity                       bool `json:"connectivity,omitempty"`
	SuppressPresenceActivityCheck      bool `json:"suppressPresenceActivityCheck,omitempty"`
	Gameplay                           bool `json:"gameplay,omitempty"`
	Large                              bool `json:"large,omitempty"`
	UserAuthorizationStyle             bool `json:"userAuthorizationStyle,omitempty"`
	ConnectionRequiredForActiveMembers bool `json:"connectionRequiredForActiveMembers,omitempty"`
	CrossPlay                          bool `json:"crossPlay,omitempty"`
	Searchable                         bool `json:"searchable,omitempty"`
	HasOwners                          bool `json:"hasOwners,omitempty"`
}

type SessionVisibility string

const (
	SessionVisibilityPrivate SessionVisibility = "private"
	SessionVisibilityVisible SessionVisibility = "visible"
	SessionVisibilityOpen    SessionVisibility = "open"
)
