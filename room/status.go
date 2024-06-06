package room

type StatusProvider interface {
	Status() (Status, error)
}

type Status struct {
	Joinability             Joinability      `json:"Joinability"`
	HostName                string           `json:"hostName"`
	OwnerID                 string           `json:"ownerId"`
	RakNetGUID              string           `json:"rakNetGUID"`
	Version                 string           `json:"version"`
	LevelID                 string           `json:"levelId"`
	WorldName               string           `json:"worldName"`
	WorldType               WorldType        `json:"worldType"`
	Protocol                int32            `json:"protocol"`
	MemberCount             uint32           `json:"MemberCount"`
	MaxMembersCount         uint32           `json:"MaxMembersCount"`
	BroadcastSetting        BroadcastSetting `json:"BroadcastSetting"`
	LanGame                 bool             `json:"LanGame"`
	IsEditorWorld           bool             `json:"isEditorWorld,omitempty"`
	TransportLayer          TransportLayer   `json:"TransportLayer"`
	WebRTCNetworkID         uint64           `json:"WebRTCNetworkId"`
	OnlineCrossPlatformGame bool             `json:"OnlineCrossPlatformGame"`
	CrossPlayDisabled       bool             `json:"CrossPlayDisabled"`
	TitleID                 uint32           `json:"TitleId"`
	SupportedConnections    []Connection     `json:"SupportedConnections"`
}

type Joinability string

const (
	JoinabilityJoinableByFriends Joinability = "joinable_by_friends"
)

type WorldType string

const (
	WorldTypeCreative WorldType = "Creative"
)

type BroadcastSetting uint32

const (
	BroadcastSettingFriendsOfFriends BroadcastSetting = 3
)

type TransportLayer uint32

const (
	TransportLayerRakNet TransportLayer = iota
	_
	TransportLayerNetherNet
)

type Connection struct {
	ConnectionType  uint32 `json:"ConnectionType"`
	HostIPAddress   string `json:"HostIpAddress"`
	HostPort        uint16 `json:"HostPort"`
	NetherNetID     uint64 `json:"NetherNetId"`
	WebRTCNetworkID uint64 `json:"WebRTCNetworkId"`
	RakNetGUID      string `json:"RakNetGUID"`
}
