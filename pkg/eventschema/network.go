package eventschema

// NetworkEvent contains network-specific event fields.
type NetworkEvent struct {
	SourceIP        string `json:"source.ip"`
	SourcePort      int    `json:"source.port"`
	DestinationIP   string `json:"destination.ip"`
	DestinationPort int    `json:"destination.port"`
	Protocol        string `json:"network.protocol"`
	Direction       string `json:"network.direction"` // inbound, outbound
	ProcessPID      int    `json:"process.pid,omitempty"`
	ProcessName     string `json:"process.name,omitempty"`
	BytesSent       int64  `json:"source.bytes,omitempty"`
	BytesReceived   int64  `json:"destination.bytes,omitempty"`
}
