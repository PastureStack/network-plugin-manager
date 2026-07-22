package metadata

// The structs in this file describe the documented JSON fields consumed from
// the dated metadata API. Unknown fields are intentionally ignored by the JSON
// decoder so Server and Agent additions remain forward compatible.

type Stack struct {
	EnvironmentName string    `json:"environment_name"`
	EnvironmentUUID string    `json:"environment_uuid"`
	MetadataKind    string    `json:"metadata_kind"`
	Name            string    `json:"name"`
	Services        []Service `json:"services"`
	System          bool      `json:"system"`
	UUID            string    `json:"uuid"`
}

type HealthCheck struct {
	HealthyThreshold   int    `json:"healthy_threshold"`
	Interval           int    `json:"interval"`
	Port               int    `json:"port"`
	RequestLine        string `json:"request_line"`
	ResponseTimeout    int    `json:"response_timeout"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
}

type Service struct {
	Containers         []Container            `json:"containers"`
	CreateIndex        int                    `json:"create_index"`
	EnvironmentUUID    string                 `json:"environment_uuid"`
	Expose             []string               `json:"expose"`
	ExternalIps        []string               `json:"external_ips"`
	Fqdn               string                 `json:"fqdn"`
	HealthCheck        HealthCheck            `json:"health_check"`
	Hostname           string                 `json:"hostname"`
	Kind               string                 `json:"kind"`
	Labels             map[string]string      `json:"labels"`
	LBConfig           LBConfig               `json:"lb_config"`
	Links              map[string]string      `json:"links"`
	Metadata           map[string]interface{} `json:"metadata"`
	MetadataKind       string                 `json:"metadata_kind"`
	Name               string                 `json:"name"`
	Ports              []string               `json:"ports"`
	PrimaryServiceName string                 `json:"primary_service_name"`
	Scale              int                    `json:"scale"`
	Sidekicks          []string               `json:"sidekicks"`
	StackName          string                 `json:"stack_name"`
	StackUUID          string                 `json:"stack_uuid"`
	State              string                 `json:"state"`
	System             bool                   `json:"system"`
	Token              string                 `json:"token"`
	UUID               string                 `json:"uuid"`
	Vip                string                 `json:"vip"`
}

type Container struct {
	CreateIndex              int               `json:"create_index"`
	Dns                      []string          `json:"dns"`
	DnsSearch                []string          `json:"dns_search"`
	EnvironmentUUID          string            `json:"environment_uuid"`
	ExternalId               string            `json:"external_id"`
	HealthCheck              HealthCheck       `json:"health_check"`
	HealthCheckHosts         []string          `json:"health_check_hosts"`
	HealthState              string            `json:"health_state"`
	HostUUID                 string            `json:"host_uuid"`
	Hostname                 string            `json:"hostname"`
	IPs                      []string          `json:"ips"`
	Labels                   map[string]string `json:"labels"`
	Links                    map[string]string `json:"links"`
	MemoryReservation        int64             `json:"memory_reservation"`
	MetadataKind             string            `json:"metadata_kind"`
	MilliCPUReservation      int64             `json:"milli_cpu_reservation"`
	Name                     string            `json:"name"`
	NetworkFromContainerUUID string            `json:"network_from_container_uuid"`
	NetworkUUID              string            `json:"network_uuid"`
	Ports                    []string          `json:"ports"`
	PrimaryIp                string            `json:"primary_ip"`
	PrimaryMacAddress        string            `json:"primary_mac_address"`
	ServiceIndex             string            `json:"service_index"`
	ServiceName              string            `json:"service_name"`
	StackName                string            `json:"stack_name"`
	StackUUID                string            `json:"stack_uuid"`
	StartCount               int               `json:"start_count"`
	State                    string            `json:"state"`
	System                   bool              `json:"system"`
	UUID                     string            `json:"uuid"`
}

type Network struct {
	Default             bool                   `json:"is_default"`
	DefaultPolicyAction string                 `json:"default_policy_action"`
	EnvironmentUUID     string                 `json:"environment_uuid"`
	HostPorts           bool                   `json:"host_ports"`
	Metadata            map[string]interface{} `json:"metadata"`
	MetadataKind        string                 `json:"metadata_kind"`
	Name                string                 `json:"name"`
	Policy              []NetworkPolicyRule    `json:"policy,omitempty"`
	UUID                string                 `json:"uuid"`
}

type Host struct {
	AgentIP         string            `json:"agent_ip"`
	AgentState      string            `json:"agent_state"`
	EnvironmentUUID string            `json:"environment_uuid"`
	HostId          int               `json:"host_id"`
	Hostname        string            `json:"hostname"`
	Labels          map[string]string `json:"labels"`
	LocalStorageMb  int64             `json:"local_storage_mb"`
	Memory          int64             `json:"memory"`
	MetadataKind    string            `json:"metadata_kind"`
	MilliCPU        int64             `json:"milli_cpu"`
	Name            string            `json:"name"`
	State           string            `json:"state"`
	UUID            string            `json:"uuid"`
}

type PortRule struct {
	BackendName string `json:"backend_name"`
	Hostname    string `json:"hostname"`
	Path        string `json:"path"`
	Priority    int    `json:"priority"`
	Protocol    string `json:"protocol"`
	Selector    string `json:"selector"`
	Service     string `json:"service"`
	SourcePort  int    `json:"source_port"`
	TargetPort  int    `json:"target_port"`
}

type LBConfig struct {
	Certs            []string           `json:"certs"`
	Config           string             `json:"config"`
	DefaultCert      string             `json:"default_cert"`
	PortRules        []PortRule         `json:"port_rules"`
	StickinessPolicy LBStickinessPolicy `json:"stickiness_policy"`
}

type LBStickinessPolicy struct {
	Cookie   string `json:"cookie"`
	Domain   string `json:"domain"`
	Indirect bool   `json:"indirect"`
	Mode     string `json:"mode"`
	Name     string `json:"name"`
	Nocache  bool   `json:"nocache"`
	Postonly bool   `json:"postonly"`
}

type NetworkPolicyRuleBetween struct {
	GroupBy  string `json:"groupBy,omitempty"`
	Selector string `json:"selector,omitempty"`
}

type NetworkPolicyRuleMember struct {
	Selector string `json:"selector,omitempty"`
}

type NetworkPolicyRule struct {
	Action  string                    `json:"action"`
	Between *NetworkPolicyRuleBetween `json:"between"`
	From    *NetworkPolicyRuleMember  `json:"from"`
	Ports   []string                  `json:"ports"`
	To      *NetworkPolicyRuleMember  `json:"to"`
	Within  string                    `json:"within"`
}
