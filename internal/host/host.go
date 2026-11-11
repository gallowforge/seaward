// Package host is what Seaward knows about one machine besides its firewall rules: its interfaces
// and addresses, its routes, what is listening, and what Docker published.
package host

import "net/netip"

// Host is one machine at the moment its snapshot was taken.
type Host struct {
	Name       string
	Interfaces []Interface
	Routes     []Route // main table, both families
	// Forward4 and Forward6 say whether the kernel forwards packets between interfaces.
	Forward4, Forward6 bool
	// RouteLocalnet lists interfaces with net.ipv4.conf.<if>.route_localnet set ("all" counts for
	// every interface). Without it a packet from outside for 127.0.0.0/8 is dropped as a martian.
	RouteLocalnet map[string]bool
	// Listeners are sockets waiting for connections or datagrams, in the host's own network
	// namespace (Netns "") and, where it could be read, inside each container (Netns = container ID).
	Listeners []Listener
	// NoListenerData is true when the snapshot has no list of listening sockets at all, so
	// "nothing is listening" cannot be said.
	NoListenerData bool
	Docker         *Docker
	Frontend       *Frontend
	// Notes are things the snapshot does not contain and why, in plain sentences.
	Notes []string
}

// Interface is one network interface.
type Interface struct {
	Name     string
	Up       bool
	Loopback bool
	// Kind is "" for an ordinary interface, or the link kind the kernel reports: "bridge", "veth",
	// "wireguard", "tun", "dummy", "vlan", "bond" ...
	Kind  string
	Addrs []netip.Prefix // each address with its prefix length
}

// Route is one route of the main table.
type Route struct {
	Dst     netip.Prefix // 0.0.0.0/0 or ::/0 for the default route
	Dev     string
	Gateway netip.Addr // zero when the destination is on the link
	// Type is "unicast" (the default), "local", "broadcast", "blackhole", "unreachable", "prohibit".
	Type string
}

// Listener is one listening socket.
type Listener struct {
	Proto string     // "tcp" or "udp"
	Addr  netip.Addr // the bound address; 0.0.0.0 or :: for every address
	// DualStack is true for a "::" socket that also takes IPv4 connections (ss prints it as "*").
	DualStack bool
	// Dev is set when the socket is bound to one interface (ss prints addr%dev).
	Dev     string
	Port    uint16
	Process string // "sshd"; empty when it could not be read
	PID     int
	Netns   string // "" for the host, else a container ID
}

// Docker is what the Docker daemon reported.
type Docker struct {
	Version    string
	Containers []Container
}

// Container is one running container.
type Container struct {
	ID    string
	Name  string
	Image string
	// HostNetwork is true for --network host: the container's listeners are the host's.
	HostNetwork bool
	Networks    []ContainerNet
	Ports       []Published
	// ListenersKnown is true when the snapshot holds the container's own listening sockets (even
	// if there are none), so "nothing is listening in there" can be told from "could not look".
	ListenersKnown bool
}

// ContainerNet is a container's address on one Docker network.
type ContainerNet struct {
	Network string
	Addr    netip.Addr // IPv4, zero if none
	Addr6   netip.Addr // IPv6, zero if none
}

// Published is one published port: host address and port to container port.
type Published struct {
	Proto         string     // "tcp" or "udp"
	HostAddr      netip.Addr // 0.0.0.0, ::, or one address
	HostPort      uint16
	ContainerPort uint16
}

// Frontend is the firewall manager the administrator talks to, and what it says it allows.
type Frontend struct {
	Tool   string // "ufw" or "firewalld"
	Active bool
	// DefaultIncoming is "deny", "reject" or "allow".
	DefaultIncoming string
	Rules           []FrontendRule
}

// FrontendRule is one line of what the firewall manager says about incoming traffic.
type FrontendRule struct {
	// Action is "allow", "deny", "reject" or "limit" (limit allows, with a rate limit).
	Action string
	Proto  string // "tcp", "udp" or "" for both
	// PortLo..PortHi is the port range; both 0 for every port.
	PortLo, PortHi uint16
	From           netip.Prefix // invalid (zero) for anywhere
	To             netip.Prefix // invalid (zero) for any address of this machine
	Iface          string       // "" for every interface
	IPv6           bool
	// Zone is the firewalld zone the rule belongs to; "" for ufw.
	Zone string
	Text string // the line as the tool printed it
}
