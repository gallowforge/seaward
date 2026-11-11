package ipt

import (
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// protoNums maps the protocol names iptables accepts and prints to IP protocol numbers.
var protoNums = map[string]uint32{
	"icmp": 1, "igmp": 2, "ipip": 4, "ipencap": 4, "tcp": 6, "egp": 8, "udp": 17,
	"ipv6": 41, "rsvp": 46, "gre": 47, "esp": 50, "ah": 51, "icmpv6": 58, "ipv6-icmp": 58,
	"ospf": 89, "pim": 103, "vrrp": 112, "l2tp": 115, "sctp": 132, "dccp": 33,
	"mh": 135, "ipv6-mh": 135, "udplite": 136,
}

// protoModule names the match module that iptables loads on its own after "-p NAME" when an
// option it does not know appears.
var protoModule = map[uint32]string{6: "tcp", 17: "udp", 132: "sctp", 33: "dccp", 136: "udplite", 1: "icmp", 58: "icmp6"}

// moduleProto is the protocol a port or type match only works with (iptables refuses the rule
// without the matching -p, so the protocol is part of the condition).
var moduleProto = map[string]uint32{"tcp": 6, "udp": 17, "sctp": 132, "dccp": 33, "udplite": 136, "icmp": 1, "icmp6": 58, "ipv6-icmp": 58}

// parseProto reads a protocol name or number. ok is false for a name it does not know.
// all is true for "all" or 0, which means any protocol.
func parseProto(s string) (n uint32, all, ok bool) {
	s = strings.ToLower(s)
	if s == "all" {
		return 0, true, true
	}
	if v, err := strconv.ParseUint(s, 10, 8); err == nil {
		return uint32(v), v == 0, true
	}
	n, ok = protoNums[s]
	return n, false, ok
}

// servicePorts covers the few service names people type; iptables-save itself prints numbers.
var servicePorts = map[string]uint32{
	"ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "bootps": 67,
	"bootpc": 68, "tftp": 69, "http": 80, "pop3": 110, "ntp": 123, "imap": 143, "imap2": 143,
	"snmp": 161, "ldap": 389, "https": 443, "submissions": 465, "smtps": 465, "syslog": 514,
	"submission": 587, "ldaps": 636, "imaps": 993, "pop3s": 995, "mysql": 3306,
	"postgresql": 5432, "http-alt": 8080,
}

func parsePortNum(s string) (uint32, bool) {
	if v, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint32(v), true
	}
	v, ok := servicePorts[strings.ToLower(s)]
	return v, ok
}

// parsePortRange reads "a", "a:b", ":b" or "a:" (sep is ":" in rules, "-" in ipset elements).
func parsePortRange(s, sep string) (rules.Atom, bool) {
	lo, hi, isRange := strings.Cut(s, sep)
	if !isRange {
		p, ok := parsePortNum(s)
		return rules.Num(p), ok
	}
	var a, b uint32 = 0, 65535
	var ok bool
	if lo != "" {
		if a, ok = parsePortNum(lo); !ok {
			return rules.Atom{}, false
		}
	}
	if hi != "" {
		if b, ok = parsePortNum(hi); !ok {
			return rules.Atom{}, false
		}
	}
	if a > b {
		// iptables swaps a reversed range when it reads it.
		a, b = b, a
	}
	return rules.NumRange(a, b), true
}

var ctStates = map[string]uint32{
	"INVALID": rules.CtInvalid, "NEW": rules.CtNew, "ESTABLISHED": rules.CtEstablished,
	"RELATED": rules.CtRelated, "UNTRACKED": rules.CtUntracked,
}

var ctStatuses = map[string]bool{"NONE": true, "EXPECTED": true, "SEEN_REPLY": true, "ASSURED": true, "CONFIRMED": true}

var addrTypes = map[string]uint32{
	"UNSPEC": rules.AddrUnspec, "UNICAST": rules.AddrUnicast, "LOCAL": rules.AddrLocal,
	"BROADCAST": rules.AddrBroadcast, "ANYCAST": rules.AddrAnycast, "MULTICAST": rules.AddrMulticast,
	"BLACKHOLE": rules.AddrBlackhole, "UNREACHABLE": rules.AddrUnreachable, "PROHIBIT": rules.AddrProhibit,
}

var pktTypes = map[string]uint32{
	"unicast": rules.PktHost, "host": rules.PktHost, "broadcast": rules.PktBroadcast,
	"multicast": rules.PktMulticast, "otherhost": rules.PktOtherHost,
}

// icmpType is a named ICMP type, with a code when the name stands for one code only.
type icmpType struct {
	typ, code uint32
	hasCode   bool
}

func tc(t uint32) icmpType     { return icmpType{typ: t} }
func tcc(t, c uint32) icmpType { return icmpType{typ: t, code: c, hasCode: true} }
func lowerKeys(m map[string]icmpType) map[string]icmpType {
	out := make(map[string]icmpType, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

var icmpNames = lowerKeys(map[string]icmpType{
	"echo-reply": tc(0), "pong": tc(0), "destination-unreachable": tc(3),
	"network-unreachable": tcc(3, 0), "host-unreachable": tcc(3, 1), "protocol-unreachable": tcc(3, 2),
	"port-unreachable": tcc(3, 3), "fragmentation-needed": tcc(3, 4), "source-route-failed": tcc(3, 5),
	"network-unknown": tcc(3, 6), "host-unknown": tcc(3, 7), "network-prohibited": tcc(3, 9),
	"host-prohibited": tcc(3, 10), "TOS-network-unreachable": tcc(3, 11), "TOS-host-unreachable": tcc(3, 12),
	"communication-prohibited": tcc(3, 13), "host-precedence-violation": tcc(3, 14),
	"precedence-cutoff": tcc(3, 15), "source-quench": tc(4), "redirect": tc(5),
	"network-redirect": tcc(5, 0), "host-redirect": tcc(5, 1), "TOS-network-redirect": tcc(5, 2),
	"TOS-host-redirect": tcc(5, 3), "echo-request": tc(8), "ping": tc(8),
	"router-advertisement": tc(9), "router-solicitation": tc(10), "time-exceeded": tc(11),
	"ttl-exceeded": tc(11), "ttl-zero-during-transit": tcc(11, 0), "ttl-zero-during-reassembly": tcc(11, 1),
	"parameter-problem": tc(12), "ip-header-bad": tcc(12, 0), "required-option-missing": tcc(12, 1),
	"timestamp-request": tc(13), "timestamp-reply": tc(14), "address-mask-request": tc(17),
	"address-mask-reply": tc(18),
})

var icmp6Names = lowerKeys(map[string]icmpType{
	"destination-unreachable": tc(1), "no-route": tcc(1, 0), "communication-prohibited": tcc(1, 1),
	"beyond-scope": tcc(1, 2), "address-unreachable": tcc(1, 3), "port-unreachable": tcc(1, 4),
	"failed-policy": tcc(1, 5), "reject-route": tcc(1, 6), "packet-too-big": tc(2),
	"time-exceeded": tc(3), "ttl-exceeded": tc(3), "ttl-zero-during-transit": tcc(3, 0),
	"ttl-zero-during-reassembly": tcc(3, 1), "parameter-problem": tc(4), "bad-header": tcc(4, 0),
	"unknown-header-type": tcc(4, 1), "unknown-option": tcc(4, 2), "echo-request": tc(128),
	"ping": tc(128), "echo-reply": tc(129), "pong": tc(129), "mld-listener-query": tc(130),
	"mld-listener-report": tc(131), "mld-listener-done": tc(132), "mld-listener-reduction": tc(132),
	"router-solicitation": tc(133), "router-advertisement": tc(134), "neighbour-solicitation": tc(135),
	"neighbor-solicitation": tc(135), "neighbour-advertisement": tc(136), "neighbor-advertisement": tc(136),
	"redirect": tc(137),
})

// moduleWhat says in a few words what a match extension the model does not follow looks at. It
// completes the sentence "the X match (-m X) ...".
var moduleWhat = map[string]string{
	"string":     "looks inside the packet's data",
	"u32":        "tests raw bytes of the packet",
	"bpf":        "runs a small BPF program on the packet",
	"time":       "depends on the time of day or the date",
	"owner":      "looks at which local program sent the packet",
	"physdev":    "looks at which bridge port the packet used",
	"socket":     "looks for a matching local socket",
	"length":     "looks at the packet's length",
	"ttl":        "looks at the packet's time-to-live",
	"hl":         "looks at the packet's hop limit",
	"tcpmss":     "looks at the TCP maximum segment size option",
	"mac":        "looks at the sender's hardware (MAC) address",
	"geoip":      "looks up which country an address belongs to",
	"cgroup":     "looks at which group of local programs the packet belongs to",
	"dscp":       "looks at the packet's DSCP priority field",
	"tos":        "looks at the packet's type-of-service field",
	"ecn":        "looks at the packet's congestion (ECN) bits",
	"statistic":  "matches only some packets, at random or by count",
	"nfacct":     "depends on a traffic accounting counter",
	"helper":     "looks at which connection helper (FTP, SIP and so on) made the connection",
	"ipvs":       "looks at the kernel load balancer (IPVS)",
	"cluster":    "splits traffic between cluster machines by a hash",
	"devgroup":   "looks at the interface group number",
	"realm":      "looks at the routing realm",
	"cpu":        "looks at which processor handles the packet",
	"quota":      "stops matching after a number of bytes",
	"osf":        "guesses the sender's operating system",
	"connbytes":  "looks at how much traffic the connection has carried",
	"connlabel":  "looks at labels on the connection",
	"condition":  "depends on a switch set from outside the firewall",
	"esp":        "looks at the IPsec ESP header",
	"ipcomp":     "looks at the IP compression header",
	"l2tp":       "looks at the L2TP header",
	"rateest":    "depends on a measured traffic rate",
	"mh":         "looks at the mobile IPv6 header",
	"ipv6header": "looks at which IPv6 extension headers the packet has",
	"eui64":      "compares the IPv6 source with the sender's hardware address",
	"set":        "looks up an ipset",
	"connrate":   "looks at the connection's traffic rate",
	"psd":        "detects port scans",
	"account":    "counts traffic per address",
	"pknock":     "depends on a port-knocking sequence",
	"lscan":      "detects port scans",
	"iface":      "looks at the state of an interface",
	"fuzzy":      "depends on a measured traffic rate",
	"dhcpmac":    "looks at the hardware address inside a DHCP request",
	"ipp2p":      "looks for peer-to-peer traffic inside the packet",
	"gradm":      "depends on the grsecurity policy",
	"addrtype":   "looks at the type of an address",
	"comment":    "carries a comment",
	"multiport":  "looks at ports",
	"conntrack":  "looks at the connection tracking state",
	"state":      "looks at the connection tracking state",
	"policy":     "looks at the IPsec policy",
	"rpfilter":   "checks the route back to the sender",
	"tcp":        "looks at TCP header fields",
	"udp":        "looks at UDP header fields",
	"icmp":       "looks at the ICMP type",
	"icmp6":      "looks at the ICMPv6 type",
	"recent":     "remembers addresses it has seen",
	"connlimit":  "counts open connections",
	"hashlimit":  "limits the rate per address",
	"limit":      "limits the rate",
	"mark":       "looks at the packet mark",
	"connmark":   "looks at the connection mark",
	"iprange":    "looks at an address range",
	"pkttype":    "looks at the link-layer packet type",
	"sctp":       "looks at SCTP header fields",
	"dccp":       "looks at DCCP header fields",
	"udplite":    "looks at UDP-Lite header fields",
	"ipv6-icmp":  "looks at the ICMPv6 type",
}

// unknownModule is the sentence for a match extension the model does not follow.
func unknownModule(name string) string {
	if what, ok := moduleWhat[name]; ok {
		return "the " + name + " match (-m " + name + ") " + what + ", which seaward does not model"
	}
	return "the " + name + " match (-m " + name + ") is not one seaward understands"
}

// targetWhy says why a target the model cannot follow leaves the outcome open.
var targetWhy = map[string]string{
	"TPROXY":   "the TPROXY target hands the packet to a local proxy socket, which seaward does not follow",
	"NFQUEUE":  "the NFQUEUE target passes the packet to a program that decides its fate",
	"QUEUE":    "the QUEUE target passes the packet to a program that decides its fate",
	"SYNPROXY": "the SYNPROXY target answers the TCP handshake itself before it lets the connection through",
	"TARPIT":   "the TARPIT target holds the connection open without letting it through",
	"DELUDE":   "the DELUDE target answers a connection attempt as if the port were open",
	"CHAOS":    "the CHAOS target answers at random with a reject, a tarpit or a delude",
	"NETMAP":   "the NETMAP target rewrites the destination network, which seaward does not follow",
}

// noopTargets change nothing about whether a new connection gets through.
var noopTargets = map[string]string{
	"LOG": "log", "NFLOG": "log", "ULOG": "log", "MASQUERADE": "masquerade", "SNAT": "source NAT",
	"NETMAP": "source network mapping", "TCPMSS": "TCP MSS clamping", "TOS": "set TOS", "DSCP": "set DSCP",
	"TTL": "set TTL", "HL": "set hop limit", "CHECKSUM": "fill in checksum", "CLASSIFY": "set traffic class",
	"SECMARK": "set security mark", "CONNSECMARK": "copy security mark", "AUDIT": "audit record",
	"TRACE": "trace", "SET": "add to or remove from an ipset", "RATEEST": "rate estimator",
	"IDLETIMER": "idle timer", "LED": "blink a LED", "TEE": "copy the packet elsewhere",
	"TCPOPTSTRIP": "strip TCP options", "ECN": "clear ECN bits", "CT": "connection tracking settings",
}
