package nft

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// kind says how the values compared against a key are written in the listing.
type kind int

const (
	kNone     kind = iota // not modelled
	kAddr4                // an IPv4 address, network or range
	kAddr6                // an IPv6 address, network or range
	kPort                 // a port number
	kProto                // an IP protocol, by name or number
	kIfname               // an interface name; a trailing * is a wildcard
	kIface                // an interface picked by index ("iif"); the listing shows its name
	kMark                 // a 32-bit mark
	kCtState              // connection states
	kNFProto              // ipv4 or ipv6
	kEthProto             // "meta protocol": ip or ip6
	kPktType              // host, broadcast, multicast, other
	kFibType              // local, unicast, broadcast ...
	kTCPFlags             // TCP flag names
	kCtDir                // original or reply
	kICMP                 // ICMP type
	kICMPv6               // ICMPv6 type
	kBool                 // exists or missing
	kCtStatus             // connection status flags; handled on its own
)

// typeKind maps the type names of named sets and maps.
var typeKind = map[string]kind{
	"ipv4_addr":    kAddr4,
	"ipv6_addr":    kAddr6,
	"inet_service": kPort,
	"inet_proto":   kProto,
	"ifname":       kIfname,
	"iface_index":  kIface,
	"mark":         kMark,
	"ct_state":     kCtState,
	"nf_proto":     kNFProto,
	"pkt_type":     kPktType,
	"fib_addrtype": kFibType,
	"tcp_flag":     kTCPFlags,
	"ct_dir":       kCtDir,
	"icmp_type":    kICMP,
	"icmpv6_type":  kICMPv6,
	"boolean":      kBool,
}

var protoNum = map[string]uint32{
	"hopopt": 0, "icmp": 1, "igmp": 2, "ggp": 3, "ipencap": 4, "ipip": 4, "st": 5, "tcp": 6, "egp": 8,
	"igp": 9, "pup": 12, "udp": 17, "hmp": 20, "xns-idp": 22, "rdp": 27, "iso-tp4": 29, "dccp": 33,
	"xtp": 36, "ddp": 37, "idpr-cmtp": 38, "ipv6": 41, "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45,
	"rsvp": 46, "gre": 47, "esp": 50, "ah": 51, "skip": 57, "icmpv6": 58, "ipv6-icmp": 58,
	"ipv6-nonxt": 59, "ipv6-opts": 60, "eigrp": 88, "ospf": 89, "ax.25": 93, "etherip": 97,
	"encap": 98, "pim": 103, "comp": 108, "ipcomp": 108, "vrrp": 112, "l2tp": 115, "isis": 124,
	"sctp": 132, "fc": 133, "mobility-header": 135, "mh": 135, "udplite": 136, "mpls-in-ip": 137,
	"manet": 138, "hip": 139, "shim6": 140, "wesp": 141, "rohc": 142, "ethernet": 143, "mptcp": 262,
}

var tcpFlag = map[string]uint32{
	"fin": 1, "syn": 2, "rst": 4, "psh": 8, "ack": 16, "urg": 32, "ecn": 64, "cwr": 128,
}

var valueNames = map[kind]map[string]uint32{
	kProto: protoNum,
	kCtState: {
		"invalid": rules.CtInvalid, "established": rules.CtEstablished, "related": rules.CtRelated,
		"new": rules.CtNew, "untracked": rules.CtUntracked,
	},
	kNFProto:  {"ipv4": 4, "ipv6": 6},
	kEthProto: {"ip": 4, "ip6": 6},
	kPktType: {
		"host": rules.PktHost, "unicast": rules.PktHost, "broadcast": rules.PktBroadcast,
		"multicast": rules.PktMulticast, "other": rules.PktOtherHost,
	},
	kFibType: {
		"unspec": rules.AddrUnspec, "unicast": rules.AddrUnicast, "local": rules.AddrLocal,
		"broadcast": rules.AddrBroadcast, "anycast": rules.AddrAnycast, "multicast": rules.AddrMulticast,
		"blackhole": rules.AddrBlackhole, "unreachable": rules.AddrUnreachable, "prohibit": rules.AddrProhibit,
	},
	kTCPFlags: tcpFlag,
	kCtDir:    {"original": 0, "reply": 1},
	kICMP: {
		"echo-reply": 0, "destination-unreachable": 3, "source-quench": 4, "redirect": 5,
		"echo-request": 8, "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11,
		"parameter-problem": 12, "timestamp-request": 13, "timestamp-reply": 14, "info-request": 15,
		"info-reply": 16, "address-mask-request": 17, "address-mask-reply": 18,
	},
	kICMPv6: {
		"destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3, "parameter-problem": 4,
		"echo-request": 128, "echo-reply": 129, "mld-listener-query": 130, "mld-listener-report": 131,
		"mld-listener-done": 132, "mld-listener-reduction": 132, "nd-router-solicit": 133,
		"nd-router-advert": 134, "nd-neighbor-solicit": 135, "nd-neighbor-advert": 136,
		"nd-redirect": 137, "router-renumbering": 138, "ind-neighbor-solicit": 141,
		"ind-neighbor-advert": 142, "mld2-listener-report": 143,
	},
}

// numMax is the largest value of the kinds that are written as plain numbers.
var numMax = map[kind]uint32{
	kPort: 0xffff, kProto: 0xff, kMark: 0xffffffff, kTCPFlags: 0xff, kICMP: 0xff, kICMPv6: 0xff,
}

// number reads one value of a numeric kind: a name the kind knows, or a number in its range.
func number(k kind, n *node) (uint32, bool) {
	if s, ok := n.str(); ok {
		v, ok := valueNames[k][s]
		if ok && k == kProto && v > 0xff {
			return 0, false
		}
		return v, ok
	}
	max, ok := numMax[k]
	if !ok {
		return 0, false
	}
	v, ok := n.num()
	if !ok || v > uint64(max) {
		return 0, false
	}
	return uint32(v), true
}

// flagBits reads TCP flags written as a name, a number, a list of names or {"|": [...]}.
func flagBits(n *node) (uint32, bool) {
	if k, v := n.obj().one(); k == "|" {
		n = v
	} else if n.obj() != nil {
		return 0, false
	}
	if !n.isArr() {
		return number(kTCPFlags, n)
	}
	var bits uint32
	for _, x := range n.arr() {
		b, ok := flagBits(x)
		if !ok {
			return 0, false
		}
		bits |= b
	}
	return bits, true
}

// addrOf reads an address of the kind's family.
func addrOf(k kind, n *node) (netip.Addr, bool) {
	s, ok := n.str()
	if !ok {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	if (k == kAddr4) != a.Is4() {
		return netip.Addr{}, false
	}
	return a, true
}

// unwrap takes a set element out of its {"elem": {"val": ...}} wrapper, which carries a timeout,
// a comment or a counter beside the value.
func unwrap(n *node) *node {
	for o := n.obj(); o != nil && o.has("elem") && len(o.m) == 1; o = n.obj() {
		inner := o.get("elem").obj()
		if inner == nil || !inner.has("val") {
			return n
		}
		n = inner.get("val")
		inner.all = true
	}
	return n
}

// atomOf reads one value of a key field: a single value, a network or a range.
func atomOf(k kind, n *node) (rules.Atom, bool) {
	n = unwrap(n)
	isAddr := k == kAddr4 || k == kAddr6
	if o := n.obj(); o != nil {
		key, v := o.one()
		switch key {
		case "prefix":
			po := v.obj()
			a, ok := addrOf(k, po.get("addr"))
			l, ok2 := po.get("len").num()
			if !isAddr || !ok || !ok2 || l > uint64(a.BitLen()) {
				return rules.Atom{}, false
			}
			return rules.Pfx(netip.PrefixFrom(a, int(l))), true
		case "range":
			xs := v.arr()
			if len(xs) != 2 {
				return rules.Atom{}, false
			}
			if isAddr {
				lo, ok := addrOf(k, xs[0])
				hi, ok2 := addrOf(k, xs[1])
				if !ok || !ok2 || hi.Less(lo) {
					return rules.Atom{}, false
				}
				return rules.Atom{Kind: rules.AtomRange, AddrLo: lo, AddrHi: hi}, true
			}
			if _, numeric := numMax[k]; !numeric {
				return rules.Atom{}, false
			}
			lo, ok := number(k, xs[0])
			hi, ok2 := number(k, xs[1])
			if !ok || !ok2 || hi < lo {
				return rules.Atom{}, false
			}
			return rules.NumRange(lo, hi), true
		case "|":
			if k == kTCPFlags {
				if bits, ok := flagBits(v); ok {
					return rules.Num(bits), true
				}
			}
		}
		return rules.Atom{}, false
	}
	switch k {
	case kNone, kCtStatus:
		return rules.Atom{}, false
	case kAddr4, kAddr6:
		a, ok := addrOf(k, n)
		if !ok {
			return rules.Atom{}, false
		}
		return rules.Pfx(netip.PrefixFrom(a, a.BitLen())), true
	case kIfname:
		s, ok := n.str()
		switch {
		case !ok:
			return rules.Atom{}, false
		case strings.HasSuffix(s, `\*`):
			return rules.Str(strings.TrimSuffix(s, `\*`) + "*"), true
		case strings.HasSuffix(s, "*"):
			return rules.StrPfx(strings.TrimSuffix(s, "*")), true
		}
		return rules.Str(s), true
	case kIface:
		// A number here is the index of an interface that no longer exists.
		s, ok := n.str()
		return rules.Str(s), ok
	case kBool:
		b, ok := n.boolean()
		if b {
			return rules.Num(1), ok
		}
		return rules.Num(0), ok
	}
	v, ok := number(k, n)
	return rules.Num(v), ok
}

// elemOf reads one element: a value, or a concatenation with one value per key field.
func elemOf(ks []kind, n *node) (rules.Elem, bool) {
	n = unwrap(n)
	if len(ks) == 1 {
		a, ok := atomOf(ks[0], n)
		return rules.Elem{a}, ok
	}
	key, v := n.obj().one()
	xs := v.arr()
	if key != "concat" || len(xs) != len(ks) {
		return nil, false
	}
	e := make(rules.Elem, len(ks))
	for i, k := range ks {
		a, ok := atomOf(k, xs[i])
		if !ok {
			return nil, false
		}
		e[i] = a
	}
	return e, true
}

// keyPart is one thing a rule looks at.
type keyPart struct {
	f    rules.Field
	k    kind
	nf   uint32 // the IP version the key implies (4 or 6), or 0
	l4   uint32 // the transport protocol the key implies, or 0
	name string // the key in nft's words: "ip saddr", "meta mark"
	why  string // when seaward does not model the key: one sentence
}

// l4Of gives the protocol number behind a header name such as "tcp".
var l4Of = map[string]uint32{
	"tcp": 6, "udp": 17, "sctp": 132, "dccp": 33, "udplite": 136, "icmp": 1, "icmpv6": 58,
	"esp": 50, "ah": 51, "comp": 108, "gre": 47, "igmp": 2,
}

func notModelled(name, what string) string {
	if what == "" {
		return fmt.Sprintf("the %s match is not one seaward understands", clip(name))
	}
	return fmt.Sprintf("the %s match %s, which seaward does not model", clip(name), what)
}

// keyOf reads the left-hand side of a comparison, or one field of a concatenation.
func keyOf(n *node, family string) keyPart {
	key, v := n.obj().one()
	o := v.obj()
	switch key {
	case "payload":
		return payloadKey(o)
	case "meta":
		p := metaKey(o)
		if family == "netdev" && p.k == kNFProto {
			// In a netdev table the kernel answers this with the table's own family, not the
			// packet's, so it does not tell IPv4 from IPv6 there.
			p.why = notModelled(p.name, "does not tell IPv4 from IPv6 in a netdev table")
		}
		return p
	case "ct":
		return ctKey(o, family)
	case "":
		return keyPart{name: "?", why: "this rule compares something that is not written the way nft writes it"}
	}
	p := keyPart{name: key}
	switch key {
	case "exthdr", "tcp option", "ip option", "sctp chunk", "dccp option", "gre", "geneve", "vxlan", "gretap", "inner":
		p.why = notModelled(key, "looks at the packet's optional or inner headers")
	case "socket":
		p.why = notModelled(key, "looks for a matching local socket")
	case "osf":
		p.why = notModelled(key, "guesses the sender's operating system")
	case "ipsec":
		p.why = notModelled(key, "looks at how the packet was encrypted in transit")
	case "numgen", "jhash", "symhash":
		p.why = notModelled(key, "matches only some packets, at random or by count")
	case "rt":
		p.why = notModelled(key, "looks at the route the packet will take")
	case "fib":
		p.why = notModelled(key, "looks an address up in the routing table in a way seaward cannot follow here")
	default:
		p.why = notModelled(key, "")
	}
	return p
}

func payloadKey(o *object) keyPart {
	if o.has("base") || !o.has("protocol") {
		return keyPart{name: "raw payload", why: notModelled("raw payload", "looks inside the packet's data")}
	}
	proto, field := o.text("protocol"), o.text("field")
	p := keyPart{name: proto + " " + field, l4: l4Of[proto]}
	switch proto {
	case "ip", "icmp", "igmp":
		p.nf = 4
	case "ip6", "icmpv6":
		p.nf = 6
	}
	port := false
	switch proto {
	case "tcp", "udp", "sctp", "dccp", "udplite", "th":
		port = true
	}
	switch {
	case proto == "ip" && field == "saddr":
		p.f.Name, p.k = rules.FSaddr, kAddr4
	case proto == "ip" && field == "daddr":
		p.f.Name, p.k = rules.FDaddr, kAddr4
	case proto == "ip6" && field == "saddr":
		p.f.Name, p.k = rules.FSaddr, kAddr6
	case proto == "ip6" && field == "daddr":
		p.f.Name, p.k = rules.FDaddr, kAddr6
	case proto == "ip" && field == "protocol", proto == "ip6" && field == "nexthdr":
		p.f.Name, p.k = rules.FL4Proto, kProto
	case port && field == "sport":
		p.f.Name, p.k = rules.FSport, kPort
	case port && field == "dport":
		p.f.Name, p.k = rules.FDport, kPort
	case proto == "tcp" && field == "flags":
		p.f.Name, p.k = rules.FTCPFlags, kTCPFlags
	case proto == "icmp" && field == "type":
		p.f.Name, p.k = rules.FICMPType, kICMP
	case proto == "icmpv6" && field == "type":
		p.f.Name, p.k = rules.FICMPv6Type, kICMPv6
	case field == "ttl", field == "hoplimit":
		p.why = notModelled(p.name, "looks at the packet's time-to-live")
	case field == "length":
		p.why = notModelled(p.name, "looks at the packet's length")
	case proto == "ether" && field == "saddr":
		p.why = notModelled(p.name, "looks at the sender's hardware (MAC) address")
	case proto == "ether", proto == "vlan", proto == "arp":
		p.why = notModelled(p.name, "looks at the frame the packet travelled in")
	case (proto == "icmp" || proto == "icmpv6") && field == "code":
		p.why = fmt.Sprintf("the %s match checks the code of an ICMP message, and seaward models only the type", proto)
	default:
		p.why = notModelled(p.name, "looks at a part of the packet's header that seaward does not track")
		p.why = strings.Replace(p.why, ", which seaward does not model", "", 1)
	}
	return p
}

func metaKey(o *object) keyPart {
	key := o.text("key")
	p := keyPart{name: metaName(key)}
	switch key {
	case "iifname":
		p.f.Name, p.k = rules.FIifName, kIfname
	case "oifname":
		p.f.Name, p.k = rules.FOifName, kIfname
	case "iif":
		p.f.Name, p.k = rules.FIifName, kIface
	case "oif":
		p.f.Name, p.k = rules.FOifName, kIface
	case "l4proto":
		p.f.Name, p.k = rules.FL4Proto, kProto
	case "nfproto":
		p.f.Name, p.k = rules.FNFProto, kNFProto
	case "protocol":
		p.f.Name, p.k = rules.FNFProto, kEthProto
	case "mark":
		p.f.Name, p.k = rules.FMark, kMark
	case "pkttype":
		p.f.Name, p.k = rules.FPktType, kPktType
	case "ipsec", "secpath":
		p.f.Name, p.k = rules.FIPSecIn, kBool
	case "length":
		p.why = notModelled(p.name, "looks at the packet's length")
	case "iifgroup", "oifgroup":
		p.why = notModelled(p.name, "looks at the group number of the interface")
	case "iiftype", "oiftype", "iifkind", "oifkind":
		p.why = notModelled(p.name, "looks at what kind of interface the packet used")
	case "skuid", "skgid", "cgroup":
		p.why = notModelled(p.name, "looks at which local program sent the packet")
	case "hour", "day", "time":
		p.why = notModelled(p.name, "depends on the time of day or the date")
	case "random":
		p.why = notModelled(p.name, "matches only some packets, at random or by count")
	case "cpu":
		p.why = notModelled(p.name, "depends on which processor handles the packet")
	default:
		p.why = notModelled(p.name, "")
	}
	return p
}

// metaName is a meta key as nft prints it: a few keys go without the word "meta".
func metaName(key string) string {
	switch key {
	case "iif", "oif", "iifname", "oifname", "iifgroup", "oifgroup":
		return key
	}
	return "meta " + key
}

func ctKey(o *object, family string) keyPart {
	key, dir := o.text("key"), o.text("dir")
	p := keyPart{name: "ct " + key}
	if dir != "" {
		p.name = "ct " + dir + " " + key
	}
	switch {
	case dir == "" && key == "state":
		p.f.Name, p.k = rules.FCtState, kCtState
	case dir == "" && key == "mark":
		p.f.Name, p.k = rules.FCtMark, kMark
	case dir == "" && key == "status":
		p.k = kCtStatus
	case dir == "" && key == "direction":
		p.f.Name, p.k = rules.FCtDirection, kCtDir
	case dir == "original" && key == "proto-dst":
		p.f.Name, p.k = rules.FCtOrigDport, kPort
	case dir == "original" && key == "ip daddr", dir == "original" && key == "daddr" && family == "ip":
		p.f.Name, p.k = rules.FCtOrigDaddr, kAddr4
	case dir == "original" && key == "ip6 daddr", dir == "original" && key == "daddr" && family == "ip6":
		p.f.Name, p.k = rules.FCtOrigDaddr, kAddr6
	case key == "helper":
		p.why = notModelled(p.name, "looks at which helper follows the connection")
	default:
		p.why = notModelled(p.name, "looks at a detail of the tracked connection")
	}
	return p
}

// ctx translates one rule.
type ctx struct {
	p      *parser
	t      *table
	out    []rules.Expr
	nf, l4 map[uint32]bool // IP versions and protocols the rule has already required
	// A statement that picks its target from a map turns the rule into several: the expressions
	// before it, then one of these tails each. altAt is where the tails go.
	alts  [][]rules.Expr
	altAt int
	last  bool // the expression being read is the rule's last
}

func (c *ctx) add(e rules.Expr) {
	if m, ok := e.(*rules.Match); ok && !m.Neg && len(m.Key) == 1 && !m.Key[0].HasMask && m.Values != nil && len(m.Values.Elems) == 1 {
		// A rule that already says "tcp" needs no second protocol match for "tcp dport".
		if a := m.Values.Elems[0][0]; a.Kind == rules.AtomNum && a.Lo == a.Hi {
			switch m.Key[0].Name {
			case rules.FNFProto:
				c.nf[a.Lo] = true
			case rules.FL4Proto:
				c.l4[a.Lo] = true
			}
		}
	}
	c.out = append(c.out, e)
}

// unknown adds a condition seaward cannot decide.
func (c *ctx) unknown(why string) { c.out = append(c.out, &rules.Unknown{Why: why}) }

// stop adds a statement seaward cannot follow.
func (c *ctx) stop(why string) { c.out = append(c.out, &rules.UnknownStmt{Why: why}) }

// need adds the matches a key implies and nft leaves out of its listing: "tcp dport 22" only
// matches TCP, and in an inet table "ip saddr" only matches IPv4.
func (c *ctx) need(p keyPart) {
	own := uint32(0)
	switch c.t.family {
	case "ip":
		own = 4
	case "ip6":
		own = 6
	}
	if p.nf != 0 && p.nf != own && !c.nf[p.nf] {
		c.add(rules.Eq(rules.FNFProto, rules.Num(p.nf)))
	}
	if p.l4 != 0 && !c.l4[p.l4] {
		c.add(rules.Eq(rules.FL4Proto, rules.Num(p.l4)))
	}
}

// keys reads a key that may be a concatenation, adding what its fields imply. A non-empty why
// means a field is not modelled.
func (c *ctx) keys(n *node) (fields []rules.Field, kinds []kind, name, why string) {
	parts := []*node{n}
	if k, v := n.obj().onePeek(); k == "concat" && v.isArr() {
		n.obj().one()
		parts = v.arr()
	}
	var names []string
	for _, x := range parts {
		p := keyOf(x, c.t.family)
		c.need(p)
		if p.k == kCtStatus {
			p.why = notModelled(p.name, "looks at several flags of the tracked connection at once")
		}
		if p.why != "" && why == "" {
			why = p.why
		}
		fields = append(fields, p.f)
		kinds = append(kinds, p.k)
		names = append(names, p.name)
	}
	if len(parts) == 0 && why == "" {
		// A key put together from nothing: nft writes no such thing, and nothing can be said
		// of what would match it.
		why = "this rule compares a key made of no field, which is not the way nft writes one"
	}
	return fields, kinds, strings.Join(names, " . "), why
}

// values reads the right-hand side of a comparison: a named set, an anonymous set, a list or one
// value.
func (c *ctx) values(ks []kind, n *node) (set *rules.Set, ref string, ok bool) {
	if s, isStr := n.str(); isStr && strings.HasPrefix(s, "@") {
		// nft refuses a lookup whose key does not fit the set, so a listing cannot hold one. A
		// set that is not there at all is for the engine to report.
		if si := c.t.sets[s[1:]]; si != nil && !si.set.Incomplete && len(si.kinds) != len(ks) {
			return nil, "", false
		}
		return nil, rules.SetKey(c.t.family, c.t.name, s[1:]), true
	}
	items := []*node{n}
	if o := n.obj(); o != nil && o.has("set") {
		k, v := o.one()
		if k != "set" || !v.isArr() {
			return nil, "", false
		}
		items = v.arr()
	} else if n.isArr() {
		items = n.arr()
	}
	set = &rules.Set{}
	for _, it := range items {
		e, ok := elemOf(ks, it)
		if !ok {
			return nil, "", false
		}
		set.Elems = append(set.Elems, e)
	}
	return set, "", true
}

// match translates one comparison.
func (c *ctx) match(o *object) {
	op := o.text("op")
	left, right := o.get("left"), o.get("right")
	switch k, v := left.obj().onePeek(); k {
	case "&":
		left.obj().one()
		c.masked(op, v, right)
		return
	case "concat":
		fields, kinds, name, why := c.keys(left)
		if why != "" {
			c.unknown(why)
			return
		}
		if op != "==" && op != "!=" && op != "in" {
			c.unknown(fmt.Sprintf("the %s match uses a comparison (%s) seaward does not know", clip(name), clip(op)))
			return
		}
		set, ref, ok := c.values(kinds, right)
		if !ok {
			c.unknown(fmt.Sprintf("the %s match compares against values seaward cannot read", clip(name)))
			return
		}
		c.add(&rules.Match{Key: fields, Neg: op == "!=", Values: set, SetRef: ref})
		return
	case "fib":
		left.obj().one()
		c.fib(op, v.obj(), right)
		return
	}
	p := keyOf(left, c.t.family)
	c.need(p)
	switch {
	case p.why != "":
		c.unknown(p.why)
	case p.k == kCtStatus:
		c.ctStatus(op, right)
	default:
		c.compare(p, op, right)
	}
}

// compare translates "key op value" for one modelled key.
func (c *ctx) compare(p keyPart, op string, right *node) {
	neg := false
	switch op {
	case "==", "in":
	case "!=":
		neg = true
	case "!":
		// "!" is "none of these bits": a negation for the fields that are sets of flags.
		if (p.k != kCtState && p.k != kTCPFlags) || p.f.HasMask {
			c.unknown(fmt.Sprintf("the %s match uses a comparison (!) seaward does not know for it", clip(p.name)))
			return
		}
		neg = true
	case "<", ">", "<=", ">=":
		set, ok := bound(p.k, op, right)
		if !ok {
			c.unknown(fmt.Sprintf("the %s match compares sizes (%s) in a way seaward cannot read", clip(p.name), op))
			return
		}
		c.add(&rules.Match{Key: []rules.Field{p.f}, Values: set})
		return
	default:
		c.unknown(fmt.Sprintf("the %s match uses a comparison (%s) seaward does not know", clip(p.name), clip(op)))
		return
	}
	if p.k == kTCPFlags && !p.f.HasMask && (op == "in" || op == "!") {
		// "tcp flags syn" asks whether any of the named flags is set; "!" whether none is.
		bits, ok := flagBits(right)
		if !ok {
			c.unknown(fmt.Sprintf("the %s match names flags seaward cannot read", clip(p.name)))
			return
		}
		f := p.f
		f.Mask, f.HasMask = bits, true
		c.add(&rules.Match{Key: []rules.Field{f}, Neg: op == "in", Values: rules.One(rules.Num(0))})
		return
	}
	set, ref, ok := c.values([]kind{p.k}, right)
	if !ok {
		c.unknown(fmt.Sprintf("the %s match compares against a value seaward cannot read", clip(p.name)))
		return
	}
	c.add(&rules.Match{Key: []rules.Field{p.f}, Neg: neg, Values: set, SetRef: ref})
}

// bound turns "< v", "> v" and the like into the range of values that pass. Nothing passes an
// empty range, which is what "< 0" means.
func bound(k kind, op string, right *node) (*rules.Set, bool) {
	if k == kAddr4 || k == kAddr6 {
		a, ok := addrOf(k, right)
		if !ok {
			return nil, false
		}
		lo, hi := netip.IPv4Unspecified(), netip.AddrFrom4([4]byte{255, 255, 255, 255})
		if k == kAddr6 {
			var ones [16]byte
			for i := range ones {
				ones[i] = 0xff
			}
			lo, hi = netip.IPv6Unspecified(), netip.AddrFrom16(ones)
		}
		switch op {
		case "<":
			hi = a.Prev()
		case "<=":
			hi = a
		case ">":
			lo = a.Next()
		case ">=":
			lo = a
		}
		if !lo.IsValid() || !hi.IsValid() {
			return &rules.Set{}, true
		}
		return rules.One(rules.Atom{Kind: rules.AtomRange, AddrLo: lo, AddrHi: hi}), true
	}
	max, numeric := numMax[k]
	v, ok := number(k, right)
	if !numeric || !ok {
		return nil, false
	}
	lo, hi := uint32(0), max
	switch op {
	case "<":
		if v == 0 {
			return &rules.Set{}, true
		}
		hi = v - 1
	case "<=":
		hi = v
	case ">":
		if v == max {
			return &rules.Set{}, true
		}
		lo = v + 1
	case ">=":
		lo = v
	}
	return rules.One(rules.NumRange(lo, hi)), true
}

// maskBits gives the prefix length of an address mask, or false when the mask has gaps.
func maskBits(m netip.Addr) (int, bool) {
	n, zero := 0, false
	for _, b := range m.AsSlice() {
		for i := 7; i >= 0; i-- {
			switch one := b&(1<<uint(i)) != 0; {
			case one && zero:
				return 0, false
			case one:
				n++
			default:
				zero = true
			}
		}
	}
	return n, true
}

// masked translates "key & mask op value".
func (c *ctx) masked(op string, operands, right *node) {
	xs := operands.arr()
	if len(xs) != 2 {
		c.unknown("this rule masks a value in a way seaward cannot read")
		return
	}
	p := keyOf(xs[0], c.t.family)
	c.need(p)
	if p.name == "ip frag-off" {
		// "ip frag-off & 0x1fff != 0" is how a later fragment is told apart (iptables -f).
		m, ok := xs[1].num()
		v, ok2 := right.num()
		if ok && ok2 && m == 0x1fff && v == 0 && (op == "!=" || op == "==") {
			if op == "!=" {
				c.add(&rules.Never{What: "later fragments only (ip frag-off): a first packet is never a later fragment"})
			} else {
				c.add(&rules.Always{What: "not a later fragment (ip frag-off): a first packet is never one"})
			}
			return
		}
	}
	if p.why != "" {
		c.unknown(p.why)
		return
	}
	switch p.k {
	case kMark:
		if m, ok := xs[1].u32(); ok {
			p.f.Mask, p.f.HasMask = m, true
			c.compare(p, op, right)
			return
		}
	case kTCPFlags:
		if m, ok := flagBits(xs[1]); ok {
			p.f.Mask, p.f.HasMask = m, true
			c.compare(p, op, right)
			return
		}
	case kAddr4, kAddr6:
		m, ok := addrOf(p.k, xs[1])
		a, ok2 := addrOf(p.k, right)
		if !ok || !ok2 || (op != "==" && op != "!=") {
			break
		}
		bits, whole := maskBits(m)
		if !whole {
			word := "source"
			if p.f.Name == rules.FDaddr {
				word = "destination"
			}
			c.unknown(fmt.Sprintf("the %s address match (%s & %s) has a mask with gaps in it, which seaward cannot represent", word, p.name, m))
			return
		}
		pfx := netip.PrefixFrom(a, bits)
		set := rules.One(rules.Pfx(pfx))
		if pfx.Masked().Addr() != a {
			set = &rules.Set{} // the value has bits the mask clears: nothing is equal to it
		}
		c.add(&rules.Match{Key: []rules.Field{p.f}, Neg: op == "!=", Values: set})
		return
	}
	c.unknown(fmt.Sprintf("the %s match looks at some bits of the value only, in a way seaward cannot read", clip(p.name)))
}

// fib translates the routing-table lookups: what kind of address this is, and the reverse path
// check.
func (c *ctx) fib(op string, o *object, right *node) {
	result := o.text("result")
	flags := o.get("flags").strs()
	has := map[string]bool{}
	for _, f := range flags {
		has[f] = true
	}
	name := "fib " + strings.Join(flags, " . ") + " " + result
	only := func(want ...string) bool {
		if len(has) != len(want) {
			return false
		}
		for _, w := range want {
			if !has[w] {
				return false
			}
		}
		return true
	}
	switch result {
	case "type":
		p := keyPart{k: kFibType, name: name}
		switch {
		case only("daddr"):
			p.f.Name = rules.FFibDaddrType
		case only("saddr"):
			p.f.Name = rules.FFibSaddrType
		case only("daddr", "iif"):
			p.f.Name = rules.FFibDaddrTypeIif
		case only("saddr", "iif"):
			p.f.Name = rules.FFibSaddrTypeIif
		case has["oif"]:
			c.unknown(fmt.Sprintf("the %s match asks what kind of address this is as the outgoing interface sees it, which seaward does not model", clip(name)))
			return
		default:
			c.unknown(fmt.Sprintf("the %s match looks the address up in a way seaward does not model", clip(name)))
			return
		}
		c.compare(p, op, right)
		return
	case "oif", "check":
		// "fib saddr . iif oif missing": no route back to the sender through the interface the
		// packet came in on. firewalld adds the mark to the lookup.
		if !only("saddr", "iif") && !only("saddr", "mark", "iif") || (op != "==" && op != "!=") {
			break
		}
		exists, ok := right.boolean()
		if v, isNum := right.num(); isNum && v == 0 {
			exists, ok = false, true
		}
		if !ok {
			break
		}
		if op == "!=" {
			exists = !exists
		}
		if exists {
			c.add(rules.Eq(rules.FRpfOK, rules.Num(1)))
		} else {
			c.add(rules.Eq(rules.FRpfOK, rules.Num(0)))
		}
		return
	}
	c.unknown(fmt.Sprintf("the %s match looks up a route for the packet, which seaward does not model", clip(name)))
}

// ctStatus translates "ct status": whether the connection had an address rewritten.
func (c *ctx) ctStatus(op string, right *node) {
	names := right.strs()
	dnat, snat := false, false
	for _, n := range names {
		switch n {
		case "dnat":
			dnat = true
		case "snat":
			snat = true
		default:
			c.unknown(fmt.Sprintf("the ct status match checks a flag of the tracked connection (%s), which seaward does not model", clip(n)))
			return
		}
	}
	if len(names) == 0 || right.obj() != nil {
		c.unknown("the ct status match compares against a value seaward cannot read")
		return
	}
	want := uint32(1)
	switch op {
	case "in":
	case "!":
		want = 0
	default:
		c.unknown("the ct status match compares every flag of the tracked connection at once, which seaward does not model")
		return
	}
	switch {
	case dnat && snat && want == 1:
		// either one
		c.add(&rules.Match{
			Key: []rules.Field{{Name: rules.FCtStatusDNAT}, {Name: rules.FCtStatusSNAT}},
			Values: &rules.Set{Elems: []rules.Elem{
				{rules.Num(1), rules.Atom{}},
				{rules.Atom{}, rules.Num(1)},
			}},
		})
	case dnat && snat:
		c.add(&rules.Match{
			Key:    []rules.Field{{Name: rules.FCtStatusDNAT}, {Name: rules.FCtStatusSNAT}},
			Values: &rules.Set{Elems: []rules.Elem{{rules.Num(0), rules.Num(0)}}},
		})
	case dnat:
		c.add(rules.Eq(rules.FCtStatusDNAT, rules.Num(want)))
	default:
		c.add(rules.Eq(rules.FCtStatusSNAT, rules.Num(want)))
	}
}
