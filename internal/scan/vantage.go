package scan

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// vantage is a Vantage with the packets that stand for it.
type vantage struct {
	Vantage
	direct bool // the machine has a public address there
	sides  []*side
}

// side is one address family of a vantage.
type side struct {
	v6      bool
	dsts    []netip.Addr // this machine's addresses packets are sent to
	nets    []netip.Prefix
	classes []srcClass // the first one stands for "everyone else"
}

// srcClass is one kind of sender the rules tell apart, and the address that stands for it.
type srcClass struct {
	label   string
	addr    netip.Addr
	generic bool
}

const maxClasses = 12

// Sources that stand for "anyone out there": the documentation networks, which no real machine
// uses, and the benchmarking network as a spare.
var (
	world4 = []string{"198.51.100.7", "203.0.113.7", "192.0.2.7", "198.18.0.7"}
	world6 = []string{"2001:db8:99::7", "2001:db8:77::7", "2001:db8:55::7"}
	cgnat  = netip.MustParsePrefix("100.64.0.0/10")
)

func isVPN(in host.Interface) bool {
	switch in.Kind {
	case "wireguard", "tun", "ipip", "gre", "sit", "xfrm", "vti", "ppp":
		return true
	}
	for _, p := range []string{"tailscale", "wg", "tun", "tap", "zt", "nordlynx", "ppp", "ipsec"} {
		if strings.HasPrefix(in.Name, p) {
			return true
		}
	}
	return false
}

// inside reports whether an interface leads to this machine's own containers, not to the outside.
func (b *builder) inside(in host.Interface) bool {
	if in.Kind == "veth" || in.Kind == "dummy" || in.Name == "docker0" || in.Name == "docker_gwbridge" ||
		strings.HasPrefix(in.Name, "br-") || strings.HasPrefix(in.Name, "veth") {
		return true
	}
	if b.h.Docker == nil {
		return false
	}
	for _, c := range b.h.Docker.Containers {
		for _, n := range c.Networks {
			for _, p := range in.Addrs {
				if (n.Addr.IsValid() && p.Contains(n.Addr)) || (n.Addr6.IsValid() && p.Contains(n.Addr6)) {
					return true
				}
			}
		}
	}
	return false
}

func public(a netip.Addr) bool {
	return !a.IsPrivate() && !cgnat.Contains(a) && !a.IsLinkLocalUnicast() && !a.IsLoopback()
}

// vantages lists where packets can come from: per outside interface, the wide world behind its
// default route and the network it is plugged into.
func (b *builder) vantages() []*vantage {
	var world, lan, vpn []*vantage
	for _, in := range b.h.Interfaces {
		if !in.Up || in.Loopback || b.inside(in) {
			continue
		}
		tunnel := isVPN(in)
		far := &vantage{Vantage: Vantage{Iface: in.Name, Scope: "world"}}
		near := &vantage{Vantage: Vantage{Iface: in.Name, Scope: "lan"}}
		if tunnel {
			near.Scope = "vpn"
		}
		var netNames []string
		for _, v6 := range []bool{false, true} {
			var dsts []netip.Addr
			var nets []netip.Prefix
			for _, p := range in.Addrs {
				a := p.Addr().Unmap()
				if a.Is6() != v6 || a.IsLinkLocalUnicast() {
					continue
				}
				dsts = append(dsts, a)
				if p.Bits() < a.BitLen() {
					n := netip.PrefixFrom(a, p.Bits()).Masked()
					nets = append(nets, n)
					netNames = append(netNames, n.String())
				}
				if public(a) {
					far.direct = true
				}
			}
			if len(dsts) == 0 {
				continue
			}
			if !tunnel {
				if cl := b.classes(in.Name, "world", v6, nets, dsts); len(cl) > 0 {
					far.sides = append(far.sides, &side{v6: v6, dsts: dsts, nets: nets, classes: cl})
				}
			}
			if cl := b.classes(in.Name, near.Scope, v6, nets, dsts); len(cl) > 0 {
				near.sides = append(near.sides, &side{v6: v6, dsts: dsts, nets: nets, classes: cl})
			}
		}
		if len(far.sides) > 0 {
			far.ID, far.Label, far.Short = "internet", "the internet", "internet"
			if !far.direct {
				far.ID, far.Label, far.Short = "outside", "outside the local network", "outside"
			}
			if len(world) > 0 {
				far.ID += ":" + in.Name
				far.Short += " " + in.Name
				far.Label += " (" + in.Name + ")"
			}
			world = append(world, far)
		}
		if len(near.sides) > 0 {
			if tunnel {
				near.ID, near.Label, near.Short = "vpn:"+in.Name, "VPN peers on "+in.Name, "VPN "+in.Name
				vpn = append(vpn, near)
			} else {
				near.ID, near.Short = "lan:"+in.Name, "LAN "+in.Name
				near.Label = "the local network on " + in.Name
				if len(netNames) > 0 {
					near.Label += " (" + strings.Join(netNames, ", ") + ")"
				}
				lan = append(lan, near)
			}
		}
	}
	return append(append(world, lan...), vpn...)
}

// classes picks the senders that stand for everyone a vantage covers: one address for "everyone
// else", and one more for each group of addresses some rule singles out.
func (b *builder) classes(iface, scope string, v6 bool, nets []netip.Prefix, dsts []netip.Addr) []srcClass {
	var cand []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() {
			cand = append(cand, a.Unmap())
		}
	}
	if scope == "world" {
		list := world4
		if v6 {
			list = world6
		}
		for _, s := range list {
			add(netip.MustParseAddr(s))
		}
	} else {
		for _, d := range dsts {
			add(d.Next())
			add(d.Next().Next())
			add(d.Prev())
		}
	}
	for _, p := range b.preds {
		for i, v := range p.iv {
			if i == 6 {
				break
			}
			add(v.lo)
			add(v.hi)
			add(v.lo.Next())
			add(v.hi.Next())
			add(v.lo.Prev())
		}
	}
	inNets := func(a netip.Addr) (netip.Prefix, bool) {
		for _, n := range nets {
			if n.Contains(a) {
				return n, true
			}
		}
		return netip.Prefix{}, false
	}
	valid := func(a netip.Addr) bool {
		if a.Is6() != v6 || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			return false
		}
		for _, d := range dsts {
			if d == a {
				return false
			}
		}
		n, near := inNets(a)
		if near && !v6 && n.Bits() < 31 && (a == n.Addr() || a == lastAddr(n)) {
			return false // the network's own address and its broadcast address
		}
		dev, routed := b.e.IifFor(a)
		switch scope {
		case "world":
			if near {
				return false
			}
			if len(b.h.Routes) == 0 {
				return true // no route table in the snapshot: take the interface at its word
			}
			return routed && dev == iface
		case "lan":
			return near && (!routed || dev == iface)
		default: // vpn: its routes often live outside the main table
			return near || len(nets) == 0 || (routed && dev == iface)
		}
	}
	type pick struct {
		addr netip.Addr
		sig  string
		bits int
	}
	var picks []pick
	seen := map[string]bool{}
	for _, a := range cand {
		if !valid(a) {
			continue
		}
		sig := make([]byte, len(b.preds))
		bits := 0
		for i, p := range b.preds {
			sig[i] = '0'
			if _, ok := p.find(a); ok {
				sig[i] = '1'
				bits++
			}
		}
		if seen[string(sig)] {
			continue
		}
		seen[string(sig)] = true
		picks = append(picks, pick{a, string(sig), bits})
	}
	if len(picks) == 0 {
		return nil
	}
	// "Everyone else" is the sender the fewest rules single out; the first candidates are the
	// plain ones, so a tie goes to them.
	sort.SliceStable(picks, func(i, j int) bool { return picks[i].bits < picks[j].bits })
	if len(picks) > maxClasses {
		picks = picks[:maxClasses]
	}
	out := make([]srcClass, 0, len(picks))
	for i, p := range picks {
		c := srcClass{addr: p.addr, generic: i == 0}
		switch {
		case i > 0:
			c.label = b.label(p.addr)
		case scope == "world":
			c.label = "anyone"
		case scope == "lan":
			c.label = "anyone on the local network"
		default:
			c.label = "any VPN peer"
		}
		out = append(out, c)
	}
	return out
}

// label names the group of senders an address stands for: the narrowest thing a rule says about it.
func (b *builder) label(a netip.Addr) string {
	var best ival
	name, found := "", false
	for _, p := range b.preds {
		if v, ok := p.find(a); ok && (!found || within(v, best)) {
			best, name, found = v, p.name, true
		}
	}
	switch {
	case !found:
		return a.String()
	case name != "":
		return "the set " + name
	}
	return best.String()
}

// ival is a range of addresses, both ends included.
type ival struct{ lo, hi netip.Addr }

func within(a, b ival) bool { return a.lo.Compare(b.lo) >= 0 && a.hi.Compare(b.hi) <= 0 }

func (v ival) String() string {
	if v.lo == v.hi {
		return v.lo.String()
	}
	x, y := v.lo.AsSlice(), v.hi.AsSlice()
	bits := 0
	for i := range x {
		d := x[i] ^ y[i]
		if d == 0 {
			bits += 8
			continue
		}
		for m := byte(0x80); m != 0 && d&m == 0; m >>= 1 {
			bits++
		}
		break
	}
	if p := netip.PrefixFrom(v.lo, bits); p.Masked().Addr() == v.lo && lastAddr(p) == v.hi {
		return p.String()
	}
	return v.lo.String() + " to " + v.hi.String()
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// pred is one thing the rules say about a sender's address: "is it in here?".
type pred struct {
	name string // a named set, or ""
	iv   []ival
}

// find is the narrowest range of the predicate that holds the address.
func (p *pred) find(a netip.Addr) (ival, bool) {
	var best ival
	ok := false
	for _, v := range p.iv {
		if v.lo.Is4() != a.Is4() || a.Compare(v.lo) < 0 || a.Compare(v.hi) > 0 {
			continue
		}
		if !ok || within(v, best) {
			best, ok = v, true
		}
	}
	return best, ok
}

func atomIval(a rules.Atom) (ival, bool) {
	switch a.Kind {
	case rules.AtomPrefix:
		if !a.Prefix.IsValid() || a.Prefix.Bits() == 0 {
			return ival{}, false
		}
		return ival{a.Prefix.Masked().Addr().Unmap(), lastAddr(a.Prefix).Unmap()}, true
	case rules.AtomRange:
		if !a.AddrLo.IsValid() || !a.AddrHi.IsValid() {
			return ival{}, false
		}
		return ival{a.AddrLo.Unmap(), a.AddrHi.Unmap()}, true
	}
	return ival{}, false
}

// sourcePreds collects every way the rules, and the firewall manager's own list, tell senders
// apart by address. Two senders no predicate tells apart get the same treatment everywhere.
func (b *builder) sourcePreds() []pred {
	var out []pred
	seen := map[string]bool{}
	add := func(name string, iv []ival) {
		if len(iv) == 0 {
			return
		}
		key := name + "|" + iv[0].lo.String() + "|" + iv[len(iv)-1].hi.String() + "|" + string(rune(len(iv)))
		if !seen[key] {
			seen[key] = true
			out = append(out, pred{name, iv})
		}
	}
	fromSet := func(key []rules.Field, set *rules.Set, name string, each bool) {
		idx := -1
		for i, f := range key {
			if f.Name == rules.FSaddr {
				idx = i
			}
		}
		if idx < 0 || set == nil {
			return
		}
		var all []ival
		for _, el := range set.Elems {
			if idx < len(el) {
				if v, ok := atomIval(el[idx]); ok {
					all = append(all, v)
				}
			}
		}
		// One field and one outcome: being in the set is all that counts. Otherwise each element
		// may lead somewhere else, so each is told apart.
		if !each && len(key) == 1 && len(set.Verdicts) == 0 {
			add(name, all)
			return
		}
		for i, v := range all {
			if i == 16 {
				break
			}
			add(name, []ival{v})
		}
	}
	for _, t := range b.rs.Tables {
		for _, cn := range t.Order {
			c := t.Chains[cn]
			if c == nil {
				continue
			}
			for _, r := range c.Rules {
				for _, x := range r.Exprs {
					switch m := x.(type) {
					case *rules.Match:
						if m.Values != nil {
							fromSet(m.Key, m.Values, "", false)
						} else {
							fromSet(m.Key, b.rs.Sets[m.SetRef], setName(m.SetRef), false)
						}
					case *rules.VerdictMap:
						if m.SetRef != "" {
							fromSet(m.Key, b.rs.Sets[m.SetRef], setName(m.SetRef), true)
							continue
						}
						s := &rules.Set{}
						for _, en := range m.Entries {
							s.Elems = append(s.Elems, en.Key)
						}
						fromSet(m.Key, s, "", true)
					}
				}
			}
		}
	}
	if b.f != nil {
		for _, r := range b.f.Rules {
			if r.From.IsValid() && r.From.Bits() > 0 {
				add("", []ival{{r.From.Masked().Addr().Unmap(), lastAddr(r.From).Unmap()}})
			}
		}
	}
	return out
}

func setName(key string) string {
	if i := strings.LastIndexByte(key, 0); i >= 0 {
		return key[i+1:]
	}
	return key
}
