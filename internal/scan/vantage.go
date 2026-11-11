package scan

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// vantage is a Vantage with the packets that stand for it.
type vantage struct {
	Vantage
	direct bool // the machine has a public address there
	cut    bool // the rules tell more senders apart there than were asked: see maxClasses
	sides  []*side
}

// side is one address family of a vantage.
type side struct {
	v6      bool
	dsts    []netip.Addr // this machine's addresses packets are sent to
	own     int          // how many of them, the first ones, sit on the vantage's own interface
	nets    []netip.Prefix
	classes []srcClass // the first one stands for "everyone else"
}

// srcClass is one kind of sender the rules tell apart, and the address that stands for it.
type srcClass struct {
	label   string
	addr    netip.Addr
	generic bool
}

// maxClasses is how many groups of senders the scan asks about from one place over one address
// family. No ordinary ruleset comes near it; a report that reaches it says so.
const maxClasses = 1024

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

// elsewhere lists the machine's addresses of one family that sit on another interface than in: a
// spare address on the loopback or on a dummy interface, a bridge's address, another card's. Linux
// takes a packet for any address it holds, whichever interface it arrives on, so each of them is
// one more address a sender can aim at. The loopback range itself is left out: the kernel drops a
// packet for it that comes from outside.
func (b *builder) elsewhere(in host.Interface, v6 bool) []netip.Addr {
	seen := map[netip.Addr]bool{}
	for _, p := range in.Addrs {
		seen[p.Addr().Unmap()] = true
	}
	var out []netip.Addr
	for _, o := range b.h.Interfaces {
		if o.Name == in.Name {
			continue
		}
		for _, p := range o.Addrs {
			a := p.Addr().Unmap()
			if a.Is6() != v6 || seen[a] || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// heldOn names the interface an address of this machine sits on.
func (b *builder) heldOn(a netip.Addr) string {
	for _, in := range b.h.Interfaces {
		for _, p := range in.Addrs {
			if p.Addr().Unmap() == a {
				return in.Name
			}
		}
	}
	return ""
}

// vantages lists where packets can come from: per outside interface, the wide world behind its
// default route and the network it is plugged into. From each, packets are sent to the
// interface's own addresses and to the machine's addresses elsewhere: all of them from the
// network it is plugged into, the public ones from the wide world, which can route no other.
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
			var own []netip.Addr
			var nets []netip.Prefix
			speaks := false // the interface has an address of this family, if only a link-local one
			for _, p := range in.Addrs {
				a := p.Addr().Unmap()
				if a.Is6() != v6 {
					continue
				}
				speaks = true
				if a.IsLinkLocalUnicast() {
					continue
				}
				own = append(own, a)
				if p.Bits() < a.BitLen() {
					n := netip.PrefixFrom(a, p.Bits()).Masked()
					nets = append(nets, n)
					netNames = append(netNames, n.String())
				}
				if public(a) {
					far.direct = true
				}
			}
			if !speaks {
				continue
			}
			all := own[:len(own):len(own)]
			wide := own[:len(own):len(own)]
			for _, a := range b.elsewhere(in, v6) {
				all = append(all, a)
				if public(a) {
					wide = append(wide, a)
				}
			}
			if len(all) == 0 {
				continue
			}
			if !tunnel && len(wide) > 0 {
				if cl, cut := b.classes(in.Name, "world", v6, nets, own, wide); len(cl) > 0 {
					far.sides = append(far.sides, &side{v6: v6, dsts: wide, own: len(own), nets: nets, classes: cl})
					far.direct = far.direct || len(wide) > len(own)
					far.cut = far.cut || cut
				}
			}
			if cl, cut := b.classes(in.Name, near.Scope, v6, nets, own, all); len(cl) > 0 {
				near.sides = append(near.sides, &side{v6: v6, dsts: all, own: len(own), nets: nets, classes: cl})
				near.cut = near.cut || cut
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
// else", and one more for each group of addresses some rule singles out. own are the interface's
// addresses, dsts every address packets are sent to; a sender is never one of those.
//
// Every stretch of addresses the rules cannot tell apart is looked at (see atlas), so a group is
// missed only when none of its addresses can arrive here, or past maxClasses. cut says the
// ceiling was reached and groups were left out: the report then claims nothing about them.
func (b *builder) classes(iface, scope string, v6 bool, nets []netip.Prefix, own, dsts []netip.Addr) (classes []srcClass, cut bool) {
	// The plain senders come first, so that "everyone else" is one of them whenever it can be.
	var plain []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() {
			plain = append(plain, a.Unmap())
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
		for _, d := range own {
			add(d.Next())
			add(d.Next().Next())
			add(d.Prev())
		}
	}
	valid := b.sender(iface, scope, v6, nets, dsts)
	at := b.atlas(v6)
	type pick struct {
		addr netip.Addr
		held int // which of the atlas's sets of predicates hold it
	}
	var picks []pick
	taken := make([]bool, len(at.held))
	for _, a := range plain {
		if !valid(a) {
			continue
		}
		if h := at.find(a); !taken[h] {
			taken[h] = true
			picks = append(picks, pick{a, h})
		}
	}
	for i, a := range at.starts {
		if h := at.where[i]; !taken[h] && valid(a) {
			taken[h] = true
			picks = append(picks, pick{a, h})
		}
	}
	if len(picks) == 0 {
		return nil, false
	}
	// "Everyone else" is the sender the fewest rules single out; the first candidates are the
	// plain ones, so a tie goes to them.
	sort.SliceStable(picks, func(i, j int) bool { return len(at.held[picks[i].held]) < len(at.held[picks[j].held]) })
	if len(picks) > maxClasses {
		picks = picks[:maxClasses]
		cut, b.crowded = true, true
	}
	out := make([]srcClass, 0, len(picks))
	for i, p := range picks {
		c := srcClass{addr: p.addr, generic: i == 0}
		switch {
		case i > 0:
			c.label = b.label(p.addr, at.held[p.held])
		case scope == "world":
			c.label = "anyone"
		case scope == "lan":
			c.label = "anyone on the local network"
		default:
			c.label = "any VPN peer"
		}
		out = append(out, c)
	}
	return out, cut
}

// sender says which addresses can send a packet that arrives on iface as part of scope: ordinary
// addresses of the right family, none of them this machine's own, that lie where the scope says
// (on the interface's networks for "lan", off them and routed through it for "world").
func (b *builder) sender(iface, scope string, v6 bool, nets []netip.Prefix, dsts []netip.Addr) func(netip.Addr) bool {
	inNets := func(a netip.Addr) (netip.Prefix, bool) {
		for _, n := range nets {
			if n.Contains(a) {
				return n, true
			}
		}
		return netip.Prefix{}, false
	}
	return func(a netip.Addr) bool {
		// An IPv4 address written as an IPv6 one (::ffff:192.0.2.1) is never on the wire as a sender.
		if a.Is6() != v6 || a.Is4In6() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
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
}

// atlas is one address family cut into stretches of addresses that no predicate tells apart and
// that are all possible senders or none of them: every address of a stretch is in the same
// predicates as its first one, is routed like it and is as ordinary or as special. Asking about
// the first address of each stretch is therefore asking about every address there is.
type atlas struct {
	starts []netip.Addr // where each stretch starts, ascending; the first is the family's zero
	where  []int        // per stretch: which entry of held is true of it
	held   [][]int32    // the distinct sets of predicates, each a list of indexes into builder.preds
}

// find is the entry of held that is true of an address.
func (at *atlas) find(a netip.Addr) int {
	i := sort.Search(len(at.starts), func(i int) bool { return at.starts[i].Compare(a) > 0 })
	return at.where[max(i-1, 0)]
}

// atlas cuts a family where a stretch can end: at the start of every range a predicate names and
// right after its end, and at the same two points of everything that decides whether an address
// can be a sender at all (the machine's networks and addresses, its routes, the special ranges).
func (b *builder) atlas(v6 bool) *atlas {
	if at := b.atlases[v6]; at != nil {
		return at
	}
	var cuts []netip.Addr
	cut := func(a netip.Addr) {
		if a.IsValid() && a.Is6() == v6 {
			cuts = append(cuts, a)
		}
	}
	span := func(lo, hi netip.Addr) {
		cut(lo)
		cut(hi.Next())
	}
	// A network is read the way the engine reads routes and addresses: the address in its plain
	// form, the length as written. One that is no network then (an IPv4 address in its IPv6 form
	// with an IPv6 length) matches nothing there and cuts nothing here.
	whole := func(p netip.Prefix) {
		if p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked(); p.IsValid() {
			span(p.Addr(), lastAddr(p))
		}
	}
	special := []string{"0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"}
	zero := netip.IPv4Unspecified()
	if v6 {
		special = []string{"::/128", "::1/128", "::ffff:0:0/96", "fe80::/10", "ff00::/8"}
		zero = netip.IPv6Unspecified()
	}
	cut(zero)
	for _, s := range special {
		p := netip.MustParsePrefix(s)
		span(p.Addr(), lastAddr(p))
	}
	for _, in := range b.h.Interfaces {
		for _, p := range in.Addrs {
			// The address itself, its network, and that network's first and last address, which
			// are no senders on IPv4.
			a := p.Addr().Unmap()
			span(a, a)
			if n := netip.PrefixFrom(a, p.Bits()).Masked(); n.IsValid() {
				whole(n)
				span(n.Addr(), n.Addr())
				span(lastAddr(n), lastAddr(n))
			}
		}
	}
	for _, r := range b.h.Routes {
		if r.Dst.IsValid() {
			whole(r.Dst)
		}
	}
	// One event where a predicate starts to hold and one where it stops. The ranges of a
	// predicate do not overlap (newPred), so its count is 0 or 1 but for the moment two of them
	// meet.
	type event struct {
		at   netip.Addr
		pred int32
		on   bool
	}
	var events []event
	for i := range b.preds {
		for _, g := range b.preds[i].groups {
			if g.lo.Is6() != v6 {
				continue
			}
			span(g.lo, g.hi)
			events = append(events, event{g.lo, int32(i), true})
			if end := g.hi.Next(); end.IsValid() {
				events = append(events, event{end, int32(i), false})
			}
		}
	}
	slices.SortFunc(cuts, netip.Addr.Compare)
	cuts = slices.Compact(cuts)
	slices.SortStableFunc(events, func(x, y event) int { return x.at.Compare(y.at) })

	at := &atlas{starts: cuts, where: make([]int, len(cuts))}
	count := make([]int, len(b.preds))
	var active []int32 // the predicates that hold, ascending
	var key []byte
	known := map[string]int{}
	next := 0
	for i, c := range cuts {
		for ; next < len(events) && events[next].at.Compare(c) <= 0; next++ {
			e := events[next]
			j, _ := slices.BinarySearch(active, e.pred)
			switch {
			case e.on:
				if count[e.pred]++; count[e.pred] == 1 {
					active = slices.Insert(active, j, e.pred)
				}
			default:
				if count[e.pred]--; count[e.pred] == 0 {
					active = slices.Delete(active, j, j+1)
				}
			}
		}
		key = key[:0]
		for _, p := range active {
			key = binary.LittleEndian.AppendUint32(key, uint32(p))
		}
		h, ok := known[string(key)]
		if !ok {
			h = len(at.held)
			known[string(key)] = h
			at.held = append(at.held, slices.Clone(active))
		}
		at.where[i] = h
	}
	if b.atlases == nil {
		b.atlases = map[bool]*atlas{}
	}
	b.atlases[v6] = at
	return at
}

// label names the group of senders an address stands for: the narrowest thing a rule says about
// it. held lists the predicates that hold the address.
func (b *builder) label(a netip.Addr, held []int32) string {
	var best ival
	name, found := "", false
	for _, i := range held {
		p := &b.preds[i]
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
	if !p.IsValid() {
		return netip.Addr{}
	}
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
	// iv are the ranges, by where they start; of two that start together the wider comes first.
	iv []ival
	// groups are the same ranges with those that overlap run together, so that no two groups
	// share an address and an address is found by halving.
	groups []group
}

// group is a run of ranges of one predicate that overlap: iv[from:to], which together cover
// lo to hi without a gap.
type group struct {
	lo, hi   netip.Addr
	from, to int
}

// newPred sorts the ranges and runs the overlapping ones together, once. A range that is none
// (its ends the wrong way round, or one of them IPv4 and the other IPv6) holds no address and
// is left out.
func newPred(name string, iv []ival) pred {
	iv = slices.DeleteFunc(slices.Clone(iv), func(v ival) bool {
		return !v.lo.IsValid() || v.lo.BitLen() != v.hi.BitLen() || v.lo.Compare(v.hi) > 0
	})
	slices.SortFunc(iv, func(x, y ival) int {
		if c := x.lo.Compare(y.lo); c != 0 {
			return c
		}
		return y.hi.Compare(x.hi)
	})
	iv = slices.Compact(iv)
	p := pred{name: name, iv: iv}
	for i, v := range iv {
		// netip orders every IPv4 address before every IPv6 one, so two families never run together.
		if n := len(p.groups); n > 0 && v.lo.Compare(p.groups[n-1].hi) <= 0 {
			g := &p.groups[n-1]
			g.to = i + 1
			if v.hi.Compare(g.hi) > 0 {
				g.hi = v.hi
			}
			continue
		}
		p.groups = append(p.groups, group{lo: v.lo, hi: v.hi, from: i, to: i + 1})
	}
	return p
}

// key spells the predicate out, so that two rules that say the same thing count once.
func (p *pred) key() string {
	k := make([]byte, 0, len(p.name)+1+len(p.iv)*10)
	k = append(append(k, p.name...), 0)
	for _, v := range p.iv {
		k = append(append(append(k, byte(v.lo.BitLen())), v.lo.AsSlice()...), v.hi.AsSlice()...)
	}
	return string(k)
}

// find is the narrowest range of the predicate that holds the address.
func (p *pred) find(a netip.Addr) (ival, bool) {
	i := sort.Search(len(p.groups), func(i int) bool { return p.groups[i].hi.Compare(a) >= 0 })
	if i == len(p.groups) || p.groups[i].lo.Compare(a) > 0 {
		return ival{}, false
	}
	var best ival
	ok := false
	for _, v := range p.iv[p.groups[i].from:p.groups[i].to] {
		if a.Compare(v.lo) < 0 || a.Compare(v.hi) > 0 {
			continue
		}
		if !ok || within(v, best) {
			best, ok = v, true
		}
	}
	return best, ok
}

// atomIval is the range of addresses an atom holds, as the engine compares it with a packet: in
// the atom's own address family, both ends. An IPv6 network is an IPv6 range even where it ends
// on an address that could be read as an IPv4 one (::/80 ends at ::ffff:255.255.255.255).
func atomIval(a rules.Atom) (ival, bool) {
	switch a.Kind {
	case rules.AtomPrefix:
		if !a.Prefix.IsValid() || a.Prefix.Bits() == 0 {
			return ival{}, false
		}
		return ival{a.Prefix.Masked().Addr(), lastAddr(a.Prefix)}, true
	case rules.AtomRange:
		lo, hi := a.AddrLo, a.AddrHi
		if !lo.IsValid() || !hi.IsValid() {
			return ival{}, false
		}
		// The engine compares both ends with the packet as they are. A range from an IPv4 address
		// to an IPv6 one holds every IPv4 address from the first on, since each sorts before
		// every IPv6 address; the other way round, and with its ends in the wrong order, none.
		if lo.Is4() && !hi.Is4() {
			hi = netip.AddrFrom4([4]byte{255, 255, 255, 255})
		}
		if lo.BitLen() != hi.BitLen() || lo.Compare(hi) > 0 {
			return ival{}, false
		}
		return ival{lo, hi}, true
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
		p := newPred(name, iv)
		if key := p.key(); !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	// A named set is read once however many rules look it up.
	read := map[string]bool{}
	fromSet := func(key []rules.Field, set *rules.Set, ref string, each bool) {
		idx := -1
		for i, f := range key {
			if f.Name == rules.FSaddr {
				idx = i
			}
		}
		if idx < 0 || set == nil {
			return
		}
		// One field and one outcome: being in the set is all that counts. Otherwise each element
		// may lead somewhere else, so each is told apart.
		each = each || len(key) != 1 || len(set.Verdicts) != 0
		if ref != "" {
			once := ref + "\x00" + string(rune('0'+idx)) + map[bool]string{true: "each", false: "all"}[each]
			if read[once] {
				return
			}
			read[once] = true
		}
		name := setName(ref)
		var all []ival
		for _, el := range set.Elems {
			if idx < len(el) {
				if v, ok := atomIval(el[idx]); ok {
					all = append(all, v)
				}
			}
		}
		if !each {
			add(name, all)
			return
		}
		for _, v := range all {
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
							fromSet(m.Key, b.rs.Sets[m.SetRef], m.SetRef, false)
						}
					case *rules.VerdictMap:
						if m.SetRef != "" {
							fromSet(m.Key, b.rs.Sets[m.SetRef], m.SetRef, true)
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
				add("", []ival{{r.From.Masked().Addr(), lastAddr(r.From)}})
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
