package scan

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

type builder struct {
	rs    *rules.Ruleset
	h     *host.Host
	e     *engine.Engine
	f     *host.Frontend // the firewall manager, when one is active
	preds []pred
	// atlases holds, per address family (true is IPv6), the family cut into the stretches of
	// addresses the predicates cannot tell apart.
	atlases map[bool]*atlas
	notes   []string
	// ranges are the port ranges asked about in part, by name and by their ends, and cut says the
	// list of ports hit its ceiling.
	ranges []string
	parts  []partRange
	cut    bool
	// more says a port that can be reached stands for others of its range that were not asked
	// one by one, so the count of reachable ports is the least there are.
	more bool
	// moreUndecided says the same of a port that could not be decided.
	moreUndecided bool
	// only, when set, is the one port that is asked about (One): no other is a candidate, a range
	// is asked for that port and not in part, and the ceiling of ports does not come into it.
	only *portKey
	// crowded says the rules tell more groups of senders apart than the scan asks about.
	crowded bool
}

func newBuilder(rs *rules.Ruleset, h *host.Host) *builder {
	if rs == nil {
		rs = &rules.Ruleset{}
	}
	if h == nil {
		h = &host.Host{}
	}
	b := &builder{rs: rs, h: h, e: engine.New(rs, h)}
	if f := h.Frontend; f != nil {
		if f.Active {
			b.f = f
		} else {
			b.notes = append(b.notes, "The firewall manager "+f.Tool+" is installed and not active, so it has no say here.")
		}
	}
	b.preds = b.sourcePreds()
	return b
}

// Run scans a machine: every port something listens on, Docker publishes, a rule redirects or the
// firewall manager names, seen from every place a packet can come from.
func Run(rs *rules.Ruleset, h *host.Host) *Report {
	b := newBuilder(rs, h)
	rep := &Report{Host: b.h.Name, Vantages: []Vantage{}, Ports: []Port{}, Caveat: Caveat}
	vs := b.vantages()
	for _, v := range vs {
		rep.Vantages = append(rep.Vantages, v.Vantage)
		if v.Scope == "world" && !v.direct {
			b.notes = append(b.notes, "This machine has no public address on "+v.Iface+". \"Outside the local network\" means whatever the device in front of it (a router, a cloud gateway) passes on.")
		}
	}
	if b.f != nil {
		rep.Frontend = &Frontend{Tool: b.f.Tool, Default: b.f.DefaultIncoming, Allows: b.allows()}
	}
	asked := b.candidates()
	isAsked := make(map[portKey]bool, len(asked))
	for _, k := range asked {
		isAsked[k] = true
	}
	for _, k := range asked {
		p := b.port(k, vs)
		if len(p.Cells) > 0 {
			rep.Ports = append(rep.Ports, p)
		}
		// In a range asked in part, a port stands for the ports after it up to the next one asked:
		// a count of such ports is a count of at least that many.
		if k.port < 65535 && !isAsked[portKey{k.proto, k.port + 1}] {
			stands := false
			for _, r := range b.parts {
				stands = stands || (r.proto == k.proto && r.lo <= k.port && k.port < r.hi)
			}
			switch p.Finding {
			case Exposed, Open, Limited:
				b.more = b.more || stands
			case Undecided:
				b.moreUndecided = b.moreUndecided || stands
			}
		}
	}
	if len(b.ranges) > 0 {
		b.notes = append(b.notes, "A long range of ports is asked about at its two ends and at every port inside it that a rule, a listener or the target of a rewrite sets apart; the ports between fare like the nearest one below them that was asked: "+list(b.ranges)+".")
	}
	// A ceiling that was reached is more than a note: what lies beyond it was not asked.
	if b.crowded {
		rep.Partial = append(rep.Partial, sendersCut)
	}
	if b.cut {
		rep.Partial = append(rep.Partial, portsCut)
	}
	sort.SliceStable(rep.Ports, func(i, j int) bool {
		x, y := rep.Ports[i], rep.Ports[j]
		if rank(x) != rank(y) {
			return rank(x) < rank(y)
		}
		if x.Port != y.Port {
			return x.Port < y.Port
		}
		return x.Proto < y.Proto
	})
	unread := map[string]bool{}
	for _, u := range b.rs.Unread {
		if !unread[u.Why] {
			unread[u.Why] = true
			rep.Unread = append(rep.Unread, u.Why)
		}
	}
	// A chain that was not followed is named once, when some packet the scan sent passes it.
	hung := map[string]bool{}
	for _, p := range rep.Ports {
		for _, c := range p.Cells {
			for _, u := range c.Unknowns {
				hung[u] = true
			}
		}
	}
	for _, u := range b.rs.Unfollowed {
		if hung[u.Why] {
			hung[u.Why] = false
			rep.Unfollowed = append(rep.Unfollowed, sentence(u.Why))
		}
	}
	seen := map[string]bool{}
	for _, list := range [][]string{b.notes, b.h.Notes, b.rs.Notes} {
		for _, n := range list {
			if n = sentence(n); n != "" && !seen[n] && !unread[n] {
				seen[n] = true
				rep.Notes = append(rep.Notes, n)
			}
		}
	}
	b.sum(rep, len(vs))
	return rep
}

// One answers for a port the report has no row for although the scan has reason to ask about it:
// a port inside a long range that was asked about in part, or one the scan did not come to
// before its ceiling of ports. The port is asked about by itself, as the scan would have asked.
// proto "" stands for tcp and udp. A port the scan has no reason to ask about gets nothing:
// nothing listens on it, and no rule sends its packets anywhere.
func One(rs *rules.Ruleset, h *host.Host, proto string, port uint16) []Port {
	var out []Port
	for _, pr := range []string{"tcp", "udp"} {
		if proto != "" && proto != pr {
			continue
		}
		b := newBuilder(rs, h)
		vs := b.vantages()
		k := portKey{pr, port}
		b.only = &k
		if len(b.candidates()) == 0 {
			continue
		}
		if p := b.port(k, vs); len(p.Cells) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// Trace follows one packet per outside address of the machine, from one sender, for the "why" view.
func Trace(rs *rules.Ruleset, h *host.Host, proto string, port uint16, from netip.Addr) []Cell {
	b := newBuilder(rs, h)
	k := portKey{proto, port}
	from = from.Unmap()
	iif, _ := b.e.IifFor(from)
	var out []Cell
	for _, in := range b.h.Interfaces {
		if !in.Up || in.Loopback {
			continue
		}
		// A named sender arrives where the routes say it does, even on an interface the scan
		// itself leaves out (a container's side of the machine).
		if iif != "" {
			if in.Name != iif {
				continue
			}
		} else if b.inside(in) {
			continue
		}
		v := &vantage{Vantage: Vantage{ID: "from:" + in.Name, Iface: in.Name, Scope: "world"}}
		c := srcClass{label: from.String(), addr: from}
		seen := map[string]bool{}
		own, near := 0, false
		for _, p := range in.Addrs {
			a := p.Addr().Unmap()
			if a.Is6() != from.Is6() || a.IsLinkLocalUnicast() || a == from {
				continue
			}
			near = near || p.Contains(from)
			sh := b.shoot(k, v, a.Is6(), c, a)
			seen[sh.key(a)] = true
			out = append(out, sh.cell)
			own++
		}
		// The machine's addresses elsewhere, where the answer there is another one: all of them for
		// a sender on the interface's own network, the public ones for anyone further away.
		for _, a := range b.elsewhere(in, from.Is6()) {
			if a == from || (!near && !public(a)) {
				continue
			}
			sh := b.shoot(k, v, a.Is6(), c, a)
			key := sh.key(a)
			if seen[key] || (own > 0 && sh.res.Class == engine.Closed) {
				continue
			}
			seen[key] = true
			b.elsewhereNote(sh, a)
			out = append(out, sh.cell)
		}
	}
	return out
}

func rank(p Port) int {
	switch p.Severity {
	case "high":
		return 0
	case "medium":
		return 1
	case "unknown":
		return 2
	case "info":
		return 3
	}
	switch p.Finding {
	case Open:
		return 4
	case Shadowed:
		return 5
	case Dead:
		return 6
	case Blocked:
		return 7
	case Closed:
		return 8
	}
	return 9
}

type portKey struct {
	proto string
	port  uint16
}

func (k portKey) String() string { return fmt.Sprintf("%s %d", k.proto, k.port) }

// candidates lists the ports worth asking about: those something listens on, those Docker
// publishes, those the firewall manager names, and those a rule sends somewhere else, for which
// nothing has to listen here. The destination ports of ordinary accept rules are left out on
// purpose: a firewall manager's built-in chains name dozens nobody uses, and a port that is
// merely accepted, with nothing listening and nothing rewriting it, answers nobody.
//
// Only tcp and udp ports are asked about. A rewrite of another protocol with ports (sctp, dccp)
// is followed by "seaward why" and is no row of a scan.
func (b *builder) candidates() []portKey {
	seen := map[portKey]bool{}
	var out []portKey
	add := func(proto string, port uint16) {
		k := portKey{proto, port}
		if port == 0 || (proto != "tcp" && proto != "udp") || seen[k] {
			return
		}
		if b.only != nil && k != *b.only {
			return
		}
		if len(out) >= maxPorts {
			b.cut = true
			return
		}
		seen[k] = true
		out = append(out, k)
	}
	for _, l := range b.h.Listeners {
		if l.Netns == "" {
			add(l.Proto, l.Port)
		}
	}
	if b.h.Docker != nil {
		for _, c := range b.h.Docker.Containers {
			for _, p := range c.Ports {
				add(p.Proto, p.HostPort)
			}
		}
	}
	// Ports a rule sends somewhere else: nothing needs to listen here for those to answer. First
	// the rules that name their ports themselves, whether a port stands in the rule or in a set
	// the rule looks up, alone or beside other fields.
	breaks := b.portBreaks()
	for _, t := range b.rs.Tables {
		for _, cn := range t.Order {
			c := t.Chains[cn]
			if c == nil {
				continue
			}
			for _, r := range c.Rules {
				rewrites := false
				var protos []string
				var spans [][2]uint16
				for _, x := range r.Exprs {
					switch m := x.(type) {
					case *rules.DNAT, *rules.Redirect:
						rewrites = true
					case *rules.Match:
						set := m.Values
						if set == nil {
							set = b.rs.Sets[m.SetRef]
						}
						if m.Neg || set == nil {
							continue
						}
						for idx, f := range m.Key {
							for _, el := range set.Elems {
								if idx >= len(el) || el[idx].Kind != rules.AtomNum {
									continue
								}
								switch f.Name {
								case rules.FDport:
									spans = append(spans, [2]uint16{uint16(el[idx].Lo), uint16(el[idx].Hi)})
								case rules.FL4Proto:
									if el[idx].Lo == 6 {
										protos = append(protos, "tcp")
									} else if el[idx].Lo == 17 {
										protos = append(protos, "udp")
									}
								}
							}
						}
					}
				}
				if !rewrites {
					continue
				}
				if len(protos) == 0 {
					protos = []string{"tcp"}
				}
				for _, sp := range spans {
					for _, pr := range protos {
						b.span(add, pr, sp[0], sp[1], breaks)
					}
				}
			}
		}
	}
	// The same, the way a packet goes: a rule may name the port and jump, and the chain it jumps
	// to, or one further on, may do the rewriting. Every port that can come as far as a rewrite
	// is asked about; with nothing on the way that names a port or a protocol, that is every
	// port, of tcp and of udp.
	ways, lost := b.rewritten()
	if lost {
		ways = append(ways, way{tcp: true, udp: true, ports: allPorts})
	}
	done := map[string]bool{}
	for _, w := range ways {
		if done[w.key()] {
			continue
		}
		done[w.key()] = true
		for _, sp := range w.ports {
			if w.tcp {
				b.span(add, "tcp", sp[0], sp[1], breaks)
			}
			if w.udp {
				b.span(add, "udp", sp[0], sp[1], breaks)
			}
		}
	}
	if b.f != nil {
		for _, r := range b.f.Rules {
			if (r.PortLo == 0 && r.PortHi == 0) || offLink(r) {
				continue
			}
			proto := r.Proto
			if proto == "" {
				proto = "tcp"
			}
			b.span(add, proto, r.PortLo, r.PortHi, breaks)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].port != out[j].port {
			return out[i].port < out[j].port
		}
		return out[i].proto < out[j].proto
	})
	return out
}

// What a report says when it stopped at a ceiling (Report.Partial).
var (
	sendersCut = fmt.Sprintf("The rules tell more groups of senders apart than the scan asks about from one place: it asked about %d of them, and the senders beyond those were not asked.", maxClasses)
	portsCut   = fmt.Sprintf("The rules name more than %d ports; the scan asked about the first %d and stopped.", maxPorts, maxPorts)
)

// SendersNotAsked is the report's sentence about the ceiling of senders, when the scan reached
// it, and nothing otherwise. It goes with the answer for a single port ("why"), which the
// ceiling of ports has no part in.
func SendersNotAsked(r *Report) []string {
	for _, p := range r.Partial {
		if p == sendersCut {
			return []string{p}
		}
	}
	return nil
}

// nobodyAsked is who reaches a port when every sender that was asked is stopped and not every
// sender was asked.
const nobodyAsked = "nobody that was asked"

// A range of up to wholeRange ports is asked about port by port. A longer one is asked about at
// its two ends and at every port inside it that anything sets apart, and the report says so.
// maxPorts is a ceiling no ordinary machine comes near; reaching it is said too.
const (
	wholeRange = 16
	maxPorts   = 4096
)

// span asks about the ports lo to hi.
func (b *builder) span(add func(string, uint16), proto string, lo, hi uint16, breaks []uint16) {
	if lo == 0 {
		lo = 1
	}
	if hi < lo {
		return
	}
	if b.only != nil {
		// One port is wanted, and a range holds it or does not: nothing is asked in part.
		if proto == b.only.proto && lo <= b.only.port && b.only.port <= hi {
			add(proto, b.only.port)
		}
		return
	}
	if int(hi)-int(lo) < wholeRange {
		for p := int(lo); p <= int(hi); p++ {
			add(proto, uint16(p))
		}
		return
	}
	add(proto, lo)
	add(proto, hi)
	for _, p := range breaks {
		if p > lo && p < hi {
			add(proto, p)
		}
	}
	name := fmt.Sprintf("%s %d to %d", proto, lo, hi)
	for _, r := range b.ranges {
		if r == name {
			return
		}
	}
	b.ranges = append(b.ranges, name)
	b.parts = append(b.parts, partRange{proto, lo, hi})
}

// partRange is a range of ports that was asked about in part.
type partRange struct {
	proto  string
	lo, hi uint16
}

// portBreaks lists the ports where something can start to treat a packet differently from the
// port below: the ends of every port match in the rules, every listener, every published port,
// every opening of the firewall manager, and the ends of the ports a rewrite sends packets to.
// Two ports with no such point between them fare alike.
//
// The last of these is the kernel's way with a range of ports as a target: a packet keeps its
// own port when that lies in the range and gets the first port of the range when it does not.
// So of the packets one rule rewrites to 9000-9100, those sent to 9000 and to 9101 end on port
// 9000, and those sent to 9001 do not.
func (b *builder) portBreaks() []uint16 {
	seen := map[uint16]bool{}
	mark := func(lo, hi uint32) {
		if lo > 0 && lo <= 65535 {
			seen[uint16(lo)] = true
		}
		if hi < 65535 {
			seen[uint16(hi+1)] = true
		}
	}
	target := func(lo, hi uint16) {
		if lo != 0 {
			mark(uint32(lo), uint32(max(lo, hi)))
		}
	}
	fromSet := func(key []rules.Field, set *rules.Set) {
		if set == nil {
			return
		}
		for idx, f := range key {
			if f.Name != rules.FDport && f.Name != rules.FCtOrigDport {
				continue
			}
			for _, el := range set.Elems {
				if idx < len(el) && el[idx].Kind == rules.AtomNum {
					mark(el[idx].Lo, el[idx].Hi)
				}
			}
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
							fromSet(m.Key, m.Values)
						} else {
							fromSet(m.Key, b.rs.Sets[m.SetRef])
						}
					case *rules.VerdictMap:
						if m.SetRef != "" {
							fromSet(m.Key, b.rs.Sets[m.SetRef])
							continue
						}
						set := &rules.Set{}
						for _, en := range m.Entries {
							set.Elems = append(set.Elems, en.Key)
						}
						fromSet(m.Key, set)
					case *rules.DNAT:
						target(m.Port, m.PortHi)
					case *rules.Redirect:
						target(m.Port, m.PortHi)
					}
				}
			}
		}
	}
	for _, l := range b.h.Listeners {
		mark(uint32(l.Port), uint32(l.Port))
	}
	if b.h.Docker != nil {
		for _, c := range b.h.Docker.Containers {
			for _, p := range c.Ports {
				mark(uint32(p.HostPort), uint32(p.HostPort))
			}
		}
	}
	if b.f != nil {
		for _, r := range b.f.Rules {
			if r.PortLo != 0 || r.PortHi != 0 {
				mark(uint32(r.PortLo), uint32(r.PortHi))
			}
		}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// allowed asks the firewall manager's own list: the first rule that fits the packet decides.
func (b *builder) allowed(k portKey, src, dst netip.Addr, iface string) bool {
	for _, r := range b.f.Rules {
		if (r.Proto != "" && r.Proto != k.proto) || r.IPv6 != dst.Is6() {
			continue
		}
		if !(r.PortLo == 0 && r.PortHi == 0) && (k.port < r.PortLo || k.port > r.PortHi) {
			continue
		}
		if (r.From.IsValid() && !r.From.Contains(src)) || (r.To.IsValid() && !r.To.Contains(dst)) {
			continue
		}
		if r.Iface != "" && r.Iface != iface {
			continue
		}
		return r.Action == "allow" || r.Action == "limit"
	}
	return b.f.DefaultIncoming == "allow"
}

// outsideIfaces names the interfaces a packet from outside can arrive on.
func (b *builder) outsideIfaces() map[string]bool {
	out := map[string]bool{}
	for _, in := range b.h.Interfaces {
		if in.Up && !in.Loopback && !b.inside(in) {
			out[in.Name] = true
		}
	}
	return out
}

// everywhere reports whether a zone's openings on these interfaces add up to every interface a
// packet from outside can arrive on. firewalld's default zone takes every interface no other zone
// names, so its list reads as one line per interface; said plainly, the port is simply allowed.
func everywhere(outside, on map[string]bool) bool {
	if len(outside) == 0 || len(on) == 0 {
		return false
	}
	for i := range outside {
		if !on[i] {
			return false
		}
	}
	return true
}

// offLink reports whether a rule only covers packets addressed to a link-local or multicast
// address (firewalld's dhcpv6-client and mdns services). The scan follows no packet there.
func offLink(r host.FrontendRule) bool {
	if !r.To.IsValid() {
		return false
	}
	// The whole range has to lie in that space; one that merely starts there reaches further.
	for _, n := range offLinkNets {
		if r.To.Bits() >= n.Bits() && n.Contains(r.To.Addr().Unmap()) {
			return true
		}
	}
	return false
}

var offLinkNets = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

// stated is what the firewall manager says about a port, in a few words.
func (b *builder) stated(k portKey) string {
	var only []string
	seen := map[string]bool{}
	outside := b.outsideIfaces()
	zoneOn := map[string]bool{}
	for _, r := range b.f.Rules {
		if (r.Proto != "" && r.Proto != k.proto) || (r.PortLo == 0 && r.PortHi == 0 && !r.From.IsValid() && r.Iface == "") {
			continue
		}
		if !(r.PortLo == 0 && r.PortHi == 0) && (k.port < r.PortLo || k.port > r.PortHi) {
			continue
		}
		yes := r.Action == "allow" || r.Action == "limit"
		limit := ""
		switch {
		case offLink(r):
			limit = "to " + r.To.Masked().String()
		case r.From.IsValid() && r.From.Bits() > 0:
			limit = "from " + ival{r.From.Masked().Addr(), lastAddr(r.From)}.String()
		case r.Iface != "" && r.Zone != "":
			// A zone's interface: counted, and named only when the zone does not cover them all.
			if yes && outside[r.Iface] {
				zoneOn[r.Iface] = true
			}
			if !outside[r.Iface] && len(outside) > 0 {
				continue
			}
			limit = "on " + r.Iface
		case r.Iface != "":
			limit = "on " + r.Iface
		}
		if limit != "" {
			if yes && !seen[limit] {
				seen[limit] = true
				only = append(only, limit)
			}
			continue
		}
		switch {
		case yes && r.Action == "limit":
			return "allowed, with a rate limit"
		case yes:
			return "allowed"
		case len(only) == 0:
			return "denied"
		}
		break
	}
	if everywhere(outside, zoneOn) {
		return "allowed"
	}
	if len(only) > 0 {
		return "allowed only " + list(few(only))
	}
	if b.f.DefaultIncoming == "allow" {
		return "allowed by default"
	}
	return "not allowed"
}

// allows is the manager's allow list, one short entry per opening. A zone's opening is named once,
// with its interfaces only when the zone does not cover every interface facing outside.
func (b *builder) allows() []string {
	type entry struct {
		text string
		zone bool
		on   map[string]bool
	}
	var entries []*entry
	byText := map[string]*entry{}
	outside := b.outsideIfaces()
	add := func(text, iface string, zone bool) {
		if !zone && iface != "" {
			text += " on " + iface
		}
		e := byText[text]
		if e == nil {
			e = &entry{text: text, zone: zone, on: map[string]bool{}}
			byText[text] = e
			entries = append(entries, e)
		}
		if zone && iface != "" {
			e.on[iface] = true
		}
	}
	for _, r := range b.f.Rules {
		if r.Action != "allow" && r.Action != "limit" {
			continue
		}
		s := "every port"
		if r.PortLo != 0 || r.PortHi != 0 {
			s = fmt.Sprint(r.PortLo)
			if r.PortHi != r.PortLo {
				s += fmt.Sprintf("-%d", r.PortHi)
			}
			if r.Proto != "" {
				s += "/" + r.Proto
			}
		} else if r.Proto != "" {
			s += " (" + r.Proto + ")"
		}
		if r.From.IsValid() && r.From.Bits() > 0 {
			s += " from " + ival{r.From.Masked().Addr(), lastAddr(r.From)}.String()
		}
		if offLink(r) {
			s += " to " + r.To.Masked().String()
		}
		add(s, r.Iface, r.Zone != "")
	}
	out := []string{}
	for _, e := range entries {
		if !e.zone || len(e.on) == 0 || everywhere(outside, e.on) {
			out = append(out, e.text)
			continue
		}
		var on []string
		for i := range e.on {
			if outside[i] || len(outside) == 0 {
				on = append(on, i)
			}
		}
		sort.Strings(on)
		for _, i := range on {
			out = append(out, e.text+" on "+i)
		}
	}
	return out
}

func list(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// few keeps a list of names short enough to read in a line: up to four are all said, and of more
// the first three and how many others there are. Every one of them is still in the report, as a
// packet of its own.
func few(names []string) []string {
	if len(names) <= 4 {
		return names
	}
	return append(names[:3:3], fmt.Sprintf("%d more", len(names)-3))
}

// shot is one packet sent, with what the report needs to know about it.
type shot struct {
	cell    Cell
	res     engine.Result
	v       *vantage
	generic bool
	reach   bool
	exposed bool
}

func (b *builder) shoot(k portKey, v *vantage, v6 bool, c srcClass, dst netip.Addr) *shot {
	res := b.e.Run(engine.Probe{Iif: v.Iface, Src: c.addr, Dst: dst, Proto: k.proto, Dport: k.port})
	sh := &shot{res: res, v: v, generic: c.generic}
	sh.reach = res.Class == engine.Open || res.Class == engine.Forwarded
	sh.cell = Cell{Vantage: v.ID, From: c.label, Src: c.addr.String(), Dst: dst.String(), IPv6: v6,
		Class: res.Class.String(), Steps: res.Steps, Unknowns: res.Unknowns}
	if sh.cell.Steps == nil {
		sh.cell.Steps = []Step{}
	}
	for _, p := range res.Possible {
		sh.cell.Possible = append(sh.cell.Possible, p.String())
	}
	if b.f != nil {
		ok := b.allowed(k, c.addr, dst, v.Iface)
		sh.cell.Allowed = &ok
		sh.exposed = sh.reach && !ok
	}
	sh.cell.Rewrite, sh.cell.Deciding = res.Rewrite(), res.Deciding()
	sh.cell.Why = b.why(res)
	if res.Otherwise != 0 {
		// All that was not seen is a chain that can do no more than drop the packet. How it ends
		// in the rules that were followed is worth saying; it is just not the last word.
		walked := res
		walked.Class = res.Otherwise
		sh.cell.Otherwise = res.Otherwise.String()
		sh.cell.Deciding = walked.Deciding()
		sh.cell.Why = b.why(walked) + " " + mayDrop
	}
	return sh
}

// key tells apart the answers worth a line of their own: how the packet to d ended and why. The
// address itself is left out, so the same answer at two addresses is said once.
func (s *shot) key(d netip.Addr) string {
	return s.cell.Class + "\x00" + s.cell.Otherwise + "\x00" + strings.ReplaceAll(s.cell.Why, d.String(), "") + "\x00" + fmt.Sprint(s.exposed)
}

// elsewhereNote adds, to the account of a packet that got through at an address which does not
// sit on the interface it arrived on, why it could.
func (b *builder) elsewhereNote(sh *shot, d netip.Addr) {
	if on := b.heldOn(d); sh.reach && on != "" {
		sh.cell.Why += " The packet is for " + d.String() + ", an address on " + on + ": Linux takes packets for any address it holds, whichever interface they arrive on."
	}
}

// mayDrop ends the account of a packet that passes a chain seaward did not follow, when all that
// chain can do is drop it.
const mayDrop = "A chain that was not followed may drop it instead."

// end is how the packet ends as far as the finding for its port goes. One that reaches nothing
// whether or not a chain that was not followed drops it is stopped, not undecided.
func (s *shot) end() engine.Class {
	if s.res.Class == engine.Undecided && (s.res.Otherwise == engine.Closed || s.res.Otherwise == engine.Rejected) {
		return s.res.Otherwise
	}
	return s.res.Class
}

// port asks about one port from everywhere and sums the answers up.
func (b *builder) port(k portKey, vs []*vantage) Port {
	var shots []*shot
	for _, v := range vs {
		for _, s := range v.sides {
			base := map[netip.Addr]*shot{}
			seen := map[string]bool{}
			for ci, c := range s.classes {
				for di, d := range s.dsts {
					sh := b.shoot(k, v, s.v6, c, d)
					key := sh.key(d)
					if di >= s.own {
						b.elsewhereNote(sh, d)
					}
					if ci == 0 {
						base[d] = sh
						// Nothing listening at an address elsewhere on the machine says no more than
						// the same answer at the interface's own.
						idle := di >= s.own && s.own > 0 && sh.res.Class == engine.Closed
						if !seen[key] && !idle {
							seen[key] = true
							shots = append(shots, sh)
						}
						continue
					}
					// A sender some rule singles out is only worth a line when it fares differently.
					if g := base[d]; g != nil && g.cell.Class == sh.cell.Class && g.cell.Otherwise == sh.cell.Otherwise && g.exposed == sh.exposed {
						continue
					}
					shots = append(shots, sh)
					break
				}
			}
		}
	}
	p := Port{Proto: k.proto, Port: k.port, Cells: []Cell{}}
	for _, sh := range shots {
		p.Cells = append(p.Cells, sh.cell)
	}
	if len(shots) == 0 {
		return p
	}
	if b.f != nil {
		p.Stated = b.stated(k)
	}
	p.Service = b.service(k, shots)
	p.Reach = reach(shots, b.crowded)
	p.Views = views(shots, vs, true)

	var lead *shot
	pick := func(f func(*shot) bool) bool {
		for _, sh := range shots {
			if f(sh) {
				lead = sh
				return true
			}
		}
		return false
	}
	tool := ""
	if b.f != nil {
		tool = b.f.Tool
	}
	switch {
	case pick(func(s *shot) bool { return s.exposed }):
		p.Finding, p.Severity = Exposed, "medium"
		if lead.v.Scope == "world" {
			p.Severity = "high"
		}
		where := lead.v.Label
		switch {
		case !lead.generic:
			where = lead.cell.From
		case lead.v.Scope == "lan":
			where = "the local network"
		case lead.v.Scope == "vpn":
			where = "VPN peers"
		}
		p.Title = "Reachable from " + where + ". "
		if strings.HasPrefix(p.Stated, "allowed only ") {
			p.Title += tool + " allows it only " + strings.TrimPrefix(p.Stated, "allowed only ") + "."
		} else {
			p.Title += tool + " does not allow it."
		}
	case pick(func(s *shot) bool { return s.reach }):
		wide := false
		for _, sh := range shots {
			wide = wide || (sh.reach && sh.generic && sh.v.Scope == "world")
		}
		p.Title = "Reachable from " + p.Reach
		switch {
		case b.f != nil:
			p.Finding, p.Severity = Open, "ok"
			p.Title += ", as " + tool + " allows."
		case wide:
			p.Finding, p.Severity = Open, "info"
			p.Title += "."
		default:
			p.Finding, p.Severity = Limited, "info"
			p.Title += "."
		}
	case pick(func(s *shot) bool { return s.end() == engine.Undecided }):
		p.Finding, p.Severity, p.Title = Undecided, "unknown", "Not decided."
		p.Reach = "not known"
	case b.loopbackOnly(k):
		lead = shots[0]
		p.Finding, p.Severity, p.Title, p.Reach = Local, "ok", "Listens on this machine only.", "this machine only"
	default:
		yes := func(s *shot) bool { return s.cell.Allowed != nil && *s.cell.Allowed }
		stopped := func(s *shot) bool { return s.end() == engine.Filtered || s.end() == engine.Rejected }
		switch {
		case pick(func(s *shot) bool { return yes(s) && stopped(s) }):
			p.Finding, p.Severity, p.Title = Shadowed, "low", tool+" allows it, yet another rule stops it."
		case pick(func(s *shot) bool { return yes(s) && s.end() == engine.Closed }):
			p.Finding, p.Severity, p.Title = Dead, "low", tool+" allows it, and nothing is listening."
		case b.publisher(k) != nil && pick(func(s *shot) bool { return s.end() == engine.Closed }):
			p.Finding, p.Severity, p.Title = Dead, "low", "Docker publishes it, and nothing answers."
		case pick(stopped):
			p.Finding, p.Severity, p.Title = Blocked, "ok", "Stopped by the firewall."
		default:
			lead = shots[0]
			p.Finding, p.Severity, p.Title = Closed, "ok", "Nothing is listening on an outside address."
		}
	}
	p.Why, p.Rewrite, p.Deciding = lead.cell.Why, lead.cell.Rewrite, lead.cell.Deciding
	// Past the ceiling of senders, "nobody gets through" is no finding: a sender that was not
	// asked may. What was found reachable stands; what would be ruled out is not decided.
	notAsked := func() {
		p.Finding, p.Severity = Undecided, "unknown"
		p.Title = "No sender that was asked gets through, and not every sender was asked."
		p.Reach = nobodyAsked
		p.Why, p.Rewrite, p.Deciding = sendersCut, nil, nil
	}
	switch p.Finding {
	case Local:
		p.Why, p.Rewrite, p.Deciding = b.boundTo(k), nil, nil
		switch {
		case !b.crowded:
		case b.localnet():
			// With route_localnet a rule can send a packet from outside to the loopback, for
			// one sender as for all: this port is as open a question as the others.
			notAsked()
		default:
			// The kernel drops a packet from outside for the loopback, whoever sent it. What
			// was not asked changes nothing here, and no view of the port is left open.
			p.Views = views(shots, vs, false)
		}
	case Undecided:
		p.Deciding = nil // nothing has settled it
	case Shadowed, Dead, Blocked, Closed:
		if b.crowded {
			notAsked()
		}
	}
	return p
}

// localnet reports whether the kernel lets a packet from outside through to the loopback
// addresses on some interface (route_localnet). Without it such a packet is dropped as a martian.
func (b *builder) localnet() bool {
	for _, on := range b.h.RouteLocalnet {
		if on {
			return true
		}
	}
	return false
}

func (b *builder) loopbackOnly(k portKey) bool {
	n := 0
	for _, l := range b.h.Listeners {
		if l.Netns != "" || l.Proto != k.proto || l.Port != k.port {
			continue
		}
		if !l.Addr.IsLoopback() {
			return false
		}
		n++
	}
	return n > 0
}

func (b *builder) boundTo(k portKey) string {
	var at []string
	seen := map[string]bool{}
	for _, l := range b.h.Listeners {
		if l.Netns == "" && l.Proto == k.proto && l.Port == k.port && !seen[l.Addr.String()] {
			seen[l.Addr.String()] = true
			at = append(at, l.Addr.String())
		}
	}
	return "It is bound to " + list(at) + ", which only this machine can reach."
}

func (b *builder) publisher(k portKey) *host.Container {
	if b.h.Docker == nil {
		return nil
	}
	for i := range b.h.Docker.Containers {
		c := &b.h.Docker.Containers[i]
		for _, p := range c.Ports {
			if p.Proto == k.proto && p.HostPort == k.port {
				return c
			}
		}
	}
	return nil
}

func containerName(c *host.Container) string {
	s := "container " + c.Name
	if c.Image != "" {
		s += " (" + c.Image + ")"
	}
	return s
}

// service names what answers on a port: the program that took a packet, or what the machine says
// is behind it.
func (b *builder) service(k portKey, shots []*shot) string {
	pub := b.publisher(k)
	for _, sh := range shots {
		r := sh.res
		if !sh.reach {
			continue
		}
		switch {
		case r.Container != nil:
			if r.Listener != nil && r.Listener.Process != "" {
				return r.Listener.Process + " in " + containerName(r.Container)
			}
			return containerName(r.Container)
		case r.Listener != nil && r.Listener.Process != "":
			if pub != nil && strings.HasPrefix(r.Listener.Process, "docker-proxy") {
				return containerName(pub)
			}
			return r.Listener.Process
		case r.Class == engine.Forwarded && r.FinalDst.IsValid():
			return "another machine, " + netip.AddrPortFrom(r.FinalDst, r.FinalPort).String()
		}
	}
	if pub != nil {
		return containerName(pub)
	}
	for _, l := range b.h.Listeners {
		if l.Netns == "" && l.Proto == k.proto && l.Port == k.port && l.Process != "" {
			return l.Process
		}
	}
	return ""
}

// views sums the packets up per place they came from.
func views(shots []*shot, vs []*vantage, partial bool) []View {
	out := []View{}
	for _, v := range vs {
		var asked, ok [2]bool
		var named []string
		seen := map[string]bool{}
		undecided, stopped := false, false
		for _, sh := range shots {
			if sh.v != v {
				continue
			}
			i := 0
			if sh.cell.IPv6 {
				i = 1
			}
			switch {
			case sh.generic:
				asked[i] = true
				ok[i] = ok[i] || sh.reach
			case sh.reach && !seen[sh.cell.From]:
				seen[sh.cell.From] = true
				named = append(named, sh.cell.From)
			}
			undecided = undecided || sh.end() == engine.Undecided
			stopped = stopped || sh.end() == engine.Filtered || sh.end() == engine.Rejected
		}
		w := View{Vantage: v.ID}
		switch {
		case ok[0] || ok[1]:
			w.State = ViewOpen
			switch {
			case asked[0] && asked[1] && !ok[1]:
				w.Note = "IPv4 only"
			case asked[0] && asked[1] && !ok[0]:
				w.Note = "IPv6 only"
			}
		case len(named) > 0 && v.cut && partial:
			// not every sender was asked from here: these get through, and others may
			w.State, w.Note = ViewSome, "at least "+list(few(named))
		case len(named) > 0:
			w.State, w.Note = ViewSome, list(few(named))+" only"
		case undecided || (v.cut && partial):
			w.State = ViewUndecided
		case stopped:
			w.State = ViewStopped
		default:
			w.State = ViewClosed
		}
		out = append(out, w)
	}
	return out
}

// reach says who gets through, in a few words. partial says not every sender was asked: then
// those found are the least of it, and "nobody" and "only" would say more than is known.
func reach(shots []*shot, partial bool) string {
	type fam struct{ asked, ok bool }
	type near struct {
		iface string
		f     [2]fam
	}
	var world [2]fam
	var lan, vpn []*near
	find := func(all *[]*near, iface string) *near {
		for _, n := range *all {
			if n.iface == iface {
				return n
			}
		}
		n := &near{iface: iface}
		*all = append(*all, n)
		return n
	}
	wide := ""
	var named []string
	seen := map[string]bool{}
	for _, sh := range shots {
		i := 0
		if sh.cell.IPv6 {
			i = 1
		}
		if !sh.generic {
			if sh.reach && !seen[sh.cell.From] {
				seen[sh.cell.From] = true
				named = append(named, sh.cell.From)
			}
			continue
		}
		var f *fam
		switch sh.v.Scope {
		case "world":
			f = &world[i]
			if sh.reach && wide == "" {
				wide = sh.v.Label
			}
		case "vpn":
			f = &find(&vpn, sh.v.Iface).f[i]
		default:
			f = &find(&lan, sh.v.Iface).f[i]
		}
		f.asked = true
		f.ok = f.ok || sh.reach
	}
	// one is "IPv4" or "IPv6" when both were asked and only that one gets through.
	one := func(f [2]fam) string {
		switch {
		case f[0].asked && f[1].asked && f[0].ok && !f[1].ok:
			return "IPv4"
		case f[0].asked && f[1].asked && f[1].ok && !f[0].ok:
			return "IPv6"
		}
		return ""
	}
	if world[0].ok || world[1].ok {
		if v := one(world); v != "" {
			return wide + " (" + v + " only)"
		}
		return wide
	}
	// Networks this machine is plugged into: named by interface when only some of them get through.
	side := func(what string, all []*near) string {
		var in []string
		var sum [2]fam
		for _, n := range all {
			if !n.f[0].ok && !n.f[1].ok {
				continue
			}
			in = append(in, n.iface)
			for i := range sum {
				sum[i].asked = sum[i].asked || n.f[i].asked
				sum[i].ok = sum[i].ok || n.f[i].ok
			}
		}
		if len(in) == 0 {
			return ""
		}
		if len(in) < len(all) {
			what += " on " + list(in)
		}
		if v := one(sum); v != "" {
			what += " over " + v
		}
		return what
	}
	var parts []string
	for _, p := range []string{side("the local network", lan), side("VPN peers", vpn)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	parts = append(parts, few(named)...)
	switch {
	case len(parts) == 0 && partial:
		return nobodyAsked
	case len(parts) == 0:
		return "nobody"
	case partial:
		return "at least " + list(parts)
	}
	return list(parts) + " only"
}

func place(s *Step) string {
	if s == nil || s.Table == "" {
		return "the rules"
	}
	t := s.Table
	if s.Family != "" && s.Family != "ip" {
		t = s.Family + " " + t
	}
	return "chain " + s.Chain + " of table " + t
}

func sentence(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// why explains one packet's fate in a sentence or two.
func (b *builder) why(res engine.Result) string {
	last := ""
	if n := len(res.Steps); n > 0 {
		last = res.Steps[n-1].Effect
	}
	d := res.Deciding()
	switch res.Class {
	case engine.Open, engine.Forwarded:
		rw := res.Rewrite()
		if rw == nil {
			switch {
			case d == nil:
				return "No firewall rule stands in its way."
			case d.Kind == engine.StepPolicy:
				return "No rule stops it: chain " + d.Chain + " ends with policy accept."
			}
			return "Accepted by a rule in " + place(d) + "."
		}
		to := strings.TrimPrefix(rw.Effect, "destination becomes ")
		if res.Class == engine.Open && res.Container == nil {
			return "A rule in " + place(rw) + " sends it to " + to + " on this machine, where it is taken."
		}
		s := "A rule in " + place(rw) + " sends it on to " + to
		if res.Container != nil {
			s += ", container " + res.Container.Name
		}
		s += ". From there it is forwarded, not delivered to this machine, so "
		if b.f != nil && b.f.Tool == "ufw" {
			return s + "the INPUT chain, where ufw keeps its list, never sees it."
		}
		return s + "the rules for packets addressed to this machine never see it."
	case engine.Filtered, engine.Rejected:
		verb := "Dropped"
		if res.Class == engine.Rejected {
			verb = "Refused"
		}
		switch {
		case d == nil:
			return sentence(last)
		case d.Kind == engine.StepPolicy:
			return "No rule lets it in: chain " + d.Chain + " ends with policy drop."
		case d.Kind == engine.StepRule:
			return verb + " by a rule in " + place(d) + "."
		}
		return sentence(d.Effect)
	case engine.Closed:
		if strings.HasPrefix(last, "handed to ") {
			return "The firewall lets it through and it is " + last + "."
		}
		return "The firewall lets it through, but " + last + "."
	}
	if len(res.Unknowns) > 0 {
		return sentence(res.Unknowns[0])
	}
	return sentence(last)
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// sum writes the counts and the two lines at the top of the report.
func (b *builder) sum(rep *Report, vantages int) {
	docker := 0
	for _, p := range rep.Ports {
		switch p.Finding {
		case Exposed:
			rep.Counts.Exposed++
			rep.Counts.Reachable++
			if p.Rewrite != nil && b.publisher(portKey{p.Proto, p.Port}) != nil {
				docker++
			}
		case Open, Limited:
			rep.Counts.Reachable++
		case Undecided:
			rep.Counts.Undecided++
		case Blocked, Shadowed:
			rep.Counts.Stopped++
		default:
			rep.Counts.Quiet++
		}
	}
	n, x, u := rep.Counts.Reachable, rep.Counts.Exposed, rep.Counts.Undecided
	tool := ""
	if b.f != nil {
		tool = b.f.Tool
	}
	// A scan that stopped at a ceiling found what it found and rules nothing else out.
	notAsked := ""
	switch {
	case b.crowded && b.cut:
		notAsked = "not every sender and not every port was asked"
	case b.crowded:
		notAsked = "not every sender was asked"
	case b.cut:
		notAsked = "not every port was asked"
	}
	reached := plural(n, "port") + " can be reached from outside"
	var detail []string
	if notAsked != "" && n > 0 {
		reached = "At least " + reached
		detail = append(detail, sentence(notAsked))
	}
	// Each port that was asked in a long range stands for the ports up to the next one asked.
	const inPart = "A long range of ports was asked about in part: a port in it stands for the ports up to the next one asked."
	if b.more {
		reached = "At least " + strings.TrimPrefix(reached, "At least ")
		detail = append(detail, inPart)
	}
	least := b.more // whether "at least" was said of a range asked in part
	undecided := func(u int, one string) string {
		if b.moreUndecided {
			least = true
			return "At least " + plural(u, one) + " could not be decided."
		}
		return plural(u, one) + " could not be decided."
	}
	switch {
	case vantages == 0:
		rep.Headline = "No outside network interface was found, so nothing was asked."
	case len(rep.Unread) > 0 && n == 0:
		rep.Headline = "The firewall rules could not be read, so nothing is decided."
		root := true
		for _, why := range rep.Unread {
			root = root && (strings.Contains(why, "needs root") || strings.Contains(why, "without root"))
		}
		if root {
			detail = append(detail, "The kernel shows them to root only. Run it again with sudo.")
		}
		u = 0
	case n == 0 && notAsked != "":
		rep.Headline = "Nothing was found reachable from outside, but " + notAsked + "."
	case n == 0 && u > 0:
		rep.Headline = undecided(u, "port")
		if rep.Counts.Stopped+rep.Counts.Quiet > 0 {
			detail = append(detail, "No other port can be reached from outside.")
		}
		u = 0
	case n == 0:
		rep.Headline = "Nothing can be reached from outside."
	case tool == "":
		rep.Headline = reached + "."
	case x == 0 && n == 1:
		rep.Headline = reached + ", and " + tool + " allows it."
	case x == 0:
		rep.Headline = reached + ", all allowed by " + tool + "."
	case n == 1:
		rep.Headline = reached + ". " + tool + " does not allow it."
	case x == n:
		rep.Headline = reached + ". " + tool + " allows none of them."
	default:
		rep.Headline = fmt.Sprintf("%s. %s allows only %d of them.", reached, tool, n-x)
	}
	switch {
	case docker == 0:
	case x == 1:
		detail = append(detail, "Docker publishes it with rules of its own, which never pass "+tool+"'s list.")
	case docker == x:
		detail = append(detail, "Docker publishes the other "+fmt.Sprint(docker)+" with rules of its own, which never pass "+tool+"'s list.")
	default:
		detail = append(detail, "Docker publishes "+fmt.Sprint(docker)+" of the others with rules of its own, which never pass "+tool+"'s list.")
	}
	if u > 0 {
		one := "port"
		if n > 0 {
			one = "more port"
		}
		detail = append(detail, undecided(u, one))
	}
	if least && !b.more {
		detail = append(detail, inPart)
	}
	rep.Detail = strings.Join(detail, " ")
}
