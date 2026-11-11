package engine

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// Engine is a ruleset and a machine, indexed for walking packets through them.
type Engine struct {
	rs *rules.Ruleset
	h  *host.Host

	hooks map[string][]baseChain // base chains of each hook, in the order the kernel runs them
	local map[netip.Addr]string  // every address of this machine -> its interface
	bcast map[netip.Addr]bool    // broadcast addresses of connected IPv4 networks
	ifs   map[string]*host.Interface
	rt4   []host.Route // longest prefix first
	rt6   []host.Route
	ctr   map[netip.Addr]*host.Container
	// socks holds the listening sockets of each network namespace: "" is the machine itself, any
	// other key is a container ID. A container with no entry was not looked into.
	socks map[string][]*host.Listener
}

// baseChain is a base chain with the place it really runs at.
type baseChain struct {
	t   *rules.Table
	c   *rules.Chain
	eff int // effective priority
	seq int // source order, the tie-break
}

// The kernel runs connection tracking at priority -200 on prerouting. Chains before it see a
// packet with no connection yet.
const prioConntrack = -200

// natPriority is where every nat chain of a hook really runs. The kernel hangs all nat chains of
// one hook off a single hook of its own at a fixed priority; a nat chain's declared priority only
// orders it among the other nat chains.
func natPriority(hook string) int {
	if hook == rules.HookPrerouting || hook == rules.HookOutput {
		return -100
	}
	return 100
}

// New indexes a ruleset and a machine. Either may be nil.
func New(rs *rules.Ruleset, h *host.Host) *Engine {
	if rs == nil {
		rs = &rules.Ruleset{}
	}
	if h == nil {
		h = &host.Host{}
	}
	e := &Engine{
		rs: rs, h: h,
		hooks: map[string][]baseChain{},
		local: map[netip.Addr]string{},
		bcast: map[netip.Addr]bool{},
		ifs:   map[string]*host.Interface{},
		ctr:   map[netip.Addr]*host.Container{},
		socks: map[string][]*host.Listener{},
	}
	seq := 0
	for _, t := range rs.Tables {
		for _, name := range t.Order {
			c := t.Chains[name]
			if c == nil || !c.Base {
				continue
			}
			bc := baseChain{t: t, c: c, eff: c.Priority, seq: seq}
			if c.Type == "nat" {
				bc.eff = natPriority(c.Hook)
			}
			seq++
			e.hooks[c.Hook] = append(e.hooks[c.Hook], bc)
		}
	}
	for _, list := range e.hooks {
		sort.SliceStable(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.eff != b.eff {
				return a.eff < b.eff
			}
			an, bn := a.c.Type == "nat", b.c.Type == "nat"
			if an && bn && a.c.Priority != b.c.Priority {
				return a.c.Priority < b.c.Priority
			}
			return a.seq < b.seq
		})
	}
	for i := range h.Interfaces {
		in := &h.Interfaces[i]
		e.ifs[in.Name] = in
		for _, p := range in.Addrs {
			a := p.Addr().Unmap()
			e.local[a] = in.Name
			if a.Is4() && p.Bits() < 31 {
				e.bcast[lastAddr(netip.PrefixFrom(a, p.Bits()).Masked())] = true
			}
		}
	}
	for _, r := range h.Routes {
		if !r.Dst.IsValid() {
			continue
		}
		r.Dst = netip.PrefixFrom(r.Dst.Addr().Unmap(), r.Dst.Bits()).Masked()
		if r.Dst.Addr().Is4() {
			e.rt4 = append(e.rt4, r)
		} else {
			e.rt6 = append(e.rt6, r)
		}
	}
	// A snapshot without a route table still knows the connected networks.
	if len(h.Routes) == 0 {
		for _, in := range h.Interfaces {
			for _, p := range in.Addrs {
				r := host.Route{Dst: netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked(), Dev: in.Name}
				if r.Dst.Addr().Is4() {
					e.rt4 = append(e.rt4, r)
				} else if !r.Dst.Addr().IsLinkLocalUnicast() {
					e.rt6 = append(e.rt6, r)
				}
			}
		}
	}
	byLen := func(l []host.Route) {
		sort.SliceStable(l, func(i, j int) bool { return l[i].Dst.Bits() > l[j].Dst.Bits() })
	}
	byLen(e.rt4)
	byLen(e.rt6)
	if h.Docker != nil {
		for i := range h.Docker.Containers {
			c := &h.Docker.Containers[i]
			for _, n := range c.Networks {
				if n.Addr.IsValid() {
					e.ctr[n.Addr.Unmap()] = c
				}
				if n.Addr6.IsValid() {
					e.ctr[n.Addr6] = c
				}
			}
			if c.ListenersKnown && e.socks[c.ID] == nil {
				e.socks[c.ID] = []*host.Listener{}
			}
		}
	}
	for i := range h.Listeners {
		l := &h.Listeners[i]
		ns := l.Netns
		if ns != "" && h.Docker != nil {
			for j := range h.Docker.Containers {
				if sameID(h.Docker.Containers[j].ID, ns) {
					ns = h.Docker.Containers[j].ID
					break
				}
			}
		}
		e.socks[ns] = append(e.socks[ns], l)
	}
	return e
}

// sameID reports whether two container IDs name the same container: Docker prints them in full or
// cut to twelve characters.
func sameID(a, b string) bool {
	if a == b {
		return true
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return len(a) >= 12 && strings.HasPrefix(b, a)
}

// Host is the machine this engine was built for.
func (e *Engine) Host() *host.Host { return e.h }

// Rules is the ruleset this engine was built for.
func (e *Engine) Rules() *rules.Ruleset { return e.rs }

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

var loop4 = netip.MustParsePrefix("127.0.0.0/8")

// addrType is the kernel's idea of what an address is, from this machine's point of view.
func (e *Engine) addrType(a netip.Addr) uint32 {
	a = a.Unmap()
	switch {
	case !a.IsValid() || a.IsUnspecified():
		return rules.AddrUnspec
	case a.Is4() && loop4.Contains(a), a.IsLoopback():
		return rules.AddrLocal
	case a.IsMulticast():
		return rules.AddrMulticast
	}
	if _, ok := e.local[a]; ok {
		return rules.AddrLocal
	}
	if a.Is4() && (e.bcast[a] || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		return rules.AddrBroadcast
	}
	// A "local" route in the main table makes a whole network this machine's own.
	if r, ok := e.route(a); ok {
		switch r.Type {
		case "local":
			return rules.AddrLocal
		case "broadcast":
			return rules.AddrBroadcast
		case "blackhole":
			return rules.AddrBlackhole
		case "unreachable":
			return rules.AddrUnreachable
		case "prohibit":
			return rules.AddrProhibit
		}
	}
	return rules.AddrUnicast
}

// addrTypeOn is addrType as one interface alone sees it. An address is local or broadcast there
// only when that interface carries it; for an address of another interface the kernel answers
// "unicast".
func (e *Engine) addrTypeOn(a netip.Addr, dev string) uint32 {
	a = a.Unmap()
	t := e.addrType(a)
	if t != rules.AddrLocal && t != rules.AddrBroadcast {
		return t
	}
	if a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return rules.AddrBroadcast
	}
	in := e.ifs[dev]
	if in == nil {
		return rules.AddrUnicast
	}
	if in.Loopback && (a.IsLoopback() || (a.Is4() && loop4.Contains(a))) {
		return rules.AddrLocal
	}
	for _, p := range in.Addrs {
		pa := p.Addr().Unmap()
		if pa == a {
			return rules.AddrLocal
		}
		if pa.Is4() && p.Bits() < 31 && lastAddr(netip.PrefixFrom(pa, p.Bits()).Masked()) == a {
			return rules.AddrBroadcast
		}
	}
	return rules.AddrUnicast
}

// route is the main table's answer for an address: the longest matching prefix.
func (e *Engine) route(a netip.Addr) (host.Route, bool) {
	a = a.Unmap()
	list := e.rt6
	if a.Is4() {
		list = e.rt4
	}
	for _, r := range list {
		if r.Dst.Contains(a) {
			return r, true
		}
	}
	return host.Route{}, false
}

// IifFor is the interface a packet from this source arrives on: the one this machine would use to
// send to it.
func (e *Engine) IifFor(src netip.Addr) (string, bool) {
	r, ok := e.route(src)
	if !ok || r.Dev == "" {
		return "", false
	}
	switch r.Type {
	case "", "unicast":
		return r.Dev, true
	}
	return "", false
}

// firstAddr is the address REDIRECT rewrites to: the first address of the arriving interface.
func (e *Engine) firstAddr(ifname string, v6 bool) (netip.Addr, bool) {
	in := e.ifs[ifname]
	if in == nil {
		return netip.Addr{}, false
	}
	for _, p := range in.Addrs {
		a := p.Addr().Unmap()
		if a.Is4() == v6 {
			continue
		}
		if v6 && a.IsLinkLocalUnicast() {
			continue
		}
		return a, true
	}
	return netip.Addr{}, false
}

// setName is the last part of a set key, for messages.
func setName(key string) string {
	if i := strings.LastIndexByte(key, 0); i >= 0 {
		return key[i+1:]
	}
	return key
}
