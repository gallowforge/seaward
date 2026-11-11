package scan

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// span is the range lo to hi; with one address, that address alone.
func span(s ...string) ival {
	if len(s) == 1 {
		if strings.Contains(s[0], "/") {
			p := netip.MustParsePrefix(s[0])
			return ival{p.Masked().Addr(), lastAddr(p)}
		}
		return ival{addr(s[0]), addr(s[0])}
	}
	return ival{addr(s[0]), addr(s[1])}
}

// A predicate keeps its ranges sorted and runs the overlapping ones together, so that an address
// is found by halving; what it finds is still the narrowest range that holds the address.
func TestPredFind(t *testing.T) {
	p := newPred("", []ival{
		span("198.51.100.0/24"), span("10.0.0.0/8"), span("198.51.100.64/26"), span("198.51.100.70"),
		span("192.0.2.10", "192.0.2.20"), span("192.0.2.15", "192.0.2.30"), span("192.0.2.31"),
		span("2001:db8::/32"), span("2001:db8:1::/48"), span("10.0.0.0/8"), span("255.255.255.255"),
	})
	if !slices.IsSortedFunc(p.iv, func(x, y ival) int { return x.lo.Compare(y.lo) }) || len(p.iv) != 10 {
		t.Fatalf("ranges: %v", p.iv)
	}
	var groups []string
	for _, g := range p.groups {
		groups = append(groups, fmt.Sprintf("%s-%s:%d", g.lo, g.hi, g.to-g.from))
	}
	// Ranges that touch without overlapping (192.0.2.30 and .31) stay apart, and so do the families.
	eq := "10.0.0.0-10.255.255.255:1 192.0.2.10-192.0.2.30:2 192.0.2.31-192.0.2.31:1 198.51.100.0-198.51.100.255:3 " +
		"255.255.255.255-255.255.255.255:1 2001:db8::-2001:db8:ffff:ffff:ffff:ffff:ffff:ffff:2"
	if got := strings.Join(groups, " "); got != eq {
		t.Errorf("groups:\n got  %s\n want %s", got, eq)
	}
	for _, c := range []struct{ a, want string }{
		{"10.1.2.3", "10.0.0.0/8"},
		{"198.51.100.7", "198.51.100.0/24"},
		{"198.51.100.65", "198.51.100.64/26"},
		{"198.51.100.70", "198.51.100.70"},
		{"198.51.100.128", "198.51.100.0/24"},
		{"192.0.2.10", "192.0.2.10 to 192.0.2.20"},
		{"192.0.2.25", "192.0.2.15 to 192.0.2.30"},
		{"192.0.2.31", "192.0.2.31"},
		{"255.255.255.255", "255.255.255.255"},
		{"2001:db8:1::7", "2001:db8:1::/48"},
		{"2001:db8:2::7", "2001:db8::/32"},
		{"9.255.255.255", ""}, {"11.0.0.0", ""}, {"192.0.2.9", ""}, {"192.0.2.32", ""}, {"198.51.101.0", ""},
		{"0.0.0.0", ""}, {"255.255.255.254", ""}, {"::", ""}, {"2001:db9::", ""}, {"::ffff:10.1.2.3", ""},
	} {
		v, ok := p.find(addr(c.a))
		if got := map[bool]string{true: v.String(), false: ""}[ok]; got != c.want {
			t.Errorf("find(%s) = %q, want %q", c.a, got, c.want)
		}
	}
	if _, ok := (&pred{}).find(addr("10.0.0.1")); ok {
		t.Error("an empty predicate holds an address")
	}
	// Said twice, in any order, a predicate is the same predicate.
	a := newPred("x", []ival{span("10.0.0.0/8"), span("192.0.2.7"), span("10.0.0.0/8")})
	b := newPred("x", []ival{span("192.0.2.7"), span("10.0.0.0/8")})
	c := newPred("x", []ival{span("192.0.2.8"), span("10.0.0.0/8")})
	d := newPred("y", []ival{span("192.0.2.7"), span("10.0.0.0/8")})
	if a.key() != b.key() || a.key() == c.key() || a.key() == d.key() {
		t.Error("key tells apart what is the same, or not what differs")
	}
}

// Two sets that start and end alike and are as long are still two sets. 0.1.0 took the second
// for the first, and its own address was then never asked about.
func TestPredicatesThatLookAlikeAreKeptApart(t *testing.T) {
	set := func(mid string) *rules.Match {
		return rules.Eq(rules.FSaddr, rules.Pfx(netip.MustParsePrefix("198.51.100.1/32")), rules.Pfx(netip.MustParsePrefix(mid)), rules.Pfx(netip.MustParsePrefix("198.51.100.99/32")))
	}
	b := newBuilder(inputRules(set("198.51.100.50/32"), set("198.51.100.70/32")), box())
	if len(b.preds) != 2 {
		t.Fatalf("%d predicates, want 2", len(b.preds))
	}
	var got []string
	for _, c := range classesOf(b, "world", false, nets4, own4, own4) {
		got = append(got, c.addr.String())
	}
	// Everyone else, the address each set holds alone, and one for the two that both hold.
	if want := "198.51.100.7 198.51.100.50 198.51.100.70 198.51.100.1"; strings.Join(got, " ") != want {
		t.Errorf("senders: %q, want %q", got, want)
	}
}

// box is a machine with one outside interface, on 203.0.113.0/24 and 2001:db8:1::/64, and a
// second network it reaches through a router there.
func box() *host.Host {
	return &host.Host{
		Name: "box",
		Interfaces: []host.Interface{
			{Name: "lo", Up: true, Loopback: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8"), netip.MustParsePrefix("::1/128")}},
			{Name: "eth0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.10/24"), netip.MustParsePrefix("2001:db8:1::10/64")}},
			{Name: "eth1", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.129/25")}},
		},
		Routes: []host.Route{
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0", Gateway: addr("203.0.113.1")},
			{Dst: netip.MustParsePrefix("203.0.113.0/24"), Dev: "eth0"},
			{Dst: netip.MustParsePrefix("192.0.2.128/25"), Dev: "eth1"},
			{Dst: netip.MustParsePrefix("198.51.100.192/26"), Type: "blackhole"},
			{Dst: netip.MustParsePrefix("::/0"), Dev: "eth0", Gateway: addr("2001:db8:1::1")},
			{Dst: netip.MustParsePrefix("2001:db8:1::/64"), Dev: "eth0"},
		},
	}
}

var (
	nets4 = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	own4  = []netip.Addr{addr("203.0.113.10")}
	nets6 = []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
	own6  = []netip.Addr{addr("2001:db8:1::10")}
)

// classesOf is the senders asked about from eth0, for the tests that do not look at the ceiling.
func classesOf(b *builder, scope string, v6 bool, nets []netip.Prefix, own, dsts []netip.Addr) []srcClass {
	cl, _ := b.classes("eth0", scope, v6, nets, own, dsts)
	return cl
}

// inputRules is an input chain with one rule per expression given.
func inputRules(exprs ...rules.Expr) *rules.Ruleset {
	c := &rules.Chain{Name: "input", Base: true, Hook: rules.HookInput, Type: "filter", Policy: rules.Drop}
	for _, x := range exprs {
		c.Rules = append(c.Rules, &rules.Rule{Exprs: []rules.Expr{x, &rules.Verdict{Kind: rules.Accept}}})
	}
	return &rules.Ruleset{Tables: []*rules.Table{{Family: "inet", Name: "filter", Chains: map[string]*rules.Chain{"input": c}, Order: []string{"input"}}}}
}

// The scan is exhaustive for senders: whatever the rules single out, every group of addresses
// they tell apart that can send from a place is asked about from there. Held against the slow
// way of knowing, for random rules: go through every address of the networks the rules are
// about, one by one, and note which predicates hold it.
func TestEveryGroupOfSendersIsAsked(t *testing.T) {
	rng := rand.New(rand.NewSource(20261111))
	// The addresses gone through one by one: three networks and the stretch around each.
	var all4, all6 []netip.Addr
	for _, p := range []string{"203.0.113.0", "198.51.100.0", "192.0.2.0"} {
		for a, i := addr(p).Prev().Prev(), 0; i < 260; a, i = a.Next(), i+1 {
			all4 = append(all4, a)
		}
	}
	for _, p := range []string{"2001:db8:1::", "2001:db8:99::"} {
		for a, i := addr(p).Prev().Prev(), 0; i < 260; a, i = a.Next(), i+1 {
			all6 = append(all6, a)
		}
	}
	// One range of addresses inside those networks, or around them, as a rule might name it.
	atom := func(v6 bool) rules.Atom {
		base, bits, all := addr([]string{"203.0.113.0", "198.51.100.0", "192.0.2.0"}[rng.Intn(3)]).As4(), 32, all4
		if v6 {
			bits, all = 128, all6
		}
		switch rng.Intn(10) {
		case 0, 1: // a range between two of the addresses
			lo, hi := all[rng.Intn(len(all))], all[rng.Intn(len(all))]
			if lo.Compare(hi) > 0 {
				lo, hi = hi, lo
			}
			return rules.Atom{Kind: rules.AtomRange, AddrLo: lo, AddrHi: hi}
		case 2: // something much wider than the networks
			if v6 {
				return rules.Pfx(netip.PrefixFrom(addr("2001:db8::"), 16+rng.Intn(33)))
			}
			return rules.Pfx(netip.PrefixFrom(netip.AddrFrom4(base), 1+rng.Intn(23)))
		}
		a := all[rng.Intn(len(all))]
		return rules.Pfx(netip.PrefixFrom(a, bits-rng.Intn(9)))
	}
	holds := func(x rules.Atom, a netip.Addr) bool {
		if x.Kind == rules.AtomRange {
			return x.AddrLo.Is4() == a.Is4() && x.AddrLo.Compare(a) <= 0 && a.Compare(x.AddrHi) <= 0
		}
		return x.Prefix.Contains(a)
	}
	for round := 0; round < 300; round++ {
		// A handful of rules: most match a set of ranges, where being in the set is all that
		// counts; some look each sender up in a verdict map, which tells every element apart.
		var exprs []rules.Expr
		var tells [][]rules.Atom // each entry is one thing that tells senders apart
		for n := 1 + rng.Intn(6); n > 0; n-- {
			var atoms []rules.Atom
			for m := 1 + rng.Intn(5); m > 0; m-- {
				atoms = append(atoms, atom(rng.Intn(4) == 0))
			}
			if rng.Intn(4) == 0 {
				vm := &rules.VerdictMap{Key: []rules.Field{{Name: rules.FSaddr}}}
				for _, x := range atoms {
					vm.Entries = append(vm.Entries, rules.VmapEntry{Key: rules.Elem{x}, Verdict: rules.Verdict{Kind: rules.Accept}})
					tells = append(tells, []rules.Atom{x})
				}
				exprs = append(exprs, vm)
				continue
			}
			m := rules.Eq(rules.FSaddr, atoms...)
			m.Neg = rng.Intn(5) == 0
			exprs = append(exprs, m)
			tells = append(tells, atoms)
		}
		sig := func(a netip.Addr) string {
			s := make([]byte, len(tells))
			for i, atoms := range tells {
				s[i] = '0'
				for _, x := range atoms {
					if holds(x, a) {
						s[i] = '1'
					}
				}
			}
			return string(s)
		}
		b := newBuilder(inputRules(exprs...), box())
		for _, side := range []struct {
			scope string
			v6    bool
		}{{"world", false}, {"lan", false}, {"world", true}, {"lan", true}} {
			nets, own, all := nets4, own4, all4
			if side.v6 {
				nets, own, all = nets6, own6, all6
			}
			can := b.sender("eth0", side.scope, side.v6, nets, own)
			asked := map[string]netip.Addr{}
			for _, c := range classesOf(b, side.scope, side.v6, nets, own, own) {
				if !can(c.addr) {
					t.Fatalf("round %d, %s: %s was asked and cannot send from there", round, side.scope, c.addr)
				}
				if other, twice := asked[sig(c.addr)]; twice {
					t.Fatalf("round %d, %s: %s and %s were both asked, and no rule tells them apart", round, side.scope, other, c.addr)
				}
				asked[sig(c.addr)] = c.addr
			}
			for _, a := range all {
				if _, ok := asked[sig(a)]; can(a) && !ok {
					t.Fatalf("round %d, %s, IPv6 %v: nobody like %s was asked (the rules tell it apart as %s); asked were %v",
						round, side.scope, side.v6, a, sig(a), asked)
				}
			}
		}
	}
}

// The atlas says of every address which predicates hold it, the same as asking each predicate.
func TestAtlasAgreesWithThePredicates(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	pick := func() netip.Addr {
		return netip.AddrFrom4([4]byte{198, 51, byte(100 + rng.Intn(2)), byte(rng.Intn(256))})
	}
	for round := 0; round < 200; round++ {
		b := &builder{rs: &rules.Ruleset{}, h: box()}
		for n := rng.Intn(8); n > 0; n-- {
			var iv []ival
			for m := 1 + rng.Intn(6); m > 0; m-- {
				lo, hi := pick(), pick()
				if lo.Compare(hi) > 0 {
					lo, hi = hi, lo
				}
				if rng.Intn(3) == 0 {
					hi = lo
				}
				iv = append(iv, ival{lo, hi})
			}
			b.preds = append(b.preds, newPred("", iv))
		}
		at := b.atlas(false)
		if !slices.IsSortedFunc(at.starts, netip.Addr.Compare) || at.starts[0] != addr("0.0.0.0") || len(at.where) != len(at.starts) {
			t.Fatalf("round %d: the stretches are out of order or do not start at the first address", round)
		}
		for i := 0; i < 400; i++ {
			a := pick()
			if i%7 == 0 {
				a = at.starts[rng.Intn(len(at.starts))] // where a stretch starts
			} else if i%7 == 1 {
				if a = at.starts[rng.Intn(len(at.starts))].Prev(); !a.IsValid() {
					continue // and where the one before it ends
				}
			}
			var want []int32
			for j := range b.preds {
				if _, ok := b.preds[j].find(a); ok {
					want = append(want, int32(j))
				}
			}
			if got := at.held[at.find(a)]; !slices.Equal(got, want) {
				t.Fatalf("round %d: %s is held by %v, the atlas says %v", round, a, want, got)
			}
		}
	}
}

// A stretch of addresses ends wherever an address stops or starts being a possible sender: the
// machine's own address, its network's first and last, the special ranges, where a route ends.
func TestAtlasCutsWhereSendersChange(t *testing.T) {
	b := newBuilder(nil, box())
	at := b.atlas(false)
	for _, a := range []string{
		"0.0.0.0", "0.0.0.1", "127.0.0.0", "128.0.0.0", "169.254.0.0", "169.255.0.0", "224.0.0.0", "240.0.0.0",
		"203.0.113.0", "203.0.113.1", "203.0.113.10", "203.0.113.11", "203.0.113.255", "203.0.114.0",
		"192.0.2.128", "192.0.2.129", "192.0.2.130", "192.0.2.255", "192.0.3.0", "198.51.100.192", "198.51.101.0",
	} {
		if _, found := slices.BinarySearchFunc(at.starts, addr(a), netip.Addr.Compare); !found {
			t.Errorf("no stretch starts at %s", a)
		}
	}
	at6 := b.atlas(true)
	for _, a := range []string{"::", "::1", "::2", "fe80::", "fec0::", "ff00::", "2001:db8:1::", "2001:db8:1::10", "2001:db8:1::11", "2001:db8:1:1::"} {
		if _, found := slices.BinarySearchFunc(at6.starts, addr(a), netip.Addr.Compare); !found {
			t.Errorf("no stretch starts at %s", a)
		}
	}
	if b.atlas(false) != at || len(at.held) != 1 || len(at.held[0]) != 0 {
		t.Errorf("without rules there is one group, everyone, and the atlas is drawn once: %v", at.held)
	}
	// A group whose first address cannot send is still asked about, at the first one that can:
	// the local network starts with its own address, which is nobody's.
	b = newBuilder(inputRules(rules.Eq(rules.FSaddr, rules.Pfx(netip.MustParsePrefix("203.0.113.0/24")), rules.Pfx(netip.MustParsePrefix("192.0.2.0/24")))), box())
	var got []string
	for _, c := range classesOf(b, "lan", false, nets4, own4, own4) {
		got = append(got, c.label+" "+c.addr.String())
	}
	if want := []string{"anyone on the local network 203.0.113.11"}; !reflect.DeepEqual(got, want) {
		t.Errorf("from the local network: %q, want %q", got, want)
	}
	got = nil
	for _, c := range classesOf(b, "world", false, nets4, own4, own4) {
		got = append(got, c.label+" "+c.addr.String())
	}
	// 192.0.2.7 stands for the rule's second network. Its upper half is reached through eth1, so
	// nobody there sends by way of eth0, and that changes nothing: the lower half is asked.
	if want := []string{"anyone 198.51.100.7", "192.0.2.0/24 192.0.2.7"}; !reflect.DeepEqual(got, want) {
		t.Errorf("from the internet: %q, want %q", got, want)
	}
}

// Past the ceiling the groups the fewest rules single out are kept, "everyone else" first, and
// the builder notes that it left some out.
func TestSenderCeiling(t *testing.T) {
	var exprs []rules.Expr
	for i := 0; i < maxClasses+50; i++ {
		exprs = append(exprs, rules.Eq(rules.FSaddr, rules.Pfx(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32))))
	}
	b := newBuilder(inputRules(exprs[:maxClasses-1]...), box())
	cl, cut := b.classes("eth0", "world", false, nets4, own4, own4)
	if len(cl) != maxClasses || cut || b.crowded {
		t.Errorf("at the ceiling: %d groups, cut %v, crowded %v", len(cl), cut, b.crowded)
	}
	b = newBuilder(inputRules(exprs...), box())
	cl, cut = b.classes("eth0", "world", false, nets4, own4, own4)
	if len(cl) != maxClasses || !cut || !b.crowded {
		t.Fatalf("past the ceiling: %d groups, cut %v, crowded %v", len(cl), cut, b.crowded)
	}
	// The ceiling is one place's: from the local network the same rules single nobody out.
	if near, cut := b.classes("eth0", "lan", false, nets4, own4, own4); len(near) != 1 || cut {
		t.Errorf("from the local network: %d groups, cut %v", len(near), cut)
	}
	if !cl[0].generic || cl[0].label != "anyone" || cl[0].addr != addr("198.51.100.7") || cl[1].label != "10.0.0.1" || cl[maxClasses-1].label != "10.3.254.1" {
		t.Errorf("kept: %v, %v ... %v", cl[0], cl[1], cl[maxClasses-1])
	}
}

// A snapshot may hold addresses nobody would write by hand: an IPv4 address or network in its
// IPv6 form (::ffff:192.0.2.9/120), an IPv6 network that ends where such addresses lie (::/80),
// a range with its ends the wrong way round or in two families. None of them may stop the scan,
// and each is read the way the engine compares it with a packet.
func TestOddAddresses(t *testing.T) {
	h := box()
	h.Interfaces[1].Addrs = append(h.Interfaces[1].Addrs, netip.MustParsePrefix("::ffff:192.0.2.9/120"))
	h.Routes = append(h.Routes,
		host.Route{Dst: netip.MustParsePrefix("::ffff:1.2.3.0/120"), Dev: "eth0"},
		host.Route{Dst: netip.MustParsePrefix("::ffff:0:0/96"), Dev: "eth0"})
	rng := func(lo, hi string) rules.Atom {
		return rules.Atom{Kind: rules.AtomRange, AddrLo: addr(lo), AddrHi: addr(hi)}
	}
	b := newBuilder(inputRules(
		rules.Eq(rules.FSaddr, rules.Pfx(netip.MustParsePrefix("::/80"))),
		rules.Eq(rules.FSaddr, rules.Pfx(netip.MustParsePrefix("::ffff:1.2.3.0/120"))),
		rules.Eq(rules.FSaddr, rng("198.51.100.9", "198.51.100.3")),                             // the wrong way round: holds nothing
		rules.Eq(rules.FSaddr, rng("2001:db8:99::1", "198.51.100.3")),                           // from IPv6 to IPv4: holds nothing
		rules.Eq(rules.FSaddr, rng("198.51.101.200", "2001:db8:99::1")),                         // from IPv4 to IPv6: every IPv4 address from there on
		rules.Eq(rules.FSaddr, rules.Atom{Kind: rules.AtomRange, AddrLo: addr("198.51.100.1")}), // half a range
	), h)
	var preds []string
	for _, p := range b.preds {
		for _, v := range p.iv {
			if v.lo.BitLen() != v.hi.BitLen() || v.lo.Compare(v.hi) > 0 {
				t.Errorf("a range that is none: %v to %v", v.lo, v.hi)
			}
			preds = append(preds, v.String())
		}
	}
	if want := "::/80 ::ffff:1.2.3.0/120 198.51.101.200 to 255.255.255.255"; strings.Join(preds, " ") != want {
		t.Errorf("predicates: %q, want %q", preds, want)
	}
	groups := func(scope string, v6 bool) []string {
		nets, own := nets4, own4
		if v6 {
			nets, own = nets6, own6
		}
		var out []string
		for _, c := range classesOf(b, scope, v6, nets, own, own) {
			if c.addr.Is6() != v6 || c.addr.Is4In6() {
				t.Errorf("%s, IPv6 %v: %s was asked", scope, v6, c.addr)
			}
			out = append(out, c.label+" "+c.addr.String())
		}
		return out
	}
	// ::/80 is told apart from the rest of IPv6, at the first of its addresses that is nobody
	// special; the IPv4 addresses written as IPv6 ones are no senders, so their network has none.
	if got, want := groups("world", true), []string{"anyone 2001:db8:99::7", "::/80 ::2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("from the internet over IPv6: %q, want %q", got, want)
	}
	if got, want := groups("world", false), []string{"anyone 198.51.100.7", "198.51.101.200 to 255.255.255.255 198.51.101.200"}; !reflect.DeepEqual(got, want) {
		t.Errorf("from the internet over IPv4: %q, want %q", got, want)
	}
	groups("lan", false)
	groups("lan", true)
	// The same through the whole scan, with the odd addresses as the firewall manager's too.
	h.Frontend = &host.Frontend{Tool: "ufw", Active: true, DefaultIncoming: "deny", Rules: []host.FrontendRule{
		{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, From: netip.MustParsePrefix("::/80"), IPv6: true},
		{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, From: netip.MustParsePrefix("::ffff:1.2.3.0/120"), IPv6: true},
	}}
	h.Listeners = []host.Listener{{Proto: "tcp", Addr: addr("::"), DualStack: true, Port: 22, Process: "sshd"}}
	r := Run(b.rs, h)
	// The machine's own network lies in the range that runs to the end of IPv4, so it gets in too.
	if len(r.Ports) != 1 || r.Ports[0].Reach != "the local network on eth0 over IPv4, 198.51.101.200 to 255.255.255.255 and ::/80 only" {
		t.Errorf("the scan: %d ports, reached by %q", len(r.Ports), r.Ports[0].Reach)
	}
	if got := r.Ports[0].Stated; got != "allowed only from ::/80 and from ::ffff:1.2.3.0/120" {
		t.Errorf("what ufw says: %q", got)
	}
	if out := Text(r, TextOptions{Width: 60}); !strings.Contains(out, "::/80") {
		t.Errorf("the text:\n%s", out)
	}
	if lastAddr(netip.Prefix{}).IsValid() {
		t.Error("a network that is none has a last address")
	}
}
