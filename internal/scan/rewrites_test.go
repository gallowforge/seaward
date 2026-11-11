package scan

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// The search for the ports a rule sends somewhere else, piece by piece. What a whole scan makes
// of it is in ports_test.go; the kernel's word on it is in the lab (dnat-behind-jump,
// nft-dnat-behind-jump).

func natTable(chains ...*rules.Chain) *rules.Table {
	t := &rules.Table{Family: "ip", Name: "nat", Origin: "nft", Chains: map[string]*rules.Chain{}}
	for _, c := range chains {
		t.Chains[c.Name] = c
		t.Order = append(t.Order, c.Name)
	}
	return t
}

// hooked is a base chain on a hook; plain is a chain only a jump reaches.
func hooked(name, hook string, rs ...*rules.Rule) *rules.Chain {
	return &rules.Chain{Name: name, Base: true, Hook: hook, Type: "nat", Priority: -100, Policy: rules.Accept, Rules: rs}
}
func plain(name string, rs ...*rules.Rule) *rules.Chain { return &rules.Chain{Name: name, Rules: rs} }
func when(xs ...rules.Expr) *rules.Rule                 { return &rules.Rule{Text: "rule", Exprs: xs} }
func to(kind rules.VerdictKind, chain string) *rules.Verdict {
	return &rules.Verdict{Kind: kind, Chain: chain}
}
func dports(spans ...[2]uint32) *rules.Match {
	var atoms []rules.Atom
	for _, s := range spans {
		atoms = append(atoms, rules.NumRange(s[0], s[1]))
	}
	return rules.Eq(rules.FDport, atoms...)
}

var (
	isTCP   = rules.Eq(rules.FL4Proto, rules.Num(6))
	isUDP   = rules.Eq(rules.FL4Proto, rules.Num(17))
	rewrite = &rules.DNAT{Addr: netip.MustParseAddr("192.0.2.50")}
)

// said writes the ways out, sorted by nothing: the order the search found them in.
func said(ws []way) string {
	var out []string
	for _, w := range ws {
		s := ""
		if w.tcp {
			s += "tcp"
		}
		if w.udp {
			s += "udp"
		}
		for _, p := range w.ports {
			if p[0] == p[1] {
				s += fmt.Sprintf(" %d", p[0])
			} else {
				s += fmt.Sprintf(" %d-%d", p[0], p[1])
			}
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

func rewrittenIn(sets map[string]*rules.Set, tables ...*rules.Table) (string, bool) {
	b := &builder{rs: &rules.Ruleset{Tables: tables, Sets: sets}}
	ws, lost := b.rewritten()
	return said(ws), lost
}

func TestPortSets(t *testing.T) {
	got := ports([][2]uint16{{80, 80}, {0, 5}, {20, 30}, {25, 40}, {9, 3}, {41, 41}, {80, 80}})
	if fmt.Sprint(got) != "[[1 5] [20 40] [41 41] [80 80]]" {
		t.Errorf("ports: %v", got)
	}
	both := got.and(ports([][2]uint16{{4, 22}, {40, 41}, {79, 90}, {100, 200}}))
	if fmt.Sprint(both) != "[[4 5] [20 22] [40 40] [41 41] [80 80]]" {
		t.Errorf("and: %v", both)
	}
	if len(got.and(nil)) != 0 || len(portSet(nil).and(got)) != 0 {
		t.Error("nothing is in both an empty set and another")
	}
	if fmt.Sprint(allPorts.and(got)) != fmt.Sprint(got) {
		t.Errorf("every port and a set: %v", allPorts.and(got))
	}
	a, b := way{tcp: true, ports: ports([][2]uint16{{1, 2}})}, way{udp: true, ports: ports([][2]uint16{{1, 2}})}
	if a.key() == b.key() || a.key() != (way{tcp: true, ports: portSet{{1, 2}}}).key() {
		t.Error("a way's key tells protocols apart and nothing else")
	}
	if !(way{tcp: true}).empty() || !(way{ports: allPorts}).empty() || a.empty() {
		t.Error("a way with no protocol or no port is empty")
	}
}

// What a condition on the way does to the ports that can have come that far.
func TestWhatNarrowsTheWay(t *testing.T) {
	concat := &rules.Match{Key: []rules.Field{{Name: rules.FL4Proto}, {Name: rules.FDport}}, Values: &rules.Set{Elems: []rules.Elem{
		{rules.Num(6), rules.Num(443)}, {rules.Num(17), rules.NumRange(5000, 5010)},
	}}}
	wild := &rules.Match{Key: []rules.Field{{Name: rules.FSaddr}, {Name: rules.FDport}}, Values: &rules.Set{Elems: []rules.Elem{
		{rules.Pfx(netip.MustParsePrefix("198.51.100.0/24")), rules.Num(22)}, {rules.Pfx(netip.MustParsePrefix("203.0.113.0/24")), {}},
	}}}
	masked := &rules.Match{Key: []rules.Field{{Name: rules.FDport, Mask: 0xff00, HasMask: true}}, Values: rules.One(rules.Num(0x1f00))}
	sets := map[string]*rules.Set{
		"web":     rules.One(rules.Num(80), rules.Num(443)),
		"torn":    {Elems: []rules.Elem{{rules.Num(80)}}, Incomplete: true, Why: "the set torn could not be read"},
		"knocked": {Elems: []rules.Elem{{rules.Num(2222)}}, Dynamic: true},
	}
	named := func(name string) *rules.Match {
		return &rules.Match{Key: []rules.Field{{Name: rules.FDport}}, SetRef: name}
	}
	for _, c := range []struct {
		name string
		cond []rules.Expr
		want string
	}{
		{"nothing", nil, "tcpudp 1-65535"},
		{"a port", []rules.Expr{dports([2]uint32{8080, 8080})}, "tcpudp 8080"},
		{"a protocol and ports", []rules.Expr{isTCP, dports([2]uint32{8000, 8010}, [2]uint32{9000, 9000})}, "tcp 8000-8010 9000"},
		{"two port matches: both hold", []rules.Expr{dports([2]uint32{8000, 8010}), dports([2]uint32{8005, 9000})}, "tcpudp 8005-8010"},
		{"two that cannot both hold", []rules.Expr{dports([2]uint32{80, 80}), dports([2]uint32{81, 81})}, ""},
		{"two protocols that cannot both hold", []rules.Expr{isTCP, isUDP}, ""},
		{"neither tcp nor udp", []rules.Expr{rules.Eq(rules.FL4Proto, rules.Num(132))}, ""},
		{"a range of protocols", []rules.Expr{rules.Eq(rules.FL4Proto, rules.NumRange(6, 17))}, "tcpudp 1-65535"},
		// Every port but one passes a match that says "not": it rules next to nothing out.
		{"not a port", []rules.Expr{rules.Ne(rules.FDport, rules.Num(22))}, "tcpudp 1-65535"},
		{"not a protocol", []rules.Expr{rules.Ne(rules.FL4Proto, rules.Num(6))}, "tcpudp 1-65535"},
		{"the port a connection was first sent to", []rules.Expr{rules.Eq(rules.FCtOrigDport, rules.Num(2222))}, "tcpudp 2222"},
		{"protocol and port as one key", []rules.Expr{concat}, "tcpudp 443 5000-5010"},
		{"an entry that holds for every port", []rules.Expr{wild}, "tcpudp 1-65535"},
		{"some bits of the port", []rules.Expr{masked}, "tcpudp 1-65535"},
		{"a named set", []rules.Expr{named("web")}, "tcpudp 80 443"},
		{"a set that could not be read", []rules.Expr{named("torn")}, "tcpudp 1-65535"},
		// What such a set holds now it may not hold in a minute.
		{"a set the rules fill as packets come", []rules.Expr{named("knocked")}, "tcpudp 1-65535"},
		{"a set that is not there", []rules.Expr{named("gone")}, "tcpudp 1-65535"},
		{"a condition the model cannot decide", []rules.Expr{&rules.Unknown{Why: "the string match looks inside the packet"}, dports([2]uint32{25, 25})}, "tcpudp 25"},
		// False for the first packet from a sender, true once the sender has knocked.
		{"a condition a first packet fails", []rules.Expr{&rules.Never{What: "recent --rcheck"}, dports([2]uint32{22, 22})}, "tcpudp 22"},
		{"the sender's port", []rules.Expr{rules.Eq(rules.FSport, rules.Num(53))}, "tcpudp 1-65535"},
	} {
		got, lost := rewrittenIn(sets, natTable(hooked("pre", rules.HookPrerouting, when(append(c.cond, rewrite)...))))
		if got != c.want || lost {
			t.Errorf("%s: %q (lost %v), want %q", c.name, got, lost, c.want)
		}
		// The same condition in the calling rule, with the rewrite one chain further.
		got, _ = rewrittenIn(sets, natTable(hooked("pre", rules.HookPrerouting, when(append(c.cond, to(rules.Jump, "next"))...)), plain("next", when(rewrite))))
		if got != c.want {
			t.Errorf("%s, before a jump: %q, want %q", c.name, got, c.want)
		}
	}
}

// Which statements count, and from which chains the search sets out.
func TestWhereARewriteCounts(t *testing.T) {
	sends := when(isTCP, dports([2]uint32{80, 80}), rewrite)
	for _, c := range []struct {
		name  string
		chain *rules.Chain
		want  string
	}{
		{"prerouting", hooked("c", rules.HookPrerouting, sends), "tcp 80"},
		{"ingress", hooked("c", rules.HookIngress, sends), "tcp 80"},
		// After routing the destination is settled; a packet this machine sends is not one from outside.
		{"input", hooked("c", rules.HookInput, sends), ""},
		{"forward", hooked("c", rules.HookForward, sends), ""},
		{"output", hooked("c", rules.HookOutput, sends), ""},
		{"postrouting", hooked("c", rules.HookPostrouting, sends), ""},
		{"a chain nothing jumps to", plain("c", sends), ""},
		{"redirect", hooked("c", rules.HookPrerouting, when(isUDP, dports([2]uint32{53, 53}), &rules.Redirect{Port: 5353})), "udp 53"},
		{"a statement the engine cannot follow", hooked("c", rules.HookPrerouting, when(isTCP, dports([2]uint32{3128, 3128}), &rules.UnknownStmt{Why: "tproxy"})), "tcp 3128"},
		{"a mark is no rewrite", hooked("c", rules.HookPrerouting, when(isTCP, dports([2]uint32{80, 80}), &rules.SetMark{Xor: 1})), ""},
		{"an accept is no rewrite", hooked("c", rules.HookPrerouting, when(isTCP, dports([2]uint32{80, 80}), to(rules.Accept, ""))), ""},
	} {
		if got, lost := rewrittenIn(nil, natTable(c.chain)); got != c.want || lost {
			t.Errorf("%s: %q (lost %v), want %q", c.name, got, lost, c.want)
		}
	}
}

// Jumps, gotos and verdict maps, in a row and side by side.
func TestTheWayThroughChains(t *testing.T) {
	byPort := func(entries ...rules.VmapEntry) *rules.VerdictMap {
		return &rules.VerdictMap{Key: []rules.Field{{Name: rules.FDport}}, Entries: entries}
	}
	entry := func(lo, hi uint32, v *rules.Verdict) rules.VmapEntry {
		return rules.VmapEntry{Key: rules.Elem{rules.NumRange(lo, hi)}, Verdict: *v}
	}
	sets := map[string]*rules.Set{
		rules.SetKey("ip", "nat", "byport"): {
			Elems:    []rules.Elem{{rules.Num(8300)}, {rules.Num(8301)}, {rules.Num(8302)}},
			Verdicts: []rules.Verdict{*to(rules.Jump, "send"), *to(rules.Drop, ""), *to(rules.Goto, "send")},
		},
		rules.SetKey("ip", "nat", "torn"): {Incomplete: true, Why: "the map torn could not be read"},
	}
	send := plain("send", when(rewrite))
	for _, c := range []struct {
		name   string
		chains []*rules.Chain
		want   string
	}{
		{"three chains deep", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{8000, 8999}), to(rules.Jump, "a"))),
			plain("a", when(dports([2]uint32{8100, 8200}), to(rules.Goto, "b"))),
			plain("b", when(dports([2]uint32{8150, 8300}), to(rules.Jump, "send"))), send},
			"tcp 8150-8200"},
		{"a port the called chain names and the caller does not", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(dports([2]uint32{80, 80}), to(rules.Jump, "a"))),
			plain("a", when(dports([2]uint32{443, 443}), rewrite))},
			""},
		{"two ways into one chain", []*rules.Chain{
			hooked("pre", rules.HookPrerouting,
				when(isTCP, dports([2]uint32{80, 80}), to(rules.Jump, "send")),
				when(isUDP, dports([2]uint32{53, 53}), to(rules.Jump, "send")),
				when(isTCP, dports([2]uint32{80, 80}), to(rules.Goto, "send"))),
			send},
			"tcp 80; udp 53"},
		{"a verdict map", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, byPort(
				entry(8200, 8200, to(rules.Jump, "send")), entry(8201, 8210, to(rules.Goto, "send")),
				entry(8211, 8211, to(rules.Accept, "")), entry(8212, 8212, to(rules.Jump, "idle"))))),
			send, plain("idle")},
			"tcp 8200; tcp 8201-8210"},
		{"a verdict map after a port match", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(dports([2]uint32{8205, 9000}), byPort(entry(8201, 8210, to(rules.Jump, "send"))))),
			send},
			"tcpudp 8205-8210"},
		{"a named verdict map", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, &rules.VerdictMap{Key: []rules.Field{{Name: rules.FDport}}, SetRef: rules.SetKey("ip", "nat", "byport")})),
			send},
			"tcp 8300; tcp 8302"},
		// Where the entries of a map lead is not known when the map could not be read: every port
		// that comes as far as the map is worth asking about.
		{"a verdict map that could not be read", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{9000, 9100}), &rules.VerdictMap{Key: []rules.Field{{Name: rules.FDport}}, SetRef: rules.SetKey("ip", "nat", "torn")}))},
			"tcp 9000-9100"},
		{"a verdict map that is not there", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isUDP, &rules.VerdictMap{Key: []rules.Field{{Name: rules.FDport}}, SetRef: "gone"}))},
			"udp 1-65535"},
		// The same for a jump to a chain the listing does not have.
		{"a jump to a chain that is not there", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{7000, 7000}), to(rules.Jump, "gone")))},
			"tcp 7000"},
		// The kernel loads no chains that jump in a circle, and a listing may still hold them. The
		// engine follows a packet round until it is too deep and decides nothing, so the ports
		// that come as far as the circle are worth a row: once for the circle, once for the rewrite.
		{"chains that jump in a circle", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{80, 80}), to(rules.Jump, "a"))),
			plain("a", when(to(rules.Jump, "b"))),
			plain("b", when(to(rules.Jump, "a")), when(rewrite))},
			"tcp 80; tcp 80"},
		{"a circle and no rewrite", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{100, 200}), to(rules.Jump, "loop"))),
			plain("loop", when(to(rules.Jump, "loop")))},
			"tcp 100-200"},
		{"a chain entered twice the same way is no circle", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{80, 80}), to(rules.Jump, "a")), when(isTCP, dports([2]uint32{80, 80}), to(rules.Jump, "a"))),
			plain("a", when(to(rules.Return, "")))},
			""},
		{"a rule that goes on after its rewrite is found once", []*rules.Chain{
			hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{80, 80}), rewrite), when(isTCP, dports([2]uint32{81, 81}), to(rules.Return, "")))},
			"tcp 80"},
	} {
		if got, lost := rewrittenIn(sets, natTable(c.chains...)); got != c.want || lost {
			t.Errorf("%s: %q (lost %v), want %q", c.name, got, lost, c.want)
		}
	}
}

// Rules too tangled to go through are said to be: the scan then asks about every port.
func TestTheSearchGivesUp(t *testing.T) {
	// Seventy chains, each jumping to the next: deeper than the engine follows.
	chains := []*rules.Chain{hooked("pre", rules.HookPrerouting, when(isTCP, dports([2]uint32{80, 80}), to(rules.Jump, "c0")))}
	for i := 0; i < 70; i++ {
		chains = append(chains, plain(fmt.Sprintf("c%d", i), when(to(rules.Jump, fmt.Sprintf("c%d", i+1)))))
	}
	chains = append(chains, plain("c70", when(rewrite)))
	if _, lost := rewrittenIn(nil, natTable(chains...)); !lost {
		t.Error("seventy chains deep: the search did not say it gave up")
	}
	// Sixty deep is followed.
	chains[61] = plain("c60", when(rewrite))
	if got, lost := rewrittenIn(nil, natTable(chains...)); got != "tcp 80" || lost {
		t.Errorf("sixty chains deep: %q (lost %v)", got, lost)
	}
	// Chains of overlapping ranges that call each other: every rule of one hands the next a way
	// of its own, and the ways multiply. The search counts the rules it looks at and stops in
	// time; it does not go on for as long as there are ways.
	wide := func(name, next string) *rules.Chain {
		c := plain(name)
		for i := uint32(0); i < 150; i++ {
			c.Rules = append(c.Rules, when(dports([2]uint32{1000 + i, 60000 - i}), to(rules.Jump, next)))
		}
		return c
	}
	l0 := wide("pre", "l1")
	l0.Base, l0.Hook, l0.Type, l0.Policy = true, rules.HookPrerouting, "nat", rules.Accept
	shift := func(c *rules.Chain, by uint32) *rules.Chain {
		for i, r := range c.Rules {
			r.Exprs[0] = dports([2]uint32{1000 + by + uint32(i)*3, 60000 + by - uint32(i)*7})
		}
		return c
	}
	began := time.Now()
	_, lost := rewrittenIn(nil, natTable(l0, shift(wide("l1", "l2"), 200), shift(wide("l2", "l3"), 500), shift(wide("l3", "l4"), 900), plain("l4", when(rewrite))))
	if took := time.Since(began); !lost || took > 3*time.Second {
		t.Errorf("chains of overlapping ranges: lost %v after %v", lost, took)
	}

	// A scan of rules it gave up on asks about every port of both protocols, as one long range,
	// at each place where a rule sets a port apart.
	chains[61] = plain("c60", when(to(rules.Jump, "c61")))
	b := newBuilder(&rules.Ruleset{Tables: []*rules.Table{natTable(chains...)}}, &host.Host{})
	var got []string
	for _, k := range b.candidates() {
		got = append(got, k.String())
	}
	if strings.Join(got, ", ") != "tcp 1, udp 1, tcp 80, udp 80, tcp 81, udp 81, tcp 65535, udp 65535" {
		t.Errorf("ports asked after giving up: %s", strings.Join(got, ", "))
	}
	if strings.Join(b.ranges, ", ") != "tcp 1 to 65535, udp 1 to 65535" {
		t.Errorf("ranges said: %q", b.ranges)
	}
}

// A big cluster is nowhere near giving up: ten thousand services, each with a rule for its port
// and one for its node port, a chain of its own and three chains that rewrite, as kube-proxy
// lays them out. Every one of the twenty thousand ports is found, each once.
func TestTenThousandServices(t *testing.T) {
	const n = 10000
	services, nodePorts := plain("KUBE-SERVICES", when(to(rules.Jump, "KUBE-NODEPORTS"))), plain("KUBE-NODEPORTS")
	chains := []*rules.Chain{hooked("PREROUTING", rules.HookPrerouting, when(to(rules.Jump, "KUBE-SERVICES"))), services, nodePorts}
	for i := uint32(0); i < n; i++ {
		svc := fmt.Sprintf("KUBE-SVC-%d", i)
		services.Rules = append(services.Rules, when(isTCP, dports([2]uint32{1000 + 3*i, 1000 + 3*i}), to(rules.Jump, svc)))
		nodePorts.Rules = append(nodePorts.Rules, when(isTCP, dports([2]uint32{1001 + 3*i, 1001 + 3*i}), to(rules.Jump, svc)))
		c := plain(svc)
		for j := 0; j < 3; j++ {
			sep := fmt.Sprintf("KUBE-SEP-%d-%d", i, j)
			c.Rules = append(c.Rules, when(to(rules.Jump, sep)))
			chains = append(chains, plain(sep, when(isTCP, rewrite)))
		}
		chains = append(chains, c)
	}
	b := &builder{rs: &rules.Ruleset{Tables: []*rules.Table{natTable(chains...)}}}
	began := time.Now()
	ws, lost := b.rewritten()
	if took := time.Since(began); lost || took > 3*time.Second {
		t.Fatalf("lost %v after %v", lost, took)
	}
	seen := map[uint16]int{}
	for _, w := range ws {
		if !w.tcp || w.udp || len(w.ports) != 1 || w.ports[0][0] != w.ports[0][1] {
			t.Fatalf("a way that is not one tcp port: %+v", w)
		}
		seen[w.ports[0][0]]++
	}
	// each port is found once for each of the three chains that rewrite it
	if len(seen) != 2*n || seen[1000] != 3 || seen[1001] != 3 || seen[1002] != 0 || seen[1000+3*(n-1)] != 3 {
		t.Errorf("%d ports found, want %d; 1000: %d, 1001: %d, 1002: %d", len(seen), 2*n, seen[1000], seen[1001], seen[1002])
	}
}
