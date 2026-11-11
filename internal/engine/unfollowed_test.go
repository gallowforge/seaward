package engine

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// The tests of this file are about rules.Unfollowed: the chains the kernel runs at a point of the
// packet path the engine does not walk. A packet that passes one is undecided, and how much still
// stands depends on what the chain can do.

// hangs checks a result that is undecided: it lists exactly these ways to end and these reasons,
// in this order, and it keeps otherwise (zero for none).
func hangs(t *testing.T, what string, r Result, otherwise Class, possible []Class, unknowns ...string) {
	t.Helper()
	if r.Class != Undecided || r.Otherwise != otherwise || !slices.Equal(r.Possible, possible) || !slices.Equal(r.Unknowns, unknowns) {
		t.Errorf("%s: %v, otherwise %v, one of %v, hanging on %q\nwant %v, otherwise %v, one of %v, hanging on %q",
			what, r.Class, r.Otherwise, r.Possible, r.Unknowns, Undecided, otherwise, possible, unknowns)
	}
}

// decided checks a result no chain outside the walked path had a say about.
func decided(t *testing.T, what string, r Result, c Class) {
	t.Helper()
	if r.Class != c || r.Otherwise != 0 || len(r.Possible) != 0 || len(r.Unknowns) != 0 {
		t.Errorf("%s: %v, otherwise %v, one of %v, hanging on %q\nwant %v and nothing else\n%s",
			what, r.Class, r.Otherwise, r.Possible, r.Unknowns, c, trace(r))
	}
}

// TestStack: the interfaces a packet passes on its way in or out are the one it is seen on and
// everything underneath it: the ports of a bridge or bond (host.Interface.Master) and whatever a
// VLAN sits on (Lower), as deep as that goes. Never what is above.
func TestStack(t *testing.T) {
	e := New(nil, &host.Host{Interfaces: []host.Interface{
		{Name: "eth0"},
		{Name: "br0", Kind: "bridge"},
		{Name: "eth1", Master: "br0"},
		{Name: "eth2", Master: "br0"},
		{Name: "bond0", Kind: "bond"},
		{Name: "eth3", Master: "bond0"},
		{Name: "eth4", Master: "bond0"},
		{Name: "eth0.100", Kind: "vlan", Lower: "eth0"},
		{Name: "bond0.200", Kind: "vlan", Lower: "bond0"},
		{Name: "br1", Kind: "bridge"},
		{Name: "eth5"},
		{Name: "eth5.300", Kind: "vlan", Lower: "eth5", Master: "br1"},
		{Name: "br1.7", Kind: "vlan", Lower: "br1"},
		// No machine says this of itself; the walk down still has to end.
		{Name: "loop0", Lower: "loop1"},
		{Name: "loop1", Lower: "loop0", Master: "loop1"},
	}})
	for _, c := range []struct {
		name    string
		want    []string
		bridged bool
	}{
		{"eth0", []string{"eth0"}, false},
		{"br0", []string{"br0", "eth1", "eth2"}, true},
		{"bond0", []string{"bond0", "eth3", "eth4"}, false},
		{"eth0.100", []string{"eth0.100", "eth0"}, false},
		{"bond0.200", []string{"bond0.200", "bond0", "eth3", "eth4"}, false},
		{"br1", []string{"br1", "eth5.300", "eth5"}, true},
		{"br1.7", []string{"br1.7", "br1", "eth5.300", "eth5"}, true},
		// A port or a lower interface on its own: the bridge above it is not on the way.
		{"eth1", []string{"eth1"}, false},
		{"eth5", []string{"eth5"}, false},
		{"eth5.300", []string{"eth5.300", "eth5"}, false},
		// An interface the snapshot does not have is still the one the packet is on.
		{"ghost0", []string{"ghost0"}, false},
		{"", nil, false},
		{"loop0", []string{"loop0", "loop1"}, false},
	} {
		got := e.stack(c.name)
		if !slices.Equal(got, c.want) {
			t.Errorf("stack(%q) = %q, want %q", c.name, got, c.want)
		}
		if b := e.bridged(got); b != c.bridged {
			t.Errorf("bridged(%q) = %v, want %v", got, b, c.bridged)
		}
	}
	if e.bridged([]string{"eth0", "eth0.100", "bond0"}) || !e.bridged([]string{"eth0", "br1"}) {
		t.Error("bridged is true when one of the interfaces is a bridge, and only then")
	}
}

// layered is machine with the three kinds of interface that have others underneath: a bridge
// over two ports, a bond over two members and a VLAN on eth0, each with a network of its own.
func layered(ls ...host.Listener) *host.Host {
	h := machine(ls...)
	h.Interfaces = append(h.Interfaces,
		host.Interface{Name: "br0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{pfx("192.0.2.1/26")}},
		host.Interface{Name: "eth1", Up: true, Master: "br0"},
		host.Interface{Name: "eth2", Up: true, Master: "br0"},
		host.Interface{Name: "bond0", Up: true, Kind: "bond", Addrs: []netip.Prefix{pfx("192.0.2.65/26")}},
		host.Interface{Name: "eth3", Up: true, Master: "bond0"},
		host.Interface{Name: "eth4", Up: true, Master: "bond0"},
		host.Interface{Name: "eth0.100", Up: true, Kind: "vlan", Lower: "eth0", Addrs: []netip.Prefix{pfx("192.0.2.129/26")}},
	)
	h.Routes = append(h.Routes,
		host.Route{Dst: pfx("192.0.2.0/26"), Dev: "br0"},
		host.Route{Dst: pfx("192.0.2.64/26"), Dev: "bond0"},
		host.Route{Dst: pfx("192.0.2.128/26"), Dev: "eth0.100"},
	)
	return h
}

// TestWalkedChainUnderneath: an ingress chain is walked for a packet that arrives on its own
// interface. For a packet that arrives on the bridge, bond or VLAN above, the chain ran one layer
// down, where the engine does not follow: the chain is not walked, and its Unfollowed entry
// (Walked) leaves the packet undecided.
func TestWalkedChainUnderneath(t *testing.T) {
	const why = "the chain ingress of table netdev early acts on packets as they pass its interface, underneath the bridge, bond or VLAN interface they arrive on, where seaward does not follow them"
	h := layered(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"))
	for _, c := range []struct {
		name         string
		upper, lower string
		src, dst     string // a packet that arrives on upper
	}{
		{"a port of a bridge", "br0", "eth2", "192.0.2.50", "192.0.2.1"},
		{"a member of a bond", "bond0", "eth3", "192.0.2.100", "192.0.2.65"},
		{"the interface a VLAN sits on", "eth0.100", "eth0", "192.0.2.150", "192.0.2.129"},
	} {
		for _, onlyStops := range []bool{true, false} {
			// The chain as the nft reader hands it over: a base chain of its table, and an entry.
			rs := ruleset(tbl("netdev", "early", ingress("ingress", -500, rules.Accept, []string{c.lower},
				rule("tcp dport 80 drop", tcp(), dport(80), v(rules.Drop)))))
			rs.Unfollowed = []rules.Unfollowed{{Why: why, In: []string{c.lower}, OnlyStops: onlyStops, Walked: true}}
			otherwise := Class(0)
			if onlyStops {
				otherwise = Open
			}
			for _, port := range []uint16{22, 80} {
				// On the interface above: the chain's drop of port 80 is not the engine's to
				// apply, and nothing is decided.
				r := Run(rs, h, probe(c.src, c.dst, port))
				hangs(t, c.name+", from above", r, otherwise, []Class{Open, Filtered}, why)
				if n := hookSteps(r, rules.HookIngress); n != 0 {
					t.Errorf("%s: the chain was walked for a packet that arrives on %s:\n%s", c.name, c.upper, trace(r))
				}
			}
			// On the chain's own interface: it is walked, and the entry has no say.
			decided(t, c.name+", port 22 on the interface itself", Run(rs, h, on(c.lower, c.src, c.dst, 22)), Open)
			r := Run(rs, h, on(c.lower, c.src, c.dst, 80))
			decided(t, c.name+", port 80 on the interface itself", r, Filtered)
			if d := decisive(t, r); d.Hook != rules.HookIngress || d.Table != "early" {
				t.Errorf("%s: decisive %+v", c.name, d)
			}
			// Somewhere else altogether.
			decided(t, c.name+", on docker0", Run(rs, h, on("docker0", world, me, 80)), Open)

			// A chain on the interface above is walked there like any other, and that is all it
			// does: what is underneath that interface is not underneath the chain.
			top := ruleset(tbl("netdev", "early", ingress("ingress", -500, rules.Accept, []string{c.upper},
				rule("tcp dport 80 drop", tcp(), dport(80), v(rules.Drop)))))
			top.Unfollowed = []rules.Unfollowed{{Why: why, In: []string{c.upper}, OnlyStops: onlyStops, Walked: true}}
			decided(t, c.name+", a chain on the interface above, port 22", Run(top, h, probe(c.src, c.dst, 22)), Open)
			decided(t, c.name+", a chain on the interface above, port 80", Run(top, h, probe(c.src, c.dst, 80)), Filtered)
		}
	}

	// A chain attached by a name pattern may be both: walked where the packet arrives, and run
	// once more underneath. What it drops where it is walked is dropped; the rest hangs on it.
	rs := ruleset(tbl("netdev", "early", ingress("ingress", -500, rules.Accept, []string{"eth*"},
		rule("tcp dport 80 drop", tcp(), dport(80), v(rules.Drop)))))
	rs.Unfollowed = []rules.Unfollowed{{Why: why, In: []string{"eth*"}, OnlyStops: true, Walked: true}}
	decided(t, "eth*, port 80 on the VLAN", Run(rs, h, probe("192.0.2.150", "192.0.2.129", 80)), Filtered)
	hangs(t, "eth*, port 22 on the VLAN", Run(rs, h, probe("192.0.2.150", "192.0.2.129", 22)), Open, []Class{Open, Filtered}, why)
	decided(t, "eth*, port 22 on eth0", Run(rs, h, probe(world, me, 22)), Open)
	// The bridge's ports match the pattern, the bridge does not: unseen underneath only.
	hangs(t, "eth*, port 80 on the bridge", Run(rs, h, probe("192.0.2.50", "192.0.2.1", 80)), Open, []Class{Open, Filtered}, why)
}

// TestUnfollowedOnTheWayIn: a chain outside the walked path has a say about the packets that
// arrive on its interfaces, or on something above them, and about no others.
func TestUnfollowedOnTheWayIn(t *testing.T) {
	const why = "the chain odd of table netdev nd hooks in at input, a point of the packet path seaward does not know"
	h := layered(lis("0.0.0.0", 80, "nginx"))
	for _, c := range []struct {
		in                 []string
		eth0, bridge, vlan bool // whether a packet that arrives there passes the chain
	}{
		{[]string{"eth0"}, true, false, true},
		{[]string{"eth1"}, false, true, false},
		{[]string{"br0"}, false, true, false},
		{[]string{"eth0.100"}, false, false, true},
		{[]string{"eth9", "eth2"}, false, true, false},
		{[]string{"eth*"}, true, true, true},
		{[]string{"br*"}, false, true, false},
		{[]string{"*"}, true, true, true},
		{[]string{"wg0"}, false, false, false},
		{nil, false, false, false},
	} {
		rs := ruleset()
		rs.Unfollowed = []rules.Unfollowed{{Why: why, In: c.in}}
		for _, p := range []struct {
			where  string
			pr     Probe
			passes bool
		}{
			{"eth0", probe(world, me, 80), c.eth0},
			{"the bridge", probe("192.0.2.50", "192.0.2.1", 80), c.bridge},
			{"the VLAN", probe("192.0.2.150", "192.0.2.129", 80), c.vlan},
			// The interface a probe names is the one that counts, not the one a route would pick.
			{"eth0, named", on("eth0", "192.0.2.50", me, 80), c.eth0},
			{"the bridge, named", on("br0", world, me, 80), c.bridge},
		} {
			r := Run(rs, h, p.pr)
			what := strings.Join(c.in, ",") + ", a packet on " + p.where
			if p.passes {
				hangs(t, what, r, 0, []Class{Open, Filtered}, why)
			} else {
				decided(t, what, r, Open)
			}
		}
	}
}

// TestChainOnAnInterfaceNobodyNames: the JSON listing of an older nft does not say which
// interface an ingress or egress chain is attached to. Such a chain is not attached to nothing.
// It may be on any interface, so every packet that arrives may pass it, and every packet that is
// sent on may pass one on the way out. The answer is "not decided" with the chain named, never
// the answer of the rules that were walked alone: that would call a port open that the chain
// drops, which is what the engine did while the reader took such a chain for an idle one.
func TestChainOnAnInterfaceNobodyNames(t *testing.T) {
	const (
		in  = "the chain ingress of table netdev early acts on packets as they arrive on an interface the snapshot does not name"
		out = "the chain out of table netdev late acts on packets as they leave through an interface the snapshot does not name"
	)
	h := twoArmed(lis("0.0.0.0", 22, "sshd"))
	arriving := func(onlyStops bool) *rules.Ruleset {
		rs := outcomes()
		rs.Unfollowed = []rules.Unfollowed{{Why: in, In: []string{"*"}, OnlyStops: onlyStops}}
		return rs
	}
	for _, c := range []struct {
		port uint16
		walk Class
	}{{22, Open}, {81, Closed}, {9100, Rejected}, {25, Filtered}, {3389, Forwarded}} {
		for _, where := range []Probe{probe(world, me, c.port), on("eth1", "192.0.2.50", "192.0.2.1", c.port)} {
			what := fmt.Sprintf("port %d arriving on %s", c.port, where.Iif)
			if where.Iif == "" {
				what = fmt.Sprintf("port %d from the internet", c.port)
			}
			decidedAlone := Run(outcomes(), h, where)
			// A chain that may do anything: nothing is decided, on either interface.
			r := Run(arriving(false), h, where)
			if r.Class != Undecided || !slices.Equal(r.Unknowns, []string{in}) {
				t.Errorf("%s, a chain that may do anything: %v, hanging on %q; want it not decided", what, r.Class, r.Unknowns)
			}
			// A chain that can only stop packets: what the walked rules already stop is stopped,
			// and everything else is still not decided, with what the walk said kept beside it.
			r = Run(arriving(true), h, where)
			switch {
			case decidedAlone.Class == Filtered:
				decided(t, what+", a chain that can only stop it", r, Filtered)
			case r.Class != Undecided || r.Otherwise != decidedAlone.Class || !slices.Equal(r.Unknowns, []string{in}):
				t.Errorf("%s, a chain that can only stop it: %v, otherwise %v, hanging on %q; want not decided, otherwise %v",
					what, r.Class, r.Otherwise, r.Unknowns, decidedAlone.Class)
			}
			if r.Class == Open || r.Class == Forwarded {
				t.Errorf("%s is called %v although a chain on an interface nobody names may drop it", what, r.Class)
			}
		}
	}

	// An egress chain nobody places: a packet the machine sends on may pass it, whichever way it
	// leaves; a packet that stays on the machine leaves through nothing.
	leaving := outcomes()
	leaving.Unfollowed = []rules.Unfollowed{{Why: out, Out: []string{"*"}}}
	if r := Run(leaving, h, probe(world, me, 3389)); r.Class != Undecided || !slices.Equal(r.Unknowns, []string{out}) {
		t.Errorf("a packet sent on: %v, hanging on %q; want it not decided", r.Class, r.Unknowns)
	}
	decided(t, "a packet for this machine, an egress chain nobody places", Run(leaving, h, probe(world, me, 22)), Open)
}

// TestUnknownArrivalInterface: with no route back to the sender and no interface named, where
// the packet arrives is not known. Every chain on some way in may then be on its way, and none
// on a way out is: a packet that arrives nowhere is not sent on.
func TestUnknownArrivalInterface(t *testing.T) {
	h := layered(lis("0.0.0.0", 80, "nginx"))
	h.Routes = []host.Route{{Dst: pfx("203.0.113.0/24"), Dev: "eth0"}} // the world is not on the map
	rs := ruleset()
	rs.Unfollowed = []rules.Unfollowed{
		{Why: "a chain on eth3's way in", In: []string{"eth3"}},
		{Why: "a chain on eth0's way out", Out: []string{"eth0"}},
		{Why: "an ingress chain on eth1", In: []string{"eth1"}, Walked: true},
		{Why: "a bridge chain on the way out", BridgeOut: true},
		{Why: "a bridge chain on the way in", BridgeIn: true},
	}
	r := Run(rs, h, probe(world, me, 80))
	want(t, r, Undecided)
	if len(r.Unknowns) != 4 || !strings.Contains(r.Unknowns[0], "no route to "+world) ||
		!slices.Equal(r.Unknowns[1:], []string{"a chain on eth3's way in", "an ingress chain on eth1", "a bridge chain on the way in"}) {
		t.Errorf("unknowns: %q", r.Unknowns)
	}
	if r.Otherwise != 0 {
		t.Errorf("otherwise %v for a walk that never began", r.Otherwise)
	}
	// Named, the interface settles it: none of these chains is on eth0's way in ...
	decided(t, "on eth0", Run(rs, h, on("eth0", world, me, 80)), Open)
	// ... and the two under or on the bridge are on the bridge's.
	hangs(t, "on br0", Run(rs, h, on("br0", world, me, 80)), 0, []Class{Open, Filtered}, "an ingress chain on eth1", "a bridge chain on the way in")
	// A sender the machine does have a route to needs no name.
	decided(t, "from the local network", Run(rs, h, probe("203.0.113.77", me, 80)), Open)
}

// TestOutIsWhereAForwardedPacketLeaves: Result.Out names the interface a packet the machine
// sends on leaves through, and is empty for one that stays.
func TestOutIsWhereAForwardedPacketLeaves(t *testing.T) {
	// Into a container, and to the machine itself.
	h := withContainer(machine(lis("0.0.0.0", 22, "sshd")), lis("0.0.0.0", 80, "nginx"))
	r := Run(dockerRules(), h, probe(world, me, 8080))
	want(t, r, Open)
	if r.Out != "docker0" {
		t.Errorf("a packet for the container leaves through %q, want docker0", r.Out)
	}
	r = Run(dockerRules(), h, probe(world, me, 22))
	want(t, r, Open)
	if r.Out != "" {
		t.Errorf("a packet for this machine leaves through %q", r.Out)
	}
	if r = Run(nil, h, probe(world, me, 81)); r.Class != Closed || r.Out != "" {
		t.Errorf("no rules: %v, leaves through %q", r.Class, r.Out)
	}

	// On to another machine.
	g := twoArmed()
	dnat := rule("-A PREROUTING -p tcp --dport 3389 -j DNAT --to-destination 192.0.2.50", tcp(), dport(3389), &rules.DNAT{Addr: ip(inside)})
	r = Run(ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept, dnat))), g, probe(world, me, 3389))
	want(t, r, Forwarded)
	if r.Out != "eth1" {
		t.Errorf("a packet for the inner network leaves through %q, want eth1", r.Out)
	}

	// Undecided between staying and leaving: the way out is kept, though the first way through
	// (the unknown condition holds, the packet is accepted as it is) never leaves.
	u := &rules.Unknown{Why: "the geoip match cannot be evaluated"}
	r = Run(ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -m geoip --src-cc XX -j ACCEPT", u, v(rules.Accept)), dnat))), g, probe(world, me, 3389))
	want(t, r, Undecided)
	if r.Out != "eth1" || !slices.Equal(r.Possible, []Class{Closed, Forwarded}) {
		t.Errorf("undecided, staying first: leaves through %q, one of %v", r.Out, r.Possible)
	}
	// The other way round as well: the first way through leaves and the last one stays.
	r = Run(ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -m geoip --src-cc XX -p tcp --dport 3389 -j DNAT --to-destination 192.0.2.50", u, tcp(), dport(3389), &rules.DNAT{Addr: ip(inside)})))),
		g, probe(world, me, 3389))
	want(t, r, Undecided)
	if r.Out != "eth1" || !slices.Equal(r.Possible, []Class{Closed, Forwarded}) {
		t.Errorf("undecided, leaving first: leaves through %q, one of %v", r.Out, r.Possible)
	}
}

// TestUnfollowedOnTheWayOut: a chain on the way out has a say about a packet the machine sends
// on through its interface, or through something above it. Not about one that stays, and not
// about one the walked rules stop: that one never gets as far.
func TestUnfollowedOnTheWayOut(t *testing.T) {
	const why = "the chain out of table netdev nd acts on packets as they leave through its interface, after the packet path seaward follows"
	h := withContainer(machine(lis("0.0.0.0", 22, "sshd")), lis("0.0.0.0", 80, "nginx"))
	h.Interfaces = append(h.Interfaces, host.Interface{Name: "veth1", Up: true, Kind: "veth", Master: "docker0"})
	container := h.Docker.Containers[0].Networks[0].Addr
	for _, c := range []struct {
		out    []string
		passes bool // a packet sent on into the container
	}{
		{[]string{"docker0"}, true},
		{[]string{"veth1"}, true}, // a port of the bridge it leaves through
		{[]string{"veth*"}, true},
		{[]string{"eth1", "docker0"}, true},
		{[]string{"eth0"}, false}, // where it came in is not where it leaves
		{[]string{"eth1"}, false},
		{nil, false},
	} {
		rs := dockerRules()
		rs.Unfollowed = []rules.Unfollowed{{Why: why, Out: c.out}}
		what := strings.Join(c.out, ",")
		r := Run(rs, h, probe(world, me, 8080))
		if c.passes {
			hangs(t, what+", into the container", r, 0, []Class{Open, Filtered}, why)
		} else {
			decided(t, what+", into the container", r, Open)
		}
		// Delivered here: it never leaves.
		decided(t, what+", for this machine", Run(rs, h, probe(world, me, 22)), Open)
		// Dropped by the input policy, and dropped by Docker's own rule in the forward chain
		// with the way out already picked: neither gets as far as the chain.
		decided(t, what+", dropped on input", Run(rs, h, probe(world, me, 8081)), Filtered)
		r = Run(rs, h, Probe{Src: ip(world), Dst: container, Proto: "tcp", Dport: 81})
		decided(t, what+", dropped on forward", r, Filtered)
		if d := decisive(t, r); d.Hook != rules.HookForward {
			t.Errorf("%s: the packet for the container was not stopped in the forward chain: %+v", what, d)
		}
	}
}

// TestBridgedTraffic: a chain of a bridge table sees what arrives through a bridge (BridgeIn) or
// leaves through one (BridgeOut), whichever bridge it is, and nothing that passes no bridge.
func TestBridgedTraffic(t *testing.T) {
	const why = "the chain c of table bridge br acts on frames as they pass a bridge"
	// docker0 is a bridge the machine sends packets out through; br0 one it receives them on,
	// with a VLAN on top.
	h := withContainer(layered(lis("0.0.0.0", 22, "sshd")), lis("0.0.0.0", 80, "nginx"))
	h.Interfaces = append(h.Interfaces, host.Interface{Name: "br0.7", Up: true, Kind: "vlan", Lower: "br0", Addrs: []netip.Prefix{pfx("192.0.2.193/26")}})
	h.Routes = append(h.Routes, host.Route{Dst: pfx("192.0.2.192/26"), Dev: "br0.7"})
	for _, c := range []struct {
		name          string
		u             rules.Unfollowed
		arrives, left bool // through a bridge
	}{
		{"prerouting", rules.Unfollowed{Why: why, BridgeIn: true}, true, false},
		{"output", rules.Unfollowed{Why: why, BridgeOut: true}, false, true},
		{"a hook nobody knows", rules.Unfollowed{Why: why, BridgeIn: true, BridgeOut: true}, true, true},
	} {
		rs := dockerRules()
		rs.Unfollowed = []rules.Unfollowed{c.u}
		for _, p := range []struct {
			where  string
			pr     Probe
			passes bool
		}{
			{"in on eth0, for this machine", probe(world, me, 22), false},
			{"in on the bond, for this machine", probe("192.0.2.100", "192.0.2.65", 22), false},
			{"in on the bridge, for this machine", probe("192.0.2.50", "192.0.2.1", 22), c.arrives},
			{"in on a VLAN on the bridge, for this machine", probe("192.0.2.200", "192.0.2.193", 22), c.arrives},
			{"in on eth0, out to the container", probe(world, me, 8080), c.left},
			{"in on the bridge, out to the container", probe("192.0.2.50", me, 8080), c.arrives || c.left},
		} {
			r := Run(rs, h, p.pr)
			if p.passes {
				hangs(t, c.name+": "+p.where, r, 0, []Class{Open, Filtered}, why)
			} else {
				decided(t, c.name+": "+p.where, r, Open)
			}
		}
	}

	// Sent on through an interface that is no bridge: a bridge chain on the way out has no say.
	g := twoArmed()
	rs := ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -p tcp --dport 3389 -j DNAT --to-destination 192.0.2.50", tcp(), dport(3389), &rules.DNAT{Addr: ip(inside)}))))
	rs.Unfollowed = []rules.Unfollowed{{Why: why, BridgeOut: true}}
	decided(t, "out through eth1", Run(rs, g, probe(world, me, 3389)), Forwarded)
}

// outcomes is a ruleset that ends a packet in each of the five ways, by port: 22 open (twoArmed
// listens there), 81 closed, 9100 rejected, 25 filtered, 3389 forwarded to the inner network.
func outcomes() *rules.Ruleset {
	return ruleset(
		tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
			rule("-A PREROUTING -p tcp --dport 3389 -j DNAT --to-destination 192.0.2.50", tcp(), dport(3389), &rules.DNAT{Addr: ip(inside)}))),
		inputTable(rules.Accept,
			rule("-A INPUT -p tcp --dport 25 -j DROP", tcp(), dport(25), v(rules.Drop)),
			rule("-A INPUT -p tcp --dport 9100 -j REJECT", tcp(), dport(9100), v(rules.Reject))),
	)
}

// TestOnlyStopsLeavesTheWalkStanding: what a packet that passes an unfollowed chain comes to,
// for every way the walked rules can end it.
//
// A chain that may do anything decides nothing: a packet the rules stop may have been sent
// somewhere else first, one they let through may be stopped. A chain that can only stop packets
// (OnlyStops) leaves more standing: a packet the rules drop is dropped either way and stays
// decided; any other is either dropped by the chain or ends the way the walk says, which
// Otherwise keeps.
func TestOnlyStopsLeavesTheWalkStanding(t *testing.T) {
	const why = "the chain c of table ip t hooks in at zz, a point of the packet path seaward does not know"
	h := twoArmed(lis("0.0.0.0", 22, "sshd"))
	with := func(rs *rules.Ruleset, onlyStops bool) *rules.Ruleset {
		rs.Unfollowed = []rules.Unfollowed{{Why: why, In: []string{"eth0"}, OnlyStops: onlyStops}}
		return rs
	}
	for _, c := range []struct {
		port     uint16
		walk     Class   // what the walked rules say
		anything []Class // Possible with a chain that may do anything
		stops    []Class // Possible with a chain that can only stop the packet
	}{
		{22, Open, []Class{Open, Filtered}, []Class{Open, Filtered}},
		{81, Closed, []Class{Closed, Filtered}, []Class{Closed, Filtered}},
		{9100, Rejected, []Class{Open, Rejected}, []Class{Rejected, Filtered}},
		{25, Filtered, []Class{Open, Filtered}, nil},
		{3389, Forwarded, []Class{Forwarded, Filtered}, []Class{Forwarded, Filtered}},
	} {
		pr := probe(world, me, c.port)
		what := c.walk.String()
		plain := Run(outcomes(), h, pr)
		decided(t, what+", no chain", plain, c.walk)

		r := Run(with(outcomes(), false), h, pr)
		hangs(t, what+", a chain that may do anything", r, 0, c.anything, why)

		s := Run(with(outcomes(), true), h, pr)
		if c.walk == Filtered {
			decided(t, what+", a chain that can only stop it", s, Filtered)
		} else {
			hangs(t, what+", a chain that can only stop it", s, c.walk, c.stops, why)
		}
		// Either way the result still tells the walk: its steps, where the packet ended up and
		// the program that would get it.
		for _, got := range []Result{r, s} {
			if len(got.Steps) != len(plain.Steps) || got.FinalDst != plain.FinalDst || got.FinalPort != plain.FinalPort ||
				got.Rewritten != plain.Rewritten || got.Out != plain.Out || got.Listener != plain.Listener {
				t.Errorf("%s: the walk was not kept:\n%s", what, trace(got))
			}
		}
		// A chain the packet does not pass changes nothing, whatever it can do.
		elsewhere := outcomes()
		elsewhere.Unfollowed = []rules.Unfollowed{{Why: why, In: []string{"eth1"}}, {Why: why, Out: []string{"eth0"}}, {Why: why, BridgeIn: true, BridgeOut: true}}
		decided(t, what+", chains elsewhere", Run(elsewhere, h, pr), c.walk)
	}

	// A walk that is itself undecided stays so, with its own reasons first. A chain that can only
	// stop the packet adds "filtered" to the ways it can end, in its place among them.
	u := &rules.Unknown{Why: "the geoip match cannot be evaluated"}
	undecided := func(what rules.Expr) *rules.Ruleset {
		return ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
			rule("-A PREROUTING -m geoip --src-cc XX -p tcp --dport 3389 -j DNAT --to-destination 192.0.2.50", u, tcp(), dport(3389), &rules.DNAT{Addr: ip(inside)}))),
			inputTable(rules.Accept, rule("-A INPUT -m geoip --src-cc XX -p tcp --dport 22", u, tcp(), dport(22), what)))
	}
	for _, c := range []struct {
		name  string
		rs    func() *rules.Ruleset
		port  uint16
		walk  []Class // Possible without any chain, and with one that may do anything
		stops []Class // with one that can only stop the packet
	}{
		{"dropped or open", func() *rules.Ruleset { return undecided(v(rules.Drop)) }, 22, []Class{Open, Filtered}, []Class{Open, Filtered}},
		{"rejected or open", func() *rules.Ruleset { return undecided(v(rules.Reject)) }, 22, []Class{Open, Rejected}, []Class{Open, Rejected, Filtered}},
		{"forwarded or closed", func() *rules.Ruleset { return undecided(v(rules.Drop)) }, 3389, []Class{Closed, Forwarded}, []Class{Closed, Filtered, Forwarded}},
	} {
		pr := probe(world, me, c.port)
		hangs(t, c.name+", no chain", Run(c.rs(), h, pr), 0, c.walk, u.Why)
		hangs(t, c.name+", a chain that may do anything", Run(with(c.rs(), false), h, pr), 0, c.walk, u.Why, why)
		hangs(t, c.name+", a chain that can only stop it", Run(with(c.rs(), true), h, pr), 0, c.stops, u.Why, why)
	}

	// A walk that came to its answer past something it could not decide keeps saying so, after
	// the chain: what was not seen is the reason there is no answer, and it leads.
	sure := func() *rules.Ruleset {
		return ruleset(inputTable(rules.Accept, rule("-A INPUT -m geoip --src-cc XX -j ACCEPT", u, v(rules.Accept))))
	}
	pr := probe(world, me, 22)
	if r := Run(sure(), h, pr); r.Class != Open || !slices.Equal(r.Unknowns, []string{u.Why}) {
		t.Errorf("open past an unknown: %v, hanging on %q", r.Class, r.Unknowns)
	}
	hangs(t, "open past an unknown, a chain that may do anything", Run(with(sure(), false), h, pr), 0, []Class{Open, Filtered}, why, u.Why)
	hangs(t, "open past an unknown, a chain that can only stop it", Run(with(sure(), true), h, pr), Open, []Class{Open, Filtered}, why, u.Why)
}

// TestTheStrongerReasonWins: a packet may pass several things that were not seen. Each is named,
// in the order rules that could not be read, then chains as the ruleset lists them. What still
// stands is what the strongest of them leaves: Otherwise is kept only when every one of them can
// do no more than stop the packet.
func TestTheStrongerReasonWins(t *testing.T) {
	const (
		weak   = "the chain guard of table netdev nd hooks in at input, a point of the packet path seaward does not know"
		weak2  = "the chain pre of table bridge br acts on frames as they arrive through a bridge, before the packet path seaward follows"
		strong = "the chain mangle of table netdev nd hooks in at input, a point of the packet path seaward does not know"
		unread = "The nftables rules could not be read: nft needs root."
	)
	h := layered(lis("0.0.0.0", 22, "sshd"))
	stops := rules.Unfollowed{Why: weak, In: []string{"eth1"}, OnlyStops: true}
	stops2 := rules.Unfollowed{Why: weak2, BridgeIn: true, OnlyStops: true}
	acts := rules.Unfollowed{Why: strong, In: []string{"br0"}}
	open, dropped := probe("192.0.2.50", "192.0.2.1", 22), probe("192.0.2.50", "192.0.2.1", 25) // both arrive on br0, over eth1 or eth2
	run := func(pr Probe, unread []rules.Unread, us ...rules.Unfollowed) Result {
		rs := ruleset(inputTable(rules.Accept, rule("-A INPUT -p tcp --dport 25 -j DROP", tcp(), dport(25), v(rules.Drop))))
		rs.Unread, rs.Unfollowed = unread, us
		return Run(rs, h, pr)
	}
	either := []Class{Open, Filtered}

	// Chains that can only stop the packet, one or several: the walk stands as far as it can.
	hangs(t, "one weak, open", run(open, nil, stops), Open, either, weak)
	decided(t, "one weak, dropped", run(dropped, nil, stops), Filtered)
	hangs(t, "two weak, open", run(open, nil, stops, stops2), Open, either, weak, weak2)
	decided(t, "two weak, dropped", run(dropped, nil, stops2, stops), Filtered)

	// One chain that may do anything among them: nothing stands, wherever it is listed.
	hangs(t, "weak then strong, open", run(open, nil, stops, acts), 0, either, weak, strong)
	hangs(t, "strong then weak, open", run(open, nil, acts, stops), 0, either, strong, weak)
	hangs(t, "strong between weak, open", run(open, nil, stops, acts, stops2), 0, either, weak, strong, weak2)
	hangs(t, "weak then strong, dropped", run(dropped, nil, stops, acts), 0, either, weak, strong)
	hangs(t, "strong then weak, dropped", run(dropped, nil, acts, stops), 0, either, strong, weak)

	// A strong chain the packet does not pass takes nothing away.
	elsewhere := rules.Unfollowed{Why: strong, In: []string{"eth0"}}
	hangs(t, "weak, strong elsewhere, open", run(open, nil, stops, elsewhere), Open, either, weak)
	decided(t, "weak, strong elsewhere, dropped", run(dropped, nil, elsewhere, stops), Filtered)

	// Rules nobody read may do anything too, and are named first.
	all := []rules.Unread{{Why: unread}}
	hangs(t, "unread and weak, open", run(open, all, stops), 0, either, unread, weak)
	hangs(t, "unread and weak, dropped", run(dropped, all, stops), 0, either, unread, weak)
	// Unless they are the other family's.
	six := []rules.Unread{{Family: "ip6", Why: unread}}
	hangs(t, "IPv6 unread and weak, open", run(open, six, stops), Open, either, weak)
	decided(t, "IPv6 unread and weak, dropped", run(dropped, six, stops), Filtered)
}

// TestPossibleStaysEmptyWhenTheWalkStopped: Possible lists the ways an undecided packet can end.
// A walk that stopped at something the model does not follow knows no such list, and a chain that
// can only stop the packet must not turn that into "it can only end filtered". The same holds
// when some ways through ended and one did not: a list short of an end nobody knows is no list.
func TestPossibleStaysEmptyWhenTheWalkStopped(t *testing.T) {
	const chain = "a chain on eth0"
	st := &rules.UnknownStmt{Why: "the TPROXY target is not modelled"}
	u := &rules.Unknown{Why: "the geoip match cannot be evaluated"}
	h := machine(lis("0.0.0.0", 80, "nginx"))
	pr := probe(world, me, 80)
	with := func(rs *rules.Ruleset, us ...rules.Unfollowed) *rules.Ruleset {
		rs.Unfollowed = us
		return rs
	}
	stops := rules.Unfollowed{Why: chain, In: []string{"eth0"}, OnlyStops: true}
	acts := rules.Unfollowed{Why: chain, In: []string{"eth0"}}

	// Every way through stops at the statement.
	stopped := func() *rules.Ruleset {
		return ruleset(inputTable(rules.Accept, rule("-A INPUT -p tcp --dport 80 -j TPROXY", tcp(), dport(80), st)))
	}
	hangs(t, "stopped, no chain", Run(stopped(), h, pr), 0, nil, st.Why)
	r := Run(with(stopped(), stops), h, pr)
	if len(r.Possible) != 0 {
		t.Errorf("a walk that stopped, past a chain that can only stop the packet: one of %v, want no list at all", r.Possible)
	}
	hangs(t, "stopped, a chain that can only stop it", r, 0, nil, st.Why, chain)
	hangs(t, "stopped, a chain that may do anything", Run(with(stopped(), acts), h, pr), 0, nil, st.Why, chain)

	// One way through stops at the statement, the other is taken by nginx.
	mixed := func() *rules.Ruleset {
		return ruleset(inputTable(rules.Accept, rule("-A INPUT -m geoip --src-cc XX -p tcp --dport 80 -j TPROXY", u, tcp(), dport(80), st)))
	}
	hangs(t, "one way through stopped, no chain", Run(mixed(), h, pr), 0, nil, u.Why, st.Why)
	hangs(t, "one way through stopped, a chain that can only stop it", Run(with(mixed(), stops), h, pr), 0, nil, u.Why, st.Why, chain)
	hangs(t, "one way through stopped, a chain that may do anything", Run(with(mixed(), acts), h, pr), 0, nil, u.Why, st.Why, chain)

	// Every way through followed to its end: the list is whole, and the chain adds its own end.
	whole := func() *rules.Ruleset {
		return ruleset(inputTable(rules.Accept, rule("-A INPUT -m geoip --src-cc XX -p tcp --dport 80 -j REJECT", u, tcp(), dport(80), v(rules.Reject))))
	}
	hangs(t, "every way through ended, no chain", Run(whole(), h, pr), 0, []Class{Open, Rejected}, u.Why)
	hangs(t, "every way through ended, a chain that can only stop it", Run(with(whole(), stops), h, pr), 0, []Class{Open, Rejected, Filtered}, u.Why, chain)

	// More conditions than the model follows: the ways it did not follow have ends nobody saw.
	var many []*rules.Rule
	for i := 0; i < 200; i++ {
		many = append(many, rule("-A INPUT -m something", &rules.Unknown{Why: "something"}, &rules.Noop{What: "count"}))
	}
	r = Run(with(ruleset(inputTable(rules.Accept, many...)), stops), h, pr)
	if r.Class != Undecided || len(r.Possible) != 0 || !slices.Contains(r.Unknowns, chain) {
		t.Errorf("too many conditions to follow: %v, one of %v, hanging on %q", r.Class, r.Possible, r.Unknowns)
	}
}

// TestEveryWayOutIsChecked: when a condition nobody can decide sends a packet one of two ways,
// and the two leave the machine by different interfaces, a chain on either way out is on the
// packet's way. A way the walked rules stop before it leaves is none.
func TestEveryWayOutIsChecked(t *testing.T) {
	const (
		egress1 = "an egress chain on eth1"
		egress0 = "an egress chain on docker0"
	)
	u := &rules.Unknown{Why: "the geoip match cannot be evaluated"}
	h := withContainer(twoArmed(lis("0.0.0.0", 22, "sshd")), lis("0.0.0.0", 80, "nginx"))
	// Port 8080 goes into the container for some senders and on to the inner network for the rest.
	nat := func() *rules.Table {
		return tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
			rule("-A PREROUTING -m geoip --src-cc XX -p tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80",
				u, tcp(), dport(8080), &rules.DNAT{Addr: ip("172.17.0.2"), Port: 80}),
			rule("-A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.0.2.50", tcp(), dport(8080), &rules.DNAT{Addr: ip(inside)})))
	}
	pr := probe(world, me, 8080)
	rs := ruleset(nat())
	r := Run(rs, h, pr)
	hangs(t, "no chain", r, 0, []Class{Open, Forwarded}, u.Why)
	if r.Out != "docker0" {
		t.Errorf("the first way through leaves by %q, want docker0", r.Out)
	}

	// The chain sits on the second way out.
	rs.Unfollowed = []rules.Unfollowed{{Why: egress1, Out: []string{"eth1"}, OnlyStops: true}}
	r = Run(rs, h, pr)
	if !slices.Contains(r.Unknowns, egress1) {
		t.Errorf("a chain on the second way out is not named: hanging on %q", r.Unknowns)
	}
	if !slices.Contains(r.Possible, Filtered) {
		t.Errorf("a chain on the second way out may drop the packet: one of %v", r.Possible)
	}
	hangs(t, "a chain on the second way out", r, 0, []Class{Open, Filtered, Forwarded}, u.Why, egress1)

	// On the first, on both, and one that may do anything.
	rs.Unfollowed = []rules.Unfollowed{{Why: egress0, Out: []string{"docker0"}, OnlyStops: true}}
	hangs(t, "a chain on the first way out", Run(rs, h, pr), 0, []Class{Open, Filtered, Forwarded}, u.Why, egress0)
	rs.Unfollowed = []rules.Unfollowed{{Why: egress0, Out: []string{"docker0"}, OnlyStops: true}, {Why: egress1, Out: []string{"eth1"}}}
	hangs(t, "a chain on each way out", Run(rs, h, pr), 0, []Class{Open, Forwarded}, u.Why, egress0, egress1)
	// A chain on an interface neither way leaves by, or on the way in of one of them, has no say.
	rs.Unfollowed = []rules.Unfollowed{{Why: "elsewhere", Out: []string{"eth0"}}, {Why: "the way in", In: []string{"eth1"}}}
	hangs(t, "chains elsewhere", Run(rs, h, pr), 0, []Class{Open, Forwarded}, u.Why)

	// The forward chain drops what is bound for the inner network: that way never gets as far as
	// eth1, so a chain there is not on the packet's way; one on docker0 still is.
	stopped := ruleset(nat(), tbl("ip", "filter", base("FORWARD", rules.HookForward, "filter", 0, rules.Accept,
		rule("-A FORWARD -o eth1 -j DROP", oif("eth1"), v(rules.Drop)))))
	stopped.Unfollowed = []rules.Unfollowed{{Why: egress1, Out: []string{"eth1"}}}
	hangs(t, "a chain on a way out the rules stop first", Run(stopped, h, pr), 0, []Class{Open, Filtered}, u.Why)
	stopped.Unfollowed = []rules.Unfollowed{{Why: egress0, Out: []string{"docker0"}, OnlyStops: true}}
	hangs(t, "a chain on the way out that is left", Run(stopped, h, pr), 0, []Class{Open, Filtered}, u.Why, egress0)

	// The same when the way that leaves comes second and the first stays on this machine.
	stays := ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -m geoip --src-cc XX -j ACCEPT", u, v(rules.Accept)),
		rule("-A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 192.0.2.50", tcp(), dport(22), &rules.DNAT{Addr: ip(inside)}))))
	stays.Unfollowed = []rules.Unfollowed{{Why: egress1, Out: []string{"eth1"}, OnlyStops: true}}
	hangs(t, "staying first, leaving second", Run(stays, h, probe(world, me, 22)), 0, []Class{Open, Filtered, Forwarded}, u.Why, egress1)
}
