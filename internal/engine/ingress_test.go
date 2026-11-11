package engine

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// ingress is a base chain on the ingress hook of the interfaces named.
func ingress(name string, prio int, policy rules.VerdictKind, devs []string, rs ...*rules.Rule) *rules.Chain {
	c := base(name, rules.HookIngress, "filter", prio, policy, rs...)
	c.Devs = devs
	return c
}

// twoArmed is machine with a second interface, eth1, and an inner network behind it.
func twoArmed(ls ...host.Listener) *host.Host {
	h := machine(ls...)
	h.Interfaces = append(h.Interfaces, host.Interface{Name: "eth1", Up: true, Addrs: []netip.Prefix{pfx("192.0.2.1/24")}})
	h.Routes = append(h.Routes, host.Route{Dst: pfx("192.0.2.0/24"), Dev: "eth1"})
	return h
}

const (
	inside  = "192.0.2.50"     // a machine of the inner network: its packets arrive on eth1
	meInner = "192.0.2.1"      // this machine's address there
	world6  = "2001:db8:99::7" // somebody on the internet, over IPv6
	me6     = "2001:db8:1::10"
)

// on is a probe that says which interface it arrives on, whatever a route would say.
func on(dev, src, dst string, port uint16) Probe {
	return Probe{Iif: dev, Src: ip(src), Dst: ip(dst), Proto: "tcp", Dport: port}
}

// hookSteps counts the steps of a trace that a hook left.
func hookSteps(r Result, hook string) int {
	n := 0
	for _, s := range r.Steps {
		if s.Hook == hook {
			n++
		}
	}
	return n
}

// both is a program listening on a port over IPv4 and IPv6.
func both(port uint16, proc string) host.Listener {
	return host.Listener{Proto: "tcp", Addr: ip("::"), DualStack: true, Port: port, Process: proc}
}

// TestIngressChainIsWalked: a chain on the ingress hook of the interface a packet arrives on runs
// before every other chain, in a netdev table for IPv4 and IPv6 alike. What it drops is gone
// whatever the input chain allows, and what it accepts still has to pass the input chain. The
// kernel lab proves the same (scenario nft-netdev-ingress).
func TestIngressChainIsWalked(t *testing.T) {
	h := machine(both(22, "sshd"), both(80, "nginx"), both(443, "caddy"))
	rs := ruleset(
		// The input chain comes first in the ruleset: the hook decides the order, not the listing.
		tbl("inet", "filter", base("input", rules.HookInput, "filter", 0, rules.Drop,
			rule("tcp dport { 22, 80 } accept", tcp(), rules.Eq(rules.FDport, rules.Num(22), rules.Num(80)), v(rules.Accept)))),
		tbl("netdev", "early", ingress("ingress", -500, rules.Accept, []string{"eth0"},
			rule("tcp dport 80 drop", tcp(), dport(80), v(rules.Drop)),
			rule("tcp dport 443 accept", tcp(), dport(443), v(rules.Accept)))),
	)
	for _, from := range [][2]string{{world, me}, {world6, me6}} {
		src, dst := from[0], from[1]
		// Nothing in the ingress chain is about port 22, and an accept policy leaves no trace.
		r := Run(rs, h, probe(src, dst, 22))
		want(t, r, Open)
		if n := hookSteps(r, rules.HookIngress); n != 0 {
			t.Fatalf("from %s: %d steps on the ingress hook for a packet no rule of it matched:\n%s", src, n, trace(r))
		}
		// Dropped on arrival, though the input chain accepts the port.
		r = Run(rs, h, probe(src, dst, 80))
		want(t, r, Filtered)
		d := decisive(t, r)
		if d.Kind != StepRule || d.Hook != rules.HookIngress || d.Family != "netdev" || d.Table != "early" || d.Chain != "ingress" || d.Rule != "tcp dport 80 drop" {
			t.Fatalf("from %s: decisive %+v", src, d)
		}
		if len(r.Steps) != 1 {
			t.Fatalf("from %s: the walk went on after the drop:\n%s", src, trace(r))
		}
		// Accepted on arrival, and dropped by the input chain all the same.
		r = Run(rs, h, probe(src, dst, 443))
		want(t, r, Filtered)
		if d = decisive(t, r); d.Kind != StepPolicy || d.Hook != rules.HookInput || d.Chain != "input" {
			t.Fatalf("from %s: decisive %+v", src, d)
		}
		if s := r.Steps[0]; s.Hook != rules.HookIngress || s.Table != "early" || s.Effect != "accept" {
			t.Fatalf("from %s: the trace does not start with the accept on arrival:\n%s", src, trace(r))
		}
	}
}

// TestIngressRunsBeforeEverythingElse: the ingress hook comes before prerouting, so its rules see
// the packet as it was sent, and before connection tracking, so every packet reads as "ct state
// invalid" there and none as new (scenario nft-inet-ingress of the kernel lab).
func TestIngressRunsBeforeEverythingElse(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 9090, "metrics"))
	nat := tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-ports 80", tcp(), dport(8080), &rules.Redirect{Port: 80})))
	// A drop of the port the packet ends on does not see a packet that was sent to another port.
	rs := ruleset(nat, tbl("netdev", "early", ingress("ingress", -500, rules.Accept, []string{"eth0"},
		rule("tcp dport 80 drop", tcp(), dport(80), v(rules.Drop)))))
	r := Run(rs, h, probe(world, me, 8080))
	want(t, r, Open)
	if !r.Rewritten || r.FinalPort != 80 {
		t.Fatalf("redirect: %v %d", r.Rewritten, r.FinalPort)
	}
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	// A drop of the port it was sent to does, and nothing is rewritten after it.
	rs = ruleset(nat, tbl("netdev", "early", ingress("ingress", -500, rules.Accept, []string{"eth0"},
		rule("tcp dport 8080 drop", tcp(), dport(8080), v(rules.Drop)))))
	r = Run(rs, h, probe(world, me, 8080))
	want(t, r, Filtered)
	if r.Rewritten || r.FinalPort != 8080 {
		t.Fatalf("a packet dropped on arrival was rewritten: %v %d", r.Rewritten, r.FinalPort)
	}
	want(t, Run(rs, h, probe(world, me, 80)), Open)

	// Connection tracking has not seen the packet yet: it is new only once it is past the hook.
	rs = ruleset(
		tbl("inet", "early", ingress("ingress", -500, rules.Accept, []string{"eth0"},
			rule("ct state new tcp dport 22 drop", ctstate(rules.CtNew), tcp(), dport(22), v(rules.Drop)),
			rule("ct state invalid tcp dport 9090 drop", ctstate(rules.CtInvalid), tcp(), dport(9090), v(rules.Drop)))),
		tbl("inet", "filter", base("input", rules.HookInput, "filter", 0, rules.Drop,
			rule("ct state new accept", ctstate(rules.CtNew), v(rules.Accept)))),
	)
	want(t, Run(rs, h, probe(world, me, 22)), Open)
	want(t, Run(rs, h, probe(world, me, 80)), Open)
	r = Run(rs, h, probe(world, me, 9090))
	want(t, r, Filtered)
	if d := decisive(t, r); d.Hook != rules.HookIngress || !strings.Contains(d.Rule, "invalid") {
		t.Fatalf("decisive: %+v", d)
	}
}

// TestIngressPolicyAndReject: a policy of drop holds for what no rule of the ingress chain
// accepts, and a reject is answered from there (scenarios nft-inet-ingress and
// nft-netdev-ingress-drop).
func TestIngressPolicyAndReject(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 8080, "app"))
	rs := ruleset(tbl("inet", "early", ingress("ingress", -500, rules.Drop, []string{"eth0"},
		rule("tcp dport 8080 reject with tcp reset", tcp(), dport(8080), v(rules.Reject)),
		rule("tcp dport 22 accept", tcp(), dport(22), v(rules.Accept)))))
	want(t, Run(rs, h, probe(world, me, 22)), Open)
	r := Run(rs, h, probe(world, me, 8080))
	want(t, r, Rejected)
	if d := decisive(t, r); d.Kind != StepRule || d.Hook != rules.HookIngress || !strings.Contains(d.Rule, "reject") {
		t.Fatalf("decisive: %+v", d)
	}
	r = Run(rs, h, probe(world, me, 80))
	want(t, r, Filtered)
	if d := decisive(t, r); d.Kind != StepPolicy || d.Hook != rules.HookIngress || d.Table != "early" || d.Chain != "ingress" || !strings.HasPrefix(d.Effect, "policy drop") {
		t.Fatalf("decisive: %+v", d)
	}
	// The policy is that of the chain the packet passes: on another interface there is none.
	want(t, Run(rs, h, on("docker0", world, me, 80)), Open)
}

// TestIngressChainOnAnotherInterface: an ingress chain sees what arrives on its own interfaces
// and nothing else. The interface is the one the packet arrives on, whoever sent it.
func TestIngressChainOnAnotherInterface(t *testing.T) {
	h := twoArmed(lis("0.0.0.0", 80, "nginx"))
	guard := func(devs ...string) *rules.Ruleset {
		return ruleset(tbl("netdev", "guard", ingress("ingress", -500, rules.Accept, devs, rule("drop", v(rules.Drop)))))
	}
	for _, c := range []struct {
		devs       []string
		eth0, eth1 Class // a packet that arrives there
	}{
		{[]string{"eth1"}, Open, Filtered},
		{[]string{"eth0"}, Filtered, Open},
		{[]string{"eth0", "eth1"}, Filtered, Filtered},
		{[]string{"eth1", "eth0"}, Filtered, Filtered},
		{[]string{"docker0"}, Open, Open},
		// The reader never hands the engine such a chain; attached to nothing, it sees nothing.
		{nil, Open, Open},
	} {
		rs := guard(c.devs...)
		for _, p := range []struct {
			pr   Probe
			want Class
		}{
			{probe(world, me, 80), c.eth0},
			{probe(inside, meInner, 80), c.eth1},
			// Named outright, against the route: the name wins.
			{on("eth1", world, me, 80), c.eth1},
			{on("eth0", inside, meInner, 80), c.eth0},
		} {
			r := Run(rs, h, p.pr)
			if r.Class != p.want {
				t.Errorf("chain on %q, packet from %s on %q: %v, want %v\n%s", c.devs, p.pr.Src, p.pr.Iif, r.Class, p.want, trace(r))
				continue
			}
			if n := hookSteps(r, rules.HookIngress); (n != 0) != (p.want == Filtered) {
				t.Errorf("chain on %q, packet from %s on %q: %d steps on the ingress hook\n%s", c.devs, p.pr.Src, p.pr.Iif, n, trace(r))
			}
		}
	}
}

// TestIngressDevicePattern: a device name that ends in "*" attaches the chain to every interface
// whose name starts that way.
func TestIngressDevicePattern(t *testing.T) {
	h := twoArmed(lis("0.0.0.0", 80, "nginx"))
	rs := ruleset(tbl("netdev", "guard", ingress("ingress", -500, rules.Accept, []string{"eth*"}, rule("drop", v(rules.Drop)))))
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	want(t, Run(rs, h, probe(inside, meInner, 80)), Filtered)
	want(t, Run(rs, h, on("eth0.100", world, me, 80)), Filtered)
	want(t, Run(rs, h, on("docker0", world, me, 80)), Open)
	want(t, Run(rs, h, on("wg0", world, me, 80)), Open)
	// Without the star a name is one interface's whole name.
	rs = ruleset(tbl("netdev", "guard", ingress("ingress", -500, rules.Accept, []string{"eth"}, rule("drop", v(rules.Drop)))))
	want(t, Run(rs, h, probe(world, me, 80)), Open)
}

func TestNamed(t *testing.T) {
	for _, c := range []struct {
		names, devs []string
		want        bool
	}{
		{[]string{"eth0"}, []string{"eth0"}, true},
		{[]string{"eth0"}, []string{"eth1"}, false},
		{[]string{"eth0"}, []string{"eth1", "eth0"}, true},
		{[]string{"br0", "eth1", "eth2"}, []string{"eth2"}, true}, // any interface the packet passes
		{[]string{"eth0"}, []string{"eth*"}, true},
		{[]string{"eth10"}, []string{"eth1*"}, true},
		{[]string{"eth0"}, []string{"eth1*"}, false},
		{[]string{"eth0"}, []string{"eth0*"}, true}, // nothing has to follow
		{[]string{"eth0.100"}, []string{"eth0*"}, true},
		{[]string{"wg0"}, []string{"eth*"}, false},
		{[]string{"wg0"}, []string{"eth*", "wg*"}, true},
		{[]string{"wg0"}, []string{"*"}, true},
		{[]string{"eth0"}, []string{"eth"}, false}, // no star: the whole name or nothing
		{[]string{"eth"}, []string{"eth0"}, false},
		{[]string{"eth0"}, nil, false},
		{nil, []string{"eth0"}, false},
		{nil, []string{"*"}, false}, // no interface passed, none seen
	} {
		if got := named(c.names, c.devs); got != c.want {
			t.Errorf("named(%q, %q) = %v, want %v", c.names, c.devs, got, c.want)
		}
	}
}

// TestIngressChainsRunInPriorityOrder: several ingress chains on one interface run lowest
// priority first, whatever table they sit in and wherever the ruleset has them. The first that
// stops the packet has the last word; an accept only ends its own chain, and the next still runs
// (scenario nft-ingress-order).
func TestIngressChainsRunInPriorityOrder(t *testing.T) {
	h := twoArmed(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 8080, "app"))
	// build puts a chain that drops port 22 next to one that refuses it.
	build := func(dropPrio, rejectPrio int) (dropFirst, rejectFirst *rules.Ruleset) {
		drops := func() *rules.Table {
			return tbl("netdev", "drops", ingress("ingress", dropPrio, rules.Accept, []string{"eth0", "eth1"},
				rule("tcp dport 22 drop", tcp(), dport(22), v(rules.Drop)),
				rule("tcp dport 80 accept", tcp(), dport(80), v(rules.Accept)),
				rule("tcp dport 8080 accept", tcp(), dport(8080), v(rules.Accept))))
		}
		rejects := func() *rules.Table {
			return tbl("inet", "rejects", ingress("ingress", rejectPrio, rules.Accept, []string{"eth0"},
				rule("tcp dport 22 reject", tcp(), dport(22), v(rules.Reject)),
				rule("tcp dport 80 reject", tcp(), dport(80), v(rules.Reject))))
		}
		return ruleset(drops(), rejects()), ruleset(rejects(), drops())
	}
	for _, c := range []struct {
		dropPrio, rejectPrio int
		want                 Class  // port 22, which both chains stop
		table                string // the chain that has the last word about it
	}{
		{-300, 0, Filtered, "drops"},
		{0, -300, Rejected, "rejects"},
		{-1, 0, Filtered, "drops"},
		{100, 99, Rejected, "rejects"},
	} {
		a, b := build(c.dropPrio, c.rejectPrio)
		for i, rs := range []*rules.Ruleset{a, b} {
			r := Run(rs, h, probe(world, me, 22))
			if r.Class != c.want {
				t.Errorf("priorities %d and %d, ruleset %d: port 22 is %v, want %v\n%s", c.dropPrio, c.rejectPrio, i, r.Class, c.want, trace(r))
				continue
			}
			if d := decisive(t, r); d.Table != c.table || d.Hook != rules.HookIngress || len(r.Steps) != 1 {
				t.Errorf("priorities %d and %d, ruleset %d: decided by %+v\n%s", c.dropPrio, c.rejectPrio, i, d, trace(r))
			}
			// The accept of one chain does not keep the other from refusing the packet,
			// whichever of them runs first.
			r = Run(rs, h, probe(world, me, 80))
			if d := decisive(t, r); r.Class != Rejected || d.Table != "rejects" {
				t.Errorf("priorities %d and %d, ruleset %d: port 80 is %v by %+v\n%s", c.dropPrio, c.rejectPrio, i, r.Class, d, trace(r))
			}
			// Accepted by the one chain that has a word about it.
			r = Run(rs, h, probe(world, me, 8080))
			if r.Class != Open || hookSteps(r, rules.HookIngress) != 1 {
				t.Errorf("priorities %d and %d, ruleset %d: port 8080 is %v\n%s", c.dropPrio, c.rejectPrio, i, r.Class, trace(r))
			}
			// On eth1 only one of the two chains is attached.
			r = Run(rs, h, probe(inside, meInner, 22))
			if d := decisive(t, r); r.Class != Filtered || d.Table != "drops" {
				t.Errorf("priorities %d and %d, ruleset %d: port 22 on eth1 is %v by %+v\n%s", c.dropPrio, c.rejectPrio, i, r.Class, d, trace(r))
			}
			if r = Run(rs, h, probe(inside, meInner, 80)); r.Class != Open {
				t.Errorf("priorities %d and %d, ruleset %d: port 80 on eth1 is %v\n%s", c.dropPrio, c.rejectPrio, i, r.Class, trace(r))
			}
		}
	}
}
