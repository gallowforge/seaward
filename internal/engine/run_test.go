package engine

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }
func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func tbl(family, name string, chains ...*rules.Chain) *rules.Table {
	t := &rules.Table{Family: family, Name: name, Origin: "nft", Chains: map[string]*rules.Chain{}}
	for _, c := range chains {
		t.Chains[c.Name] = c
		t.Order = append(t.Order, c.Name)
	}
	return t
}

func base(name, hook, typ string, prio int, policy rules.VerdictKind, rs ...*rules.Rule) *rules.Chain {
	return &rules.Chain{Name: name, Base: true, Hook: hook, Type: typ, Priority: prio, Policy: policy, Rules: rs}
}

func sub(name string, rs ...*rules.Rule) *rules.Chain { return &rules.Chain{Name: name, Rules: rs} }

func rule(text string, exprs ...rules.Expr) *rules.Rule { return &rules.Rule{Text: text, Exprs: exprs} }

func v(k rules.VerdictKind) *rules.Verdict { return &rules.Verdict{Kind: k} }
func jump(chain string) *rules.Verdict     { return &rules.Verdict{Kind: rules.Jump, Chain: chain} }
func gotoc(chain string) *rules.Verdict    { return &rules.Verdict{Kind: rules.Goto, Chain: chain} }
func tcp() *rules.Match                    { return rules.Eq(rules.FL4Proto, rules.Num(6)) }
func dport(p uint32) *rules.Match          { return rules.Eq(rules.FDport, rules.Num(p)) }
func saddr(p string) *rules.Match          { return rules.Eq(rules.FSaddr, rules.Pfx(pfx(p))) }
func daddr(p string) *rules.Match          { return rules.Eq(rules.FDaddr, rules.Pfx(pfx(p))) }
func iif(n string) *rules.Match            { return rules.Eq(rules.FIifName, rules.Str(n)) }
func oif(n string) *rules.Match            { return rules.Eq(rules.FOifName, rules.Str(n)) }
func ctstate(bits uint32) *rules.Match     { return ctbits(bits, false) }
func ruleset(ts ...*rules.Table) *rules.Ruleset {
	return &rules.Ruleset{Tables: ts, Sets: map[string]*rules.Set{}}
}
func lis(addr string, port uint16, proc string) host.Listener {
	return host.Listener{Proto: "tcp", Addr: ip(addr), Port: port, Process: proc}
}

// ctbits is "ct state has any of bits", the way both iptables and nft test it.
func ctbits(bits uint32, neg bool) *rules.Match {
	var atoms []rules.Atom
	for b := uint32(1); b <= rules.CtUntracked; b <<= 1 {
		if bits&b != 0 {
			atoms = append(atoms, rules.Num(b))
		}
	}
	m := rules.Eq(rules.FCtState, atoms...)
	m.Neg = neg
	return m
}

// machine is a server with one outside interface, loopback and a Docker bridge.
func machine(ls ...host.Listener) *host.Host {
	return &host.Host{
		Name: "harbor",
		Interfaces: []host.Interface{
			{Name: "lo", Up: true, Loopback: true, Addrs: []netip.Prefix{pfx("127.0.0.1/8"), pfx("::1/128")}},
			{Name: "eth0", Up: true, Addrs: []netip.Prefix{pfx("203.0.113.10/24"), pfx("2001:db8:1::10/64")}},
			{Name: "docker0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{pfx("172.17.0.1/16")}},
		},
		Routes: []host.Route{
			{Dst: pfx("0.0.0.0/0"), Dev: "eth0", Gateway: ip("203.0.113.1")},
			{Dst: pfx("203.0.113.0/24"), Dev: "eth0"},
			{Dst: pfx("172.17.0.0/16"), Dev: "docker0"},
			{Dst: pfx("::/0"), Dev: "eth0", Gateway: ip("2001:db8:1::1")},
			{Dst: pfx("2001:db8:1::/64"), Dev: "eth0"},
		},
		Forward4:  true,
		Listeners: ls,
	}
}

// withContainer adds a container on the bridge whose inside was looked into.
func withContainer(h *host.Host, ls ...host.Listener) *host.Host {
	const id = "4f2a9c1d7e3b4f2a9c1d7e3b4f2a9c1d7e3b4f2a9c1d7e3b4f2a9c1d7e3b0001"
	h.Docker = &host.Docker{Containers: []host.Container{{
		ID: id, Name: "web", Image: "nginx",
		Networks:       []host.ContainerNet{{Network: "bridge", Addr: ip("172.17.0.2")}},
		Ports:          []host.Published{{Proto: "tcp", HostPort: 8080, ContainerPort: 80}},
		ListenersKnown: true,
	}}}
	for _, l := range ls {
		l.Netns = id[:12]
		h.Listeners = append(h.Listeners, l)
	}
	return h
}

const (
	world = "198.51.100.7"
	me    = "203.0.113.10"
)

func probe(src, dst string, port uint16) Probe {
	return Probe{Src: ip(src), Dst: ip(dst), Proto: "tcp", Dport: port}
}

func want(t *testing.T, r Result, c Class) {
	t.Helper()
	if r.Class != c {
		t.Fatalf("got %v, want %v\nunknowns: %v\nsteps:\n%s", r.Class, c, r.Unknowns, trace(r))
	}
}

func trace(r Result) string {
	var b strings.Builder
	for _, s := range r.Steps {
		b.WriteString("  " + string(s.Kind) + " " + s.Hook + " " + s.Table + "/" + s.Chain + ": " + s.Rule + " => " + s.Effect)
		if s.Decisive {
			b.WriteString("  <- decides")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func decisive(t *testing.T, r Result) Step {
	t.Helper()
	n := 0
	var d Step
	for _, s := range r.Steps {
		if s.Decisive {
			n++
			d = s
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one decisive step, got %d\n%s", n, trace(r))
	}
	return d
}

func TestNoRules(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"), lis("127.0.0.1", 5432, "postgres"), lis("203.0.113.10", 8443, "caddy"))
	r := Run(nil, h, probe(world, me, 80))
	want(t, r, Open)
	if r.Listener == nil || r.Listener.Process != "nginx" {
		t.Fatalf("listener: %+v", r.Listener)
	}
	if d := decisive(t, r); d.Kind != StepDeliver || !strings.Contains(d.Effect, "nginx is listening on 0.0.0.0:80") {
		t.Fatalf("decisive step: %+v", d)
	}
	want(t, Run(nil, h, probe(world, me, 81)), Closed)
	want(t, Run(nil, h, probe(world, me, 5432)), Closed) // bound to loopback only
	want(t, Run(nil, h, probe(world, me, 8443)), Open)   // bound to the exact address
	// UDP has its own sockets.
	want(t, Run(nil, h, Probe{Src: ip(world), Dst: ip(me), Proto: "udp", Dport: 80}), Closed)
}

func TestNoListenerData(t *testing.T) {
	h := machine()
	h.NoListenerData = true
	r := Run(nil, h, probe(world, me, 80))
	want(t, r, Undecided)
	if len(r.Unknowns) != 1 || !strings.Contains(r.Unknowns[0], "listening programs") {
		t.Fatalf("unknowns: %v", r.Unknowns)
	}
}

func TestDualStack(t *testing.T) {
	h := machine(
		host.Listener{Proto: "tcp", Addr: ip("::"), DualStack: true, Port: 80, Process: "both"},
		host.Listener{Proto: "tcp", Addr: ip("::"), Port: 81, Process: "six"},
		host.Listener{Proto: "tcp", Addr: ip("0.0.0.0"), Port: 82, Process: "four"},
	)
	const six = "2001:db8:1::10"
	const far6 = "2001:db8:99::7"
	want(t, Run(nil, h, probe(world, me, 80)), Open)
	want(t, Run(nil, h, probe(far6, six, 80)), Open)
	want(t, Run(nil, h, probe(world, me, 81)), Closed)
	want(t, Run(nil, h, probe(far6, six, 81)), Open)
	want(t, Run(nil, h, probe(world, me, 82)), Open)
	want(t, Run(nil, h, probe(far6, six, 82)), Closed)
}

func inputTable(policy rules.VerdictKind, rs ...*rules.Rule) *rules.Table {
	return tbl("ip", "filter", base("INPUT", rules.HookInput, "filter", 0, policy, rs...))
}

func TestInputPolicy(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 9100, "exporter"))
	rs := ruleset(inputTable(rules.Drop,
		rule("-A INPUT -p tcp --dport 22 -j ACCEPT", tcp(), dport(22), v(rules.Accept)),
		rule("-A INPUT -p tcp --dport 9100 -j REJECT", tcp(), dport(9100), v(rules.Reject)),
		rule("-A INPUT -s 203.0.113.0/24 -p tcp --dport 80 -j ACCEPT", saddr("203.0.113.0/24"), tcp(), dport(80), v(rules.Accept)),
	))
	r := Run(rs, h, probe(world, me, 22))
	want(t, r, Open)
	r = Run(rs, h, probe(world, me, 80))
	want(t, r, Filtered)
	if d := decisive(t, r); d.Kind != StepPolicy || d.Chain != "INPUT" || d.Table != "filter" {
		t.Fatalf("decisive: %+v", d)
	}
	want(t, Run(rs, h, probe("203.0.113.77", me, 80)), Open)
	r = Run(rs, h, probe(world, me, 9100))
	want(t, r, Rejected)
	if d := decisive(t, r); d.Kind != StepRule || !strings.Contains(d.Rule, "REJECT") {
		t.Fatalf("decisive: %+v", d)
	}
	// An accepted port with nothing behind it is closed, not open.
	h2 := machine()
	want(t, Run(rs, h2, probe(world, me, 22)), Closed)
}

func TestFamilies(t *testing.T) {
	h := machine(host.Listener{Proto: "tcp", Addr: ip("::"), DualStack: true, Port: 80, Process: "nginx"})
	// An IPv4-only firewall leaves IPv6 wide open.
	rs := ruleset(inputTable(rules.Drop))
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	want(t, Run(rs, h, probe("2001:db8:99::7", "2001:db8:1::10", 80)), Open)
	// An inet table sees both.
	rs = ruleset(tbl("inet", "filter", base("input", rules.HookInput, "filter", 0, rules.Drop,
		rule("meta nfproto ipv6 tcp dport 80 accept", rules.Eq(rules.FNFProto, rules.Num(6)), tcp(), dport(80), v(rules.Accept)))))
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	want(t, Run(rs, h, probe("2001:db8:99::7", "2001:db8:1::10", 80)), Open)
	// A rule about IPv4 addresses never matches an IPv6 packet, negated or not.
	neg := saddr("203.0.113.0/24")
	neg.Neg = true
	rs = ruleset(tbl("inet", "filter", base("input", rules.HookInput, "filter", 0, rules.Accept,
		rule("ip saddr != 203.0.113.0/24 drop", neg, v(rules.Drop)))))
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	want(t, Run(rs, h, probe("203.0.113.77", me, 80)), Open)
	want(t, Run(rs, h, probe("2001:db8:99::7", "2001:db8:1::10", 80)), Open)
}

func TestJumpReturnGoto(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 81, "alt"), lis("0.0.0.0", 82, "third"))
	rs := ruleset(tbl("ip", "filter",
		base("INPUT", rules.HookInput, "filter", 0, rules.Drop,
			rule("-A INPUT -j checks", jump("checks")),
			rule("-A INPUT -p tcp --dport 81 -g final", tcp(), dport(81), gotoc("final")),
			rule("-A INPUT -p tcp --dport 81 -j ACCEPT", tcp(), dport(81), v(rules.Accept)),
			rule("-A INPUT -p tcp --dport 82 -j ACCEPT", tcp(), dport(82), v(rules.Accept)),
		),
		sub("checks",
			rule("-A checks -p tcp --dport 82 -j RETURN", tcp(), dport(82), v(rules.Return)),
			rule("-A checks -p tcp --dport 80 -j ACCEPT", tcp(), dport(80), v(rules.Accept)),
			rule("-A checks -p tcp --dport 82 -j DROP", tcp(), dport(82), v(rules.Drop)),
		),
		sub("final",
			rule("-A final -s 192.0.2.0/24 -j ACCEPT", saddr("192.0.2.0/24"), v(rules.Accept)),
		),
	))
	r := Run(rs, h, probe(world, me, 80))
	want(t, r, Open)
	// The trace shows the jump that led to the accept.
	if len(r.Steps) < 3 || r.Steps[1].Kind != StepJump || r.Steps[2].Chain != "checks" {
		t.Fatalf("steps:\n%s", trace(r))
	}
	// A goto does not come back: the accept after it is never reached.
	want(t, Run(rs, h, probe(world, me, 81)), Filtered)
	want(t, Run(rs, h, probe("192.0.2.50", me, 81)), Open)
	// A return goes back to the caller.
	r = Run(rs, h, probe(world, me, 82))
	want(t, r, Open)
	// The jump that decided nothing is left out of the trace.
	for _, s := range r.Steps {
		if s.Kind == StepJump {
			t.Fatalf("a jump that decided nothing stayed in the trace:\n%s", trace(r))
		}
	}
	// A jump to a chain that does not exist cannot be followed.
	rs = ruleset(inputTable(rules.Accept, rule("-A INPUT -j gone", jump("gone"))))
	want(t, Run(rs, h, probe(world, me, 80)), Undecided)
	// Chains that jump into each other for ever end, too.
	rs = ruleset(tbl("ip", "filter",
		base("INPUT", rules.HookInput, "filter", 0, rules.Accept, rule("-A INPUT -j a", jump("a"))),
		sub("a", rule("-A a -j b", jump("b"))),
		sub("b", rule("-A b -j a", jump("a"))),
	))
	want(t, Run(rs, h, probe(world, me, 80)), Undecided)
}

// dockerRules is the shape Docker gives a machine with one published port, next to a firewall
// front end whose INPUT chain drops everything but ssh.
func dockerRules() *rules.Ruleset {
	local := rules.Eq(rules.FFibDaddrType, rules.Num(rules.AddrLocal))
	notBridge := rules.Ne(rules.FIifName, rules.Str("docker0"))
	return ruleset(
		tbl("ip", "nat",
			base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
				rule("-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER", local, jump("DOCKER"))),
			sub("DOCKER",
				rule("-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.2:80",
					notBridge, tcp(), dport(8080), &rules.DNAT{Addr: ip("172.17.0.2"), Port: 80})),
		),
		tbl("ip", "filter",
			base("INPUT", rules.HookInput, "filter", 0, rules.Drop,
				rule("-A INPUT -p tcp --dport 22 -j ACCEPT", tcp(), dport(22), v(rules.Accept))),
			base("FORWARD", rules.HookForward, "filter", 0, rules.Drop,
				rule("-A FORWARD -j DOCKER-FORWARD", jump("DOCKER-FORWARD"))),
			sub("DOCKER-FORWARD",
				rule("-A DOCKER-FORWARD -o docker0 -j DOCKER", oif("docker0"), jump("DOCKER"))),
			sub("DOCKER",
				rule("-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT",
					daddr("172.17.0.2/32"), notBridge, oif("docker0"), tcp(), dport(80), v(rules.Accept)),
				rule("-A DOCKER ! -i docker0 -o docker0 -j DROP", notBridge, oif("docker0"), v(rules.Drop))),
		),
	)
}

func TestDockerPublishedPortBypassesInput(t *testing.T) {
	h := withContainer(machine(lis("0.0.0.0", 22, "sshd")), lis("0.0.0.0", 80, "nginx"))
	rs := dockerRules()
	r := Run(rs, h, probe(world, me, 8080))
	want(t, r, Open)
	if !r.Rewritten || r.FinalDst != ip("172.17.0.2") || r.FinalPort != 80 {
		t.Fatalf("rewrite: %v %v %v", r.Rewritten, r.FinalDst, r.FinalPort)
	}
	if r.Container == nil || r.Container.Name != "web" || r.Listener == nil || r.Listener.Process != "nginx" {
		t.Fatalf("delivery: %+v %+v", r.Container, r.Listener)
	}
	// The INPUT chain, where the front end keeps its rules, was never asked.
	for _, s := range r.Steps {
		if s.Hook == rules.HookInput {
			t.Fatalf("the input hook ran for a forwarded packet:\n%s", trace(r))
		}
	}
	// The same port with nothing published is dropped by the INPUT policy.
	want(t, Run(rs, h, probe(world, me, 8081)), Filtered)
	// Straight to the container address from outside: Docker's own drop.
	want(t, Run(rs, h, probe(world, "172.17.0.2", 81)), Filtered)
	// With forwarding off the kernel drops the rewritten packet.
	h.Forward4 = false
	r = Run(rs, h, probe(world, me, 8080))
	want(t, r, Filtered)
	if d := decisive(t, r); d.Kind != StepRoute || !strings.Contains(d.Effect, "ip_forward") {
		t.Fatalf("decisive: %+v", d)
	}
}

func TestContainerInsideNotCaptured(t *testing.T) {
	h := withContainer(machine())
	h.Docker.Containers[0].ListenersKnown = false
	r := Run(dockerRules(), h, probe(world, me, 8080))
	want(t, r, Forwarded)
	if r.Container == nil {
		t.Fatal("the container is not named")
	}
	// Looked into, and nothing listens: closed.
	h.Docker.Containers[0].ListenersKnown = true
	r = Run(dockerRules(), h, probe(world, me, 8080))
	want(t, r, Closed)
	if r.Container == nil {
		t.Fatal("the container is not named")
	}
}

func TestForwardToAnotherMachine(t *testing.T) {
	h := machine()
	h.Interfaces = append(h.Interfaces, host.Interface{Name: "eth1", Up: true, Addrs: []netip.Prefix{pfx("10.20.0.1/24")}})
	h.Routes = append(h.Routes, host.Route{Dst: pfx("10.20.0.0/24"), Dev: "eth1"})
	rs := ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -i eth0 -p tcp --dport 3389 -j DNAT --to-destination 10.20.0.50", iif("eth0"), tcp(), dport(3389), &rules.DNAT{Addr: ip("10.20.0.50")}))))
	r := Run(rs, h, probe(world, me, 3389))
	want(t, r, Forwarded)
	if r.FinalDst != ip("10.20.0.50") || r.FinalPort != 3389 || r.Container != nil {
		t.Fatalf("got %v:%d %+v", r.FinalDst, r.FinalPort, r.Container)
	}
	// A blackhole route swallows it.
	h.Routes = append(h.Routes, host.Route{Dst: pfx("10.20.0.50/32"), Type: "blackhole"})
	want(t, Run(rs, h, probe(world, me, 3389)), Filtered)
}

func TestUnknownConditions(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"))
	u := &rules.Unknown{Why: "the geoip match cannot be evaluated"}
	// Both answers end the same way: the result stands, with the reason attached.
	rs := ruleset(inputTable(rules.Accept, rule("-A INPUT -m geoip --src-cc XX -j ACCEPT", u, v(rules.Accept))))
	r := Run(rs, h, probe(world, me, 80))
	want(t, r, Open)
	if len(r.Unknowns) != 1 || r.Unknowns[0] != u.Why {
		t.Fatalf("unknowns: %v", r.Unknowns)
	}
	// The answers differ: undecided, and it says how it could end.
	rs = ruleset(inputTable(rules.Accept, rule("-A INPUT -m geoip --src-cc XX -j DROP", u, v(rules.Drop))))
	r = Run(rs, h, probe(world, me, 80))
	want(t, r, Undecided)
	if len(r.Possible) != 2 || r.Possible[0] != Open || r.Possible[1] != Filtered {
		t.Fatalf("possible: %v", r.Possible)
	}
	if len(r.Unknowns) != 1 {
		t.Fatalf("unknowns: %v", r.Unknowns)
	}
	// An unknown that is never reached does not show up at all.
	rs = ruleset(inputTable(rules.Accept,
		rule("-A INPUT -p tcp --dport 80 -j ACCEPT", tcp(), dport(80), v(rules.Accept)),
		rule("-A INPUT -m geoip --src-cc XX -j DROP", u, v(rules.Drop))))
	r = Run(rs, h, probe(world, me, 80))
	want(t, r, Open)
	if len(r.Unknowns) != 0 {
		t.Fatalf("unknowns: %v", r.Unknowns)
	}
	// A rule with a statement the model cannot follow stops the walk only when the packet gets there.
	st := &rules.UnknownStmt{Why: "the TPROXY target is not modelled"}
	rs = ruleset(inputTable(rules.Accept, rule("-A INPUT -p tcp --dport 81 -j TPROXY", tcp(), dport(81), st)))
	want(t, Run(rs, h, probe(world, me, 80)), Open)
	r = Run(rs, h, probe(world, me, 81))
	want(t, r, Undecided)
	if len(r.Unknowns) != 1 || r.Unknowns[0] != st.Why {
		t.Fatalf("unknowns: %v", r.Unknowns)
	}
	// Many unknowns in a row are all followed; one that leads to a drop is found.
	var many []*rules.Rule
	for i := 0; i < 5; i++ {
		many = append(many, rule("-A INPUT -m something -j RETURN", &rules.Unknown{Why: "something"}, v(rules.Return)))
	}
	many = append(many, rule("-A INPUT -j DROP", v(rules.Drop)))
	r = Run(ruleset(inputTable(rules.Accept, many...)), h, probe(world, me, 80))
	want(t, r, Undecided)
	if len(r.Unknowns) != 1 || len(r.Possible) != 2 {
		t.Fatalf("unknowns %v possible %v", r.Unknowns, r.Possible)
	}
	// Far too many to follow: it gives up and says so.
	many = nil
	for i := 0; i < 200; i++ {
		many = append(many, rule("-A INPUT -m something", &rules.Unknown{Why: "something"}, &rules.Noop{What: "count"}))
	}
	r = Run(ruleset(inputTable(rules.Accept, many...)), h, probe(world, me, 80))
	want(t, r, Undecided)
}

func TestNeverAndAlways(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"))
	rs := ruleset(inputTable(rules.Drop,
		rule("-A INPUT -m recent --update --seconds 30 --hitcount 6 -j DROP", &rules.Never{What: "a first packet has no history"}, v(rules.Drop)),
		rule("-A INPUT -m limit --limit 3/min -j ACCEPT", &rules.Always{What: "a first packet is within any rate"}, tcp(), dport(22), v(rules.Accept)),
	))
	want(t, Run(rs, h, probe(world, me, 22)), Open)
}

func TestConntrackState(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"))
	rs := ruleset(inputTable(rules.Drop,
		rule("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ctstate(rules.CtEstablished|rules.CtRelated), v(rules.Accept)),
		rule("-A INPUT -m conntrack --ctstate INVALID -j DROP", ctstate(rules.CtInvalid), v(rules.Drop)),
		rule("-A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT", tcp(), dport(80), ctstate(rules.CtNew), v(rules.Accept)),
	))
	r := Run(rs, h, probe(world, me, 80))
	want(t, r, Open)
	if d := r.Steps[len(r.Steps)-2]; !strings.Contains(d.Rule, "NEW") {
		t.Fatalf("accepted by the wrong rule:\n%s", trace(r))
	}
	// A firewall that only lets established connections in lets no new one in.
	rs = ruleset(inputTable(rules.Drop,
		rule("-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", ctstate(rules.CtEstablished|rules.CtRelated), v(rules.Accept))))
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
}

func TestNotrackSkipsNat(t *testing.T) {
	h := withContainer(machine(), lis("0.0.0.0", 80, "nginx"))
	rs := dockerRules()
	raw := tbl("ip", "raw", base("PREROUTING", rules.HookPrerouting, "filter", -300, rules.Accept,
		rule("-A PREROUTING -p tcp --dport 8080 -j CT --notrack", tcp(), dport(8080), &rules.Notrack{})))
	rs.Tables = append([]*rules.Table{raw}, rs.Tables...)
	// Untracked, the packet is never rewritten: it stays for this machine, and INPUT drops it.
	r := Run(rs, h, probe(world, me, 8080))
	want(t, r, Filtered)
	if r.Rewritten {
		t.Fatal("an untracked packet was rewritten")
	}
	// The state an untracked packet shows to rules.
	rs = ruleset(raw, inputTable(rules.Drop,
		rule("-A INPUT -m conntrack --ctstate UNTRACKED -j ACCEPT", ctstate(rules.CtUntracked), v(rules.Accept))))
	h = machine(lis("0.0.0.0", 8080, "app"), lis("0.0.0.0", 80, "nginx"))
	want(t, Run(rs, h, probe(world, me, 8080)), Open)
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	// A notrack after connection tracking has seen the packet does nothing.
	late := tbl("ip", "mangle", base("PREROUTING", rules.HookPrerouting, "filter", -150, rules.Accept,
		rule("-A PREROUTING -j CT --notrack", &rules.Notrack{})))
	rs = ruleset(late, inputTable(rules.Drop,
		rule("-A INPUT -m conntrack --ctstate NEW -j ACCEPT", ctstate(rules.CtNew), v(rules.Accept))))
	want(t, Run(rs, h, probe(world, me, 80)), Open)
}

func TestSets(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 443, "caddy"))
	rs := ruleset(tbl("inet", "fw", base("input", rules.HookInput, "filter", 0, rules.Drop,
		rule("ip saddr . tcp dport @admins accept",
			&rules.Match{Key: []rules.Field{{Name: rules.FSaddr}, {Name: rules.FDport}}, SetRef: rules.SetKey("inet", "fw", "admins")}, v(rules.Accept)),
		rule("tcp dport @web accept", &rules.Match{Key: []rules.Field{{Name: rules.FDport}}, SetRef: rules.SetKey("inet", "fw", "web")}, v(rules.Accept)),
	)))
	rs.Sets[rules.SetKey("inet", "fw", "admins")] = &rules.Set{Name: "admins", Elems: []rules.Elem{
		{rules.Pfx(pfx("192.0.2.0/24")), rules.Num(22)},
	}}
	rs.Sets[rules.SetKey("inet", "fw", "web")] = &rules.Set{Name: "web", Elems: []rules.Elem{{rules.NumRange(443, 444)}}}
	want(t, Run(rs, h, probe("192.0.2.50", me, 22)), Open)
	want(t, Run(rs, h, probe(world, me, 22)), Filtered)
	want(t, Run(rs, h, probe(world, me, 443)), Open)
	// A set that is not in the snapshot: both answers are followed.
	delete(rs.Sets, rules.SetKey("inet", "fw", "web"))
	r := Run(rs, h, probe(world, me, 443))
	want(t, r, Undecided)
	if len(r.Unknowns) != 1 || !strings.Contains(r.Unknowns[0], "the set web is not in the snapshot") {
		t.Fatalf("unknowns: %v", r.Unknowns)
	}
	// A set whose contents could not be read is the same.
	rs.Sets[rules.SetKey("inet", "fw", "web")] = &rules.Set{Name: "web", Incomplete: true, Why: "the set web holds a type the model does not read"}
	want(t, Run(rs, h, probe(world, me, 443)), Undecided)
	// An empty set matches nothing, and its negation everything.
	rs.Sets[rules.SetKey("inet", "fw", "web")] = &rules.Set{Name: "web"}
	want(t, Run(rs, h, probe(world, me, 443)), Filtered)
}

func TestVerdictMaps(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 443, "caddy"), lis("0.0.0.0", 25, "smtpd"))
	key := []rules.Field{{Name: rules.FDport}}
	rs := ruleset(tbl("inet", "fw",
		base("input", rules.HookInput, "filter", 0, rules.Drop,
			rule("tcp dport vmap { 22 : accept, 80 : jump web, 25 : drop }", &rules.VerdictMap{Key: key, Entries: []rules.VmapEntry{
				{Key: rules.Elem{rules.Num(22)}, Verdict: rules.Verdict{Kind: rules.Accept}},
				{Key: rules.Elem{rules.Num(80)}, Verdict: rules.Verdict{Kind: rules.Jump, Chain: "web"}},
				{Key: rules.Elem{rules.Num(25)}, Verdict: rules.Verdict{Kind: rules.Drop}},
			}}),
			rule("tcp dport vmap @named", &rules.VerdictMap{Key: key, SetRef: rules.SetKey("inet", "fw", "named")}),
		),
		sub("web", rule("ip saddr 192.0.2.0/24 accept", saddr("192.0.2.0/24"), v(rules.Accept))),
	))
	rs.Sets[rules.SetKey("inet", "fw", "named")] = &rules.Set{Name: "named",
		Elems:    []rules.Elem{{rules.Num(443)}},
		Verdicts: []rules.Verdict{{Kind: rules.Accept}},
	}
	want(t, Run(rs, h, probe(world, me, 22)), Open)
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	want(t, Run(rs, h, probe("192.0.2.50", me, 80)), Open)
	want(t, Run(rs, h, probe(world, me, 25)), Filtered)
	want(t, Run(rs, h, probe(world, me, 443)), Open)
	// A port no entry names falls to the policy.
	want(t, Run(rs, h, probe(world, me, 444)), Filtered)
}

func TestRouteLocalnet(t *testing.T) {
	h := machine(lis("127.0.0.1", 5432, "postgres"))
	rs := ruleset(tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -p tcp --dport 15432 -j DNAT --to-destination 127.0.0.1:5432", tcp(), dport(15432), &rules.DNAT{Addr: ip("127.0.0.1"), Port: 5432}))))
	// The kernel throws away packets for 127.0.0.1 that came from outside.
	r := Run(rs, h, probe(world, me, 15432))
	want(t, r, Filtered)
	if d := decisive(t, r); d.Kind != StepRoute {
		t.Fatalf("decisive: %+v", d)
	}
	// Unless route_localnet is on for the interface: then the loopback-only service is exposed.
	h.RouteLocalnet = map[string]bool{"eth0": true}
	r = Run(rs, h, probe(world, me, 15432))
	want(t, r, Open)
	if r.Listener == nil || r.Listener.Process != "postgres" {
		t.Fatalf("listener: %+v", r.Listener)
	}
}

func TestMarks(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 81, "alt"))
	marked := &rules.Match{Key: []rules.Field{{Name: rules.FMark, Mask: 0xff, HasMask: true}}, Values: rules.One(rules.Num(0x10))}
	ctmarked := rules.Eq(rules.FCtMark, rules.Num(0x10))
	rs := ruleset(
		tbl("ip", "mangle", base("PREROUTING", rules.HookPrerouting, "filter", -150, rules.Accept,
			rule("-A PREROUTING -p tcp --dport 80 -j MARK --set-xmark 0x110/0xffffffff", tcp(), dport(80), &rules.SetMark{And: 0, Xor: 0x110}),
			rule("-A PREROUTING -j CONNMARK --save-mark --mask 0xff", &rules.CopyMark{ToCt: true, Mask: 0xff}))),
		inputTable(rules.Drop,
			rule("-A INPUT -m mark --mark 0x10/0xff -m connmark --mark 0x10 -j ACCEPT", marked, ctmarked, v(rules.Accept))),
	)
	want(t, Run(rs, h, probe(world, me, 80)), Open)
	want(t, Run(rs, h, probe(world, me, 81)), Filtered)
}

func TestPriorityOrder(t *testing.T) {
	// A filter chain that runs before the rewrite sees the port the sender used; one that runs
	// after it sees the new one.
	nat := tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-ports 80", tcp(), dport(8080), &rules.Redirect{Port: 80})))
	h := machine(lis("0.0.0.0", 80, "nginx"))
	early := tbl("ip", "early", base("pre", rules.HookPrerouting, "filter", -150, rules.Accept,
		rule("tcp dport 8080 drop", tcp(), dport(8080), v(rules.Drop))))
	lateOld := tbl("ip", "late", base("pre", rules.HookPrerouting, "filter", 0, rules.Accept,
		rule("tcp dport 8080 drop", tcp(), dport(8080), v(rules.Drop))))
	lateNew := tbl("ip", "late", base("pre", rules.HookPrerouting, "filter", 0, rules.Accept,
		rule("tcp dport 80 drop", tcp(), dport(80), v(rules.Drop))))
	r := Run(ruleset(nat), h, probe(world, me, 8080))
	want(t, r, Open)
	if r.FinalDst != ip(me) || r.FinalPort != 80 || !r.Rewritten {
		t.Fatalf("redirect: %v %d", r.FinalDst, r.FinalPort)
	}
	// Table order in the ruleset does not matter, only priority.
	want(t, Run(ruleset(nat, early), h, probe(world, me, 8080)), Filtered)
	want(t, Run(ruleset(lateOld, nat), h, probe(world, me, 8080)), Open)
	want(t, Run(ruleset(lateNew, nat), h, probe(world, me, 8080)), Filtered)
	// The original destination stays visible to rules after the rewrite.
	orig := tbl("ip", "filter", base("INPUT", rules.HookInput, "filter", 0, rules.Drop,
		rule("-A INPUT -m conntrack --ctstate DNAT --ctorigdstport 8080 -j ACCEPT",
			rules.Eq(rules.FCtStatusDNAT, rules.Num(1)), rules.Eq(rules.FCtOrigDport, rules.Num(8080)), v(rules.Accept))))
	want(t, Run(ruleset(nat, orig), h, probe(world, me, 8080)), Open)
	want(t, Run(ruleset(nat, orig), h, probe(world, me, 80)), Filtered)
}

func TestFirstNatRuleWins(t *testing.T) {
	// Two nat chains on one hook: once the first sets the mapping the second is not asked.
	h := machine(lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 81, "alt"))
	a := tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("-A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-ports 80", tcp(), dport(8080), &rules.Redirect{Port: 80})))
	b := tbl("ip", "other", base("pre", rules.HookPrerouting, "nat", -90, rules.Accept,
		rule("tcp dport 80 redirect to :81", tcp(), dport(80), &rules.Redirect{Port: 81})))
	r := Run(ruleset(b, a), h, probe(world, me, 8080))
	want(t, r, Open)
	if r.FinalPort != 80 {
		t.Fatalf("final port %d", r.FinalPort)
	}
	// On its own the second chain does rewrite port 80.
	r = Run(ruleset(b, a), h, probe(world, me, 80))
	want(t, r, Open)
	if r.FinalPort != 81 {
		t.Fatalf("final port %d", r.FinalPort)
	}
}

func TestRewriteToARange(t *testing.T) {
	// A rewrite to a range of ports keeps the port the packet came for when it lies in the range
	// and takes the first port of the range when it does not. The kernel lab proves both
	// (scenarios nat-port-range and nft-nat-port-range).
	h := machine(lis("0.0.0.0", 8000, "first"), lis("0.0.0.0", 8105, "kept"), lis("0.0.0.0", 8200, "dnat"))
	nat := tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("redirect 80", tcp(), dport(80), &rules.Redirect{Port: 8000, PortHi: 8010}),
		rule("redirect 8105", tcp(), dport(8105), &rules.Redirect{Port: 8100, PortHi: 8110}),
		rule("redirect 8103", tcp(), dport(8103), &rules.Redirect{Port: 8100, PortHi: 8110}),
		rule("dnat 82", tcp(), dport(82), &rules.DNAT{Addr: ip(me), Port: 8200, PortHi: 8210}),
		rule("dnat 8203", tcp(), dport(8203), &rules.DNAT{Addr: ip(me), Port: 8200, PortHi: 8210}),
		rule("one port", tcp(), dport(83), &rules.Redirect{Port: 8000, PortHi: 8000}),
		rule("random", tcp(), dport(84), &rules.Redirect{Port: 8000, PortHi: 8010, Random: true}),
		rule("random dnat", tcp(), dport(85), &rules.DNAT{Addr: ip(me), Port: 8200, PortHi: 8210, Random: true}),
		rule("random, one port", tcp(), dport(86), &rules.Redirect{Port: 8000, Random: true}),
		rule("addresses", tcp(), dport(87), &rules.DNAT{Addr: ip(me), AddrHi: ip("203.0.113.12"), Port: 8000}),
		rule("one address", tcp(), dport(88), &rules.DNAT{Addr: ip(me), AddrHi: ip(me), Port: 8000})))
	rs := ruleset(nat)
	for _, c := range []struct {
		port  uint16
		class Class
		final uint16
	}{
		{80, Open, 8000},   // outside the range: the first port
		{8105, Open, 8105}, // inside the range: the port stays
		{8103, Closed, 8103},
		{82, Open, 8200},
		{8203, Closed, 8203},
		{83, Open, 8000},
		{86, Open, 8000}, // nothing to pick from: random changes nothing
		{88, Open, 8000},
	} {
		r := Run(rs, h, probe(world, me, c.port))
		want(t, r, c.class)
		if r.FinalPort != c.final {
			t.Errorf("port %d ended on port %d, want %d", c.port, r.FinalPort, c.final)
		}
	}
	// A random port or one address out of several is the kernel's pick: say so, and guess nothing.
	for port, word := range map[uint16]string{84: "picked at random", 85: "picked at random", 87: "one address out of 203.0.113.10 to 203.0.113.12"} {
		r := Run(rs, h, probe(world, me, port))
		want(t, r, Undecided)
		if len(r.Unknowns) != 1 || !strings.Contains(r.Unknowns[0], word) {
			t.Errorf("port %d: unknowns %q, want one that says %q", port, r.Unknowns, word)
		}
	}
	// A range of the other family does not match the packet at all.
	six := Run(ruleset(tbl("inet", "nat", base("pre", rules.HookPrerouting, "nat", -100, rules.Accept,
		rule("v6 range", tcp(), dport(80), &rules.DNAT{Addr: ip("2001:db8:1::10"), AddrHi: ip("2001:db8:1::12")})))),
		machine(lis("0.0.0.0", 80, "nginx")), probe(world, me, 80))
	want(t, six, Open)
}

func TestInterfaceAndReversePath(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"))
	h.Interfaces = append(h.Interfaces, host.Interface{Name: "wg0", Up: true, Addrs: []netip.Prefix{pfx("10.8.0.1/24")}})
	h.Routes = append(h.Routes, host.Route{Dst: pfx("10.8.0.0/24"), Dev: "wg0"})
	rs := ruleset(inputTable(rules.Drop,
		rule("-A INPUT -i wg+ -p tcp --dport 80 -j ACCEPT", rules.Eq(rules.FIifName, rules.StrPfx("wg")), tcp(), dport(80), v(rules.Accept))))
	want(t, Run(rs, h, probe("10.8.0.9", "10.8.0.1", 80)), Open)
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)
	// A packet that claims a VPN address but arrives on the outside interface fails a reverse-path
	// check.
	rpf := ruleset(tbl("inet", "fw", base("pre", rules.HookPrerouting, "filter", -300, rules.Accept,
		rule("fib saddr . iif oif missing drop", rules.Eq(rules.FRpfOK, rules.Num(0)), v(rules.Drop)))))
	spoof := Probe{Iif: "eth0", Src: ip("10.8.0.9"), Dst: ip(me), Proto: "tcp", Dport: 80}
	want(t, Run(rpf, h, spoof), Filtered)
	want(t, Run(rpf, h, probe(world, me, 80)), Open)
}

func TestBadProbes(t *testing.T) {
	h := machine(lis("0.0.0.0", 80, "nginx"))
	want(t, Run(nil, h, Probe{Src: ip(world), Dst: ip(me), Proto: "icmp"}), Undecided)
	want(t, Run(nil, h, Probe{Src: ip("2001:db8:99::7"), Dst: ip(me), Proto: "tcp", Dport: 80}), Undecided)
	want(t, Run(nil, h, Probe{Dst: ip(me), Proto: "tcp", Dport: 80}), Undecided)
	// No machine at all: nothing is known, and nothing panics.
	want(t, Run(nil, nil, probe(world, me, 80)), Undecided)
	// A mapped IPv4 address is IPv4.
	want(t, Run(nil, h, Probe{Src: ip("::ffff:198.51.100.7"), Dst: ip("::ffff:203.0.113.10"), Proto: "tcp", Dport: 80}), Open)
}

func TestBroadcastAndMulticast(t *testing.T) {
	h := machine(host.Listener{Proto: "udp", Addr: ip("0.0.0.0"), Port: 5353, Process: "mdns"})
	bc := Probe{Src: ip("203.0.113.77"), Dst: ip("203.0.113.255"), Proto: "udp", Dport: 5353}
	rs := ruleset(inputTable(rules.Accept,
		rule("-A INPUT -m pkttype --pkt-type broadcast -j DROP", rules.Eq(rules.FPktType, rules.Num(rules.PktBroadcast)), v(rules.Drop))))
	want(t, Run(nil, h, bc), Open)
	want(t, Run(rs, h, bc), Filtered)
	want(t, Run(nil, h, Probe{Src: ip("203.0.113.77"), Dst: ip("224.0.0.251"), Proto: "udp", Dport: 5353}), Undecided)
}

func TestAddrTypeOnInterface(t *testing.T) {
	h := machine()
	h.Interfaces = append(h.Interfaces, host.Interface{Name: "eth1", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("10.20.0.1/24")}})
	e := New(nil, h)
	for _, c := range []struct {
		addr, dev string
		want      uint32
	}{
		{"203.0.113.10", "eth0", rules.AddrLocal},
		{"203.0.113.10", "eth1", rules.AddrUnicast},
		{"10.20.0.1", "eth1", rules.AddrLocal},
		{"10.20.0.1", "eth0", rules.AddrUnicast},
		{"10.20.0.255", "eth1", rules.AddrBroadcast},
		{"10.20.0.255", "eth0", rules.AddrUnicast},
		{"255.255.255.255", "eth0", rules.AddrBroadcast},
		{"127.0.0.1", "lo", rules.AddrLocal},
		{"127.0.0.1", "eth0", rules.AddrUnicast},
		{"198.51.100.7", "eth0", rules.AddrUnicast},
		{"224.0.0.1", "eth0", rules.AddrMulticast},
		{"203.0.113.10", "nope0", rules.AddrUnicast},
	} {
		if got := e.addrTypeOn(netip.MustParseAddr(c.addr), c.dev); got != c.want {
			t.Errorf("addrTypeOn(%s, %s) = %d, want %d", c.addr, c.dev, got, c.want)
		}
	}
}

func TestUnreadRulesDecideNothing(t *testing.T) {
	h := machine(host.Listener{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 22, Process: "sshd"})
	drop := &rules.Table{Family: "ip", Name: "filter", Chains: map[string]*rules.Chain{
		"INPUT": {Name: "INPUT", Base: true, Hook: rules.HookInput, Type: "filter", Policy: rules.Accept, Rules: []*rules.Rule{
			rule("-p tcp --dport 23 -j DROP", rules.Eq(rules.FL4Proto, rules.Num(6)), rules.Eq(rules.FDport, rules.Num(23)), &rules.Verdict{Kind: rules.Drop}),
		}},
	}, Order: []string{"INPUT"}}
	const why = "The nftables rules could not be read: nft needs root."

	// Nothing unread: the walk decides.
	rs := &rules.Ruleset{Tables: []*rules.Table{drop}}
	if r := Run(rs, h, probe(world, me, 22)); r.Class != Open {
		t.Fatalf("all read: %v, want open", r.Class)
	}

	// Unread for both families: open and filtered both become undecided, each naming what the
	// read rules say first.
	rs.Unread = []rules.Unread{{Why: why}}
	r := Run(rs, h, probe(world, me, 22))
	if r.Class != Undecided || len(r.Possible) != 2 || r.Possible[0] != Open || r.Possible[1] != Filtered {
		t.Errorf("open with unread rules: %v %v", r.Class, r.Possible)
	}
	if len(r.Unknowns) == 0 || r.Unknowns[len(r.Unknowns)-1] != why {
		t.Errorf("the reason is missing: %q", r.Unknowns)
	}
	r = Run(rs, h, probe(world, me, 23))
	if r.Class != Undecided || len(r.Possible) != 2 || r.Possible[0] != Open || r.Possible[1] != Filtered {
		t.Errorf("filtered with unread rules: %v %v", r.Class, r.Possible)
	}
	r = Run(rs, h, probe(world, me, 81))
	if r.Class != Undecided || len(r.Possible) != 2 || r.Possible[0] != Closed || r.Possible[1] != Filtered {
		t.Errorf("closed with unread rules: %v %v", r.Class, r.Possible)
	}

	// Unread for IPv6 only: IPv4 is still decided, IPv6 is not.
	rs.Unread = []rules.Unread{{Family: "ip6", Why: why}}
	if r := Run(rs, h, probe(world, me, 22)); r.Class != Open || len(r.Unknowns) != 0 {
		t.Errorf("IPv4 with only IPv6 unread: %v %q", r.Class, r.Unknowns)
	}
	if r := Run(rs, h, probe("2001:db8:99::7", "2001:db8:1::10", 22)); r.Class != Undecided {
		t.Errorf("IPv6 with IPv6 unread: %v", r.Class)
	}
}
