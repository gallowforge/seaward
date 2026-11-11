package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// The settle step takes iptables-save's word for a rule it judges "plain": one written entirely
// the way iptables-nft writes rules itself. That is only safe when both listings say the same
// thing about such a rule, which is what this file checks, rule by rule, for every plain rule of
// the fixtures that iptables had a hand in.

// plainPair is one plain rule in its two readings.
type plainPair struct {
	where    string // fixture, table and chain
	family   string
	users    []string // the table's chains without a hook, so that jumps have somewhere to go
	fromJSON *rules.Rule
	fromSave *rules.Rule
}

// plainPairs collects every rule of a fixture that plainRule says yes to.
func plainPairs(t *testing.T, name string) []plainPair {
	t.Helper()
	p, err := read(readFile(t, name+".json"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var out []plainPair
	for _, sh := range sharedOf(t, name) {
		tb := p.byName[sh.Family+" "+sh.Name]
		if tb == nil {
			for _, x := range p.tables {
				if x.family == sh.Family && x.name == sh.Name {
					tb = x
				}
			}
		}
		if tb == nil {
			continue
		}
		var users []string
		for _, cname := range tb.order {
			if !tb.chains[cname].c.Base {
				users = append(users, cname)
			}
		}
		for _, cname := range tb.order {
			c, sc := tb.chains[cname], sh.Chains[cname]
			if sc == nil || len(sc.Rules) != len(c.raw) {
				t.Errorf("%s: table %s %s chain %s: the two listings do not line up", name, sh.Family, sh.Name, cname)
				continue
			}
			for i, raw := range c.raw {
				if !plainRule(raw.obj().peek("expr").arr()) {
					continue
				}
				got := p.rule(tb, raw)
				if len(got) != 1 {
					t.Errorf("%s: %s: a plain rule became %d rules", name, sc.Rules[i].Text, len(got))
					continue
				}
				out = append(out, plainPair{
					where:    fmt.Sprintf("%s: table %s %s chain %s", name, sh.Family, sh.Name, cname),
					family:   sh.Family,
					users:    users,
					fromJSON: got[0],
					fromSave: sc.Rules[i],
				})
			}
		}
	}
	return out
}

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// labHost is a machine shaped like the kernel lab's: eth0 faces the internet, eth1 an inner
// network, docker0 a container bridge. It forwards, and it listens on tcp 22 and udp 53.
func labHost() *host.Host {
	return &host.Host{
		Name: "harbor",
		Interfaces: []host.Interface{
			{Name: "lo", Up: true, Loopback: true, Addrs: []netip.Prefix{prefix("127.0.0.1/8"), prefix("::1/128")}},
			{Name: "eth0", Up: true, Addrs: []netip.Prefix{prefix("203.0.113.10/24"), prefix("2001:db8:1::10/64")}},
			{Name: "eth1", Up: true, Addrs: []netip.Prefix{prefix("10.20.0.1/24"), prefix("2001:db8:2::1/64")}},
			{Name: "docker0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{prefix("172.17.0.1/16")}},
		},
		Routes: []host.Route{
			{Dst: prefix("0.0.0.0/0"), Dev: "eth0", Gateway: addr("203.0.113.1")},
			{Dst: prefix("203.0.113.0/24"), Dev: "eth0"},
			{Dst: prefix("10.20.0.0/24"), Dev: "eth1"},
			{Dst: prefix("172.17.0.0/16"), Dev: "docker0"},
			{Dst: prefix("::/0"), Dev: "eth0", Gateway: addr("2001:db8:1::1")},
			{Dst: prefix("2001:db8:1::/64"), Dev: "eth0"},
			{Dst: prefix("2001:db8:2::/64"), Dev: "eth1"},
		},
		Forward4: true,
		Forward6: true,
		Listeners: []host.Listener{
			{Proto: "tcp", Addr: addr("::"), DualStack: true, Port: 22, Process: "sshd"},
			{Proto: "udp", Addr: addr("::"), DualStack: true, Port: 53, Process: "resolver"},
		},
	}
}

// spread is the packets one rule is tried with: a fixed handful, plus the edges of everything
// either reading of the rule names (each address, port and mark, and the value just outside it).
type spread struct {
	iifs   []string
	srcs   []netip.Addr
	dsts   []netip.Addr
	protos []string
	sports []uint16
	dports []uint16
	marks  []uint32
}

func (s *spread) addAddr(list *[]netip.Addr, a netip.Addr, v6 bool) {
	if !a.IsValid() || a.Is6() != v6 || a.IsUnspecified() {
		return
	}
	for _, x := range *list {
		if x == a {
			return
		}
	}
	*list = append(*list, a)
}

func addPort(list *[]uint16, n uint32) {
	if n == 0 || n > 65535 {
		return
	}
	for _, x := range *list {
		if uint32(x) == n {
			return
		}
	}
	*list = append(*list, uint16(n))
}

func addWord[T comparable](list *[]T, v T) {
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
}

func lastOf(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

var l4Names = map[uint32]string{6: "tcp", 17: "udp", 33: "dccp", 132: "sctp", 136: "udplite"}

func spreadFor(family string, readings ...*rules.Rule) spread {
	v6 := family == "ip6"
	s := spread{
		iifs:   []string{"eth0", "eth1", "docker0", "lo"},
		protos: []string{"tcp", "udp"},
		sports: []uint16{0, 1023},
		dports: []uint16{22, 53, 81},
		marks:  []uint32{0},
	}
	if v6 {
		s.srcs = []netip.Addr{addr("2001:db8:99::7"), addr("2001:db8:2::5")}
		s.dsts = []netip.Addr{addr("2001:db8:1::10"), addr("2001:db8:2::9"), addr("2001:db8:77::1")}
	} else {
		s.srcs = []netip.Addr{addr("198.51.100.7"), addr("10.20.0.5"), addr("172.17.0.3")}
		s.dsts = []netip.Addr{addr("203.0.113.10"), addr("10.20.0.1"), addr("172.17.0.2"), addr("198.51.100.200"), addr("10.20.0.9")}
	}
	for _, r := range readings {
		for _, x := range r.Exprs {
			m, ok := x.(*rules.Match)
			if !ok || m.Values == nil {
				continue
			}
			for _, el := range m.Values.Elems {
				for i, a := range el {
					if i >= len(m.Key) {
						break
					}
					f := m.Key[i]
					switch f.Name {
					case rules.FSaddr, rules.FDaddr:
						list := &s.srcs
						if f.Name == rules.FDaddr {
							list = &s.dsts
						}
						lo, hi := a.AddrLo, a.AddrHi
						if a.Kind == rules.AtomPrefix {
							lo, hi = a.Prefix.Masked().Addr(), lastOf(a.Prefix.Masked())
						} else if a.Kind != rules.AtomRange {
							continue
						}
						for _, v := range []netip.Addr{lo, hi, lo.Prev(), hi.Next()} {
							s.addAddr(list, v, v6)
						}
					case rules.FSport, rules.FDport:
						list := &s.sports
						if f.Name == rules.FDport {
							list = &s.dports
						}
						for _, v := range []uint32{a.Lo, a.Hi, a.Lo - 1, a.Hi + 1} {
							addPort(list, v)
						}
					case rules.FIifName:
						switch a.Kind {
						case rules.AtomStr:
							addWord(&s.iifs, a.S)
						case rules.AtomStrPfx:
							addWord(&s.iifs, a.S+"0")
							addWord(&s.iifs, a.S+"7")
						}
					case rules.FL4Proto:
						if name := l4Names[a.Lo]; name != "" {
							addWord(&s.protos, name)
						}
					case rules.FMark:
						for _, v := range []uint32{a.Lo, a.Hi, a.Lo + 1, a.Lo | 0x100, a.Lo | 0x80000000} {
							addWord(&s.marks, v)
						}
					}
				}
			}
		}
	}
	return s
}

// harness puts one reading of a rule where a packet meets it on its way in and on its way
// through, in a chain of its own:
//
//	chain in    (hook input):   jump under
//	chain fwd   (hook forward): jump under
//	chain under:                [meta mark set MARK]  THE RULE  reject
//
// so a packet the rule does not match is refused, one it accepts gets through, and one it
// returns meets the policy. A rule that says nothing by itself (a log, a bare match) is given an
// "accept", or whether it matched could not be seen. The table's other chains are there for the
// rule to jump to: either empty or holding a "drop".
func harness(family string, r *rules.Rule, users []string, mark uint32, policy rules.VerdictKind, usersDrop bool) *rules.Ruleset {
	rule := &rules.Rule{Text: "the rule", Exprs: append([]rules.Expr(nil), r.Exprs...)}
	says := false
	for _, x := range rule.Exprs {
		switch x.(type) {
		case *rules.Verdict, *rules.VerdictMap, *rules.DNAT, *rules.Redirect, *rules.UnknownStmt:
			says = true
		}
	}
	if !says {
		rule.Exprs = append(rule.Exprs, &rules.Verdict{Kind: rules.Accept})
	}
	under := &rules.Chain{Name: "under"}
	if mark != 0 {
		under.Rules = append(under.Rules, &rules.Rule{Text: "mark", Exprs: []rules.Expr{&rules.SetMark{And: 0, Xor: mark}}})
	}
	under.Rules = append(under.Rules, rule, &rules.Rule{Text: "reject", Exprs: []rules.Expr{&rules.Verdict{Kind: rules.Reject}}})
	jump := func() []*rules.Rule {
		return []*rules.Rule{{Text: "jump under", Exprs: []rules.Expr{&rules.Verdict{Kind: rules.Jump, Chain: "under"}}}}
	}
	t := &rules.Table{Family: family, Name: "t", Origin: "nft", Chains: map[string]*rules.Chain{
		"in":    {Name: "in", Base: true, Hook: rules.HookInput, Type: "filter", Policy: policy, Rules: jump()},
		"fwd":   {Name: "fwd", Base: true, Hook: rules.HookForward, Type: "filter", Policy: policy, Rules: jump()},
		"under": under,
	}, Order: []string{"in", "fwd", "under"}}
	for _, name := range users {
		if t.Chains[name] != nil {
			continue
		}
		c := &rules.Chain{Name: name}
		if usersDrop {
			c.Rules = []*rules.Rule{{Text: "drop", Exprs: []rules.Expr{&rules.Verdict{Kind: rules.Drop}}}}
		}
		t.Chains[name] = c
		t.Order = append(t.Order, name)
	}
	return &rules.Ruleset{Tables: []*rules.Table{t}, Sets: map[string]*rules.Set{}}
}

// outcome is what the engine said about one packet, without the words that differ between the
// two listings (the unknowns' sentences).
func outcome(r engine.Result) string {
	var b strings.Builder
	b.WriteString(r.Class.String())
	if len(r.Possible) > 0 {
		var ps []string
		for _, c := range r.Possible {
			ps = append(ps, c.String())
		}
		sort.Strings(ps)
		fmt.Fprintf(&b, " (one of %s)", strings.Join(ps, ", "))
	}
	if r.Class != engine.Undecided {
		for _, s := range r.Steps {
			fmt.Fprintf(&b, "; %s %s %s: %s", s.Kind, s.Hook, s.Chain, s.Effect)
		}
	}
	return b.String()
}

// shape is a rule's conditions and verdict with everything that says nothing about a first
// packet taken out (comments, counters, logs, rate limits) and the wording of what cannot be
// decided set aside, in an order that does not depend on how the listing ordered them.
func shape(r *rules.Rule) string {
	var lines []string
	for _, x := range r.Exprs {
		switch x.(type) {
		case *rules.Always, *rules.Noop:
			continue
		case *rules.Never:
			lines = append(lines, "never")
		case *rules.Unknown:
			lines = append(lines, "unknown")
		default:
			lines = append(lines, dumpExpr(x))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// TestPlainRulesReadTheSame: for every rule of the fixtures that the settle step calls plain, the
// reading of the nft listing and the reading of iptables-save say the same thing: the same
// conditions, and the same answer from the engine for every packet of a spread built around the
// rule's own addresses, ports, interfaces and marks.
func TestPlainRulesReadTheSame(t *testing.T) {
	h := labHost()
	total, probes := 0, 0
	classes := map[engine.Class]int{}
	for _, name := range []string{"iptables", "iptables-more", "mixed"} {
		pairs := plainPairs(t, name)
		if len(pairs) < 10 {
			t.Errorf("%s: only %d plain rules found; the fixture should hold many more", name, len(pairs))
		}
		for _, pp := range pairs {
			total++
			if a, b := shape(pp.fromJSON), shape(pp.fromSave); a != b {
				t.Errorf("%s: the two listings read a plain rule differently\n  nft:           %s\n%s\n  iptables-save: %s\n%s",
					pp.where, pp.fromJSON.Text, indent(a), pp.fromSave.Text, indent(b))
				continue
			}
			s := spreadFor(pp.family, pp.fromJSON, pp.fromSave)
			bad := 0
			for _, mark := range s.marks {
				for _, usersDrop := range []bool{false, true} {
					policy := rules.Drop
					if usersDrop {
						policy = rules.Accept
					}
					ej := engine.New(harness(pp.family, pp.fromJSON, pp.users, mark, policy, usersDrop), h)
					es := engine.New(harness(pp.family, pp.fromSave, pp.users, mark, policy, usersDrop), h)
					for _, iif := range s.iifs {
						for _, src := range s.srcs {
							for _, dst := range s.dsts {
								for _, proto := range s.protos {
									for _, sport := range s.sports {
										for _, dport := range s.dports {
											pr := engine.Probe{Iif: iif, Src: src, Dst: dst, Proto: proto, Sport: sport, Dport: dport}
											rj, rsv := ej.Run(pr), es.Run(pr)
											probes++
											classes[rj.Class]++
											if a, b := outcome(rj), outcome(rsv); a != b && bad < 3 {
												bad++
												t.Errorf("%s: %s\n  a %s packet on %s from %s port %d to %s port %d, mark %#x\n  read from the nft listing:  %s\n  read from iptables-save:    %s",
													pp.where, pp.fromSave.Text, proto, iif, src, sport, dst, dport, mark, a, b)
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// The spread has to reach every way a packet can end, or agreement would mean little.
	for _, c := range []engine.Class{engine.Open, engine.Closed, engine.Rejected, engine.Filtered, engine.Forwarded} {
		if classes[c] == 0 {
			t.Errorf("no packet of the spread ended as %s", c)
		}
	}
	if total < 100 {
		t.Errorf("only %d plain rules were compared", total)
	}
	t.Logf("%d plain rules, %d packets", total, probes)
}

func indent(s string) string {
	return "      " + strings.ReplaceAll(s, "\n", "\n      ")
}

// TestPlainRulesAreMatchedWhenTheyShouldBe guards the test above against a spread that never
// meets a rule: for nearly every plain rule some packet must be let through by the rule itself.
func TestPlainRulesAreMatchedWhenTheyShouldBe(t *testing.T) {
	h := labHost()
	total, never := 0, 0
	var missed []string
	for _, name := range []string{"iptables", "iptables-more", "mixed"} {
		for _, pp := range plainPairs(t, name) {
			total++
			s := spreadFor(pp.family, pp.fromJSON, pp.fromSave)
			hit := false
			for _, mark := range s.marks {
				e := engine.New(harness(pp.family, pp.fromJSON, pp.users, mark, rules.Drop, false), h)
				for _, iif := range s.iifs {
					for _, src := range s.srcs {
						for _, dst := range s.dsts {
							for _, proto := range s.protos {
								for _, sport := range s.sports {
									for _, dport := range s.dports {
										r := e.Run(engine.Probe{Iif: iif, Src: src, Dst: dst, Proto: proto, Sport: sport, Dport: dport})
										// Refused means the rule passed the packet on to the "reject" after it.
										if r.Class != engine.Rejected {
											hit = true
										}
									}
								}
							}
						}
					}
				}
			}
			if !hit {
				never++
				missed = append(missed, pp.fromSave.Text)
			}
		}
	}
	// Rules about a protocol a probe cannot be (icmp, esp, gre), about later fragments, or with
	// nothing but a jump to an empty chain are never met; they are the few.
	if never*5 > total {
		t.Errorf("%d of %d plain rules were never matched by any packet of their spread:\n  %s", never, total, strings.Join(missed, "\n  "))
	}
	t.Logf("%d of %d plain rules are met by a packet of their spread; never met: %s", total-never, total, strings.Join(missed, " | "))
}
