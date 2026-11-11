//go:build linux

package lab

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
)

// The random rulesets draw from small pools so that rules and probes often meet.
var (
	genPorts   = []uint16{22, 53, 80, 443, 8080}
	genSrcEth0 = []string{"198.51.100.7", "198.51.100.200", "203.0.113.77"}
	genSrcEth1 = []string{"192.0.2.50"}
	genSrcPfx  = []string{"198.51.100.0/24", "198.51.100.0/25", "198.51.100.7/32", "203.0.113.0/24", "192.0.2.0/24", "10.0.0.0/8"}
	genDstPfx  = []string{"203.0.113.10/32", "10.20.0.0/24", "203.0.113.0/24"}
	genIfaces  = []string{"eth0", "eth1", "eth+"}
	genStates  = []string{"NEW", "ESTABLISHED,RELATED", "INVALID", "NEW,ESTABLISHED", "UNTRACKED"}
	genMarks   = []string{"0x1", "0x2", "0x10"}
	genListen  = []string{"0.0.0.0", "0.0.0.0", "0.0.0.0", "203.0.113.10", "127.0.0.1", "10.20.0.1", "::"}
)

// Generate builds n random iptables scenarios from seed. Scenario i depends only on seed and i,
// so one ruleset can be replayed on its own.
func Generate(seed uint64, n int) []*Scenario {
	out := make([]*Scenario, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, GenerateOne(seed, i))
	}
	return out
}

type gen struct {
	r     *rand.Rand
	marks bool // mangle sets marks, so filter rules may match them
}

func (g *gen) pick(s []string) string { return s[g.r.IntN(len(s))] }
func (g *gen) chance(p float64) bool  { return g.r.Float64() < p }

// GenerateOne builds random scenario i of seed.
func GenerateOne(seed uint64, i int) *Scenario {
	g := &gen{r: rand.New(rand.NewPCG(seed, uint64(i)))}
	sc := &Scenario{
		Name:  fmt.Sprintf("random-%d-%d", seed, i),
		About: "generated",
		Eth1:  true,
		Seed:  seed,
		Index: i,
	}
	var b strings.Builder

	if g.chance(0.25) {
		b.WriteString("*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n")
		for k := g.r.IntN(2) + 1; k > 0; k-- {
			target := "NOTRACK"
			if g.chance(0.4) {
				target = "DROP"
			}
			fmt.Fprintf(&b, "-A PREROUTING%s -j %s\n", g.matches(false), target)
		}
		b.WriteString("COMMIT\n")
	}
	if g.chance(0.5) {
		g.marks = true
		b.WriteString("*mangle\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n")
		for k := g.r.IntN(3) + 1; k > 0; k-- {
			m := g.pick(genMarks)
			if g.chance(0.5) {
				fmt.Fprintf(&b, "-A PREROUTING%s -j MARK --set-xmark %s/0xff\n", g.matches(false), m)
			} else {
				fmt.Fprintf(&b, "-A PREROUTING%s -j MARK --set-mark %s\n", g.matches(false), m)
			}
		}
		if g.chance(0.2) {
			fmt.Fprintf(&b, "-A INPUT%s -j DROP\n", g.matches(false))
		}
		b.WriteString("COMMIT\n")
	}
	if g.chance(0.4) {
		b.WriteString("*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n")
		for k := g.r.IntN(2) + 1; k > 0; k-- {
			proto := g.pick([]string{"tcp", "udp"})
			from := genPorts[g.r.IntN(len(genPorts))]
			to := fmt.Sprint(genPorts[g.r.IntN(len(genPorts))])
			if g.chance(0.3) {
				// A range of ports. The kernel keeps the port the packet came for when it lies
				// in the range, so a range drawn from the same few ports tests both ways.
				i := g.r.IntN(len(genPorts) - 1)
				j := i + 1 + g.r.IntN(len(genPorts)-1-i)
				to = fmt.Sprintf("%d-%d", genPorts[i], genPorts[j])
			}
			cond := ""
			if g.chance(0.3) {
				cond = " -i " + g.pick(genIfaces)
			}
			if g.chance(0.5) {
				fmt.Fprintf(&b, "-A PREROUTING%s -p %s -m %s --dport %d -j REDIRECT --to-ports %s\n", cond, proto, proto, from, to)
			} else {
				fmt.Fprintf(&b, "-A PREROUTING%s -p %s -m %s --dport %d -j DNAT --to-destination %s:%s\n", cond, proto, proto, from, hostEth0v4, to)
			}
		}
		b.WriteString("COMMIT\n")
	}

	// filter: INPUT plus up to three user chains. Chain k jumps only to chains after it, so
	// nothing can loop.
	nUser := g.r.IntN(4)
	policy := g.pick([]string{"ACCEPT", "DROP"})
	b.WriteString("*filter\n")
	fmt.Fprintf(&b, ":INPUT %s [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n", policy)
	for k := 0; k < nUser; k++ {
		fmt.Fprintf(&b, ":U%d - [0:0]\n", k)
	}
	g.chain(&b, "INPUT", -1, nUser)
	for k := 0; k < nUser; k++ {
		g.chain(&b, fmt.Sprintf("U%d", k), k, nUser)
	}
	b.WriteString("COMMIT\n")
	sc.IPTables = b.String()

	// Listeners: at most one socket per protocol and port, so binds never clash.
	for _, proto := range []string{"tcp", "udp"} {
		for _, port := range genPorts {
			if !g.chance(0.45) {
				continue
			}
			a := netip.MustParseAddr(g.pick(genListen))
			sc.Listens = append(sc.Listens, Listen{NS: "host", Proto: proto, Addr: a, Port: port})
		}
	}

	// Probes: every source against every pooled port, both protocols.
	for _, proto := range []string{"tcp", "udp"} {
		for _, port := range genPorts {
			for _, s := range genSrcEth0 {
				sc.Probes = append(sc.Probes, Probe{Iif: "eth0", Src: netip.MustParseAddr(s), Dst: hostEth0v4, Proto: proto, Dport: port})
			}
			for _, s := range genSrcEth1 {
				sc.Probes = append(sc.Probes, Probe{Iif: "eth1", Src: netip.MustParseAddr(s), Dst: hostEth1v4, Proto: proto, Dport: port})
			}
		}
	}
	return sc
}

// chain writes the rules of one filter chain. self is the chain's user index (-1 for INPUT).
func (g *gen) chain(b *strings.Builder, name string, self, nUser int) {
	for k := g.r.IntN(5) + 1; k > 0; k-- {
		var target string
		switch x := g.r.IntN(20); {
		case x < 6:
			target = " -j ACCEPT"
		case x < 10:
			target = " -j DROP"
		case x < 12:
			target = " -j REJECT"
		case x < 13:
			target = " -j REJECT --reject-with icmp-host-prohibited"
		case x < 15:
			target = " -j RETURN"
		case x < 19 && self+1 < nUser:
			to := self + 1 + g.r.IntN(nUser-self-1)
			verb := "-j"
			if g.chance(0.35) {
				verb = "-g"
			}
			target = fmt.Sprintf(" %s U%d", verb, to)
		case x < 19:
			target = " -j ACCEPT"
		default:
			target = "" // a rule with no target only counts
		}
		m := g.matches(true)
		if strings.HasPrefix(target, " -j REJECT") && strings.Contains(m, "-p tcp") && g.chance(0.5) {
			target = " -j REJECT --reject-with tcp-reset"
		}
		fmt.Fprintf(b, "-A %s%s%s\n", name, m, target)
	}
}

// matches writes zero to three random matches. filter is true for the filter table, where
// conntrack state and marks set in mangle may be matched.
func (g *gen) matches(filter bool) string {
	var parts []string
	not := func() string {
		if g.chance(0.2) {
			return "! "
		}
		return ""
	}
	if g.chance(0.3) {
		parts = append(parts, fmt.Sprintf("%s-s %s", not(), g.pick(genSrcPfx)))
	}
	if g.chance(0.1) {
		parts = append(parts, fmt.Sprintf("%s-d %s", not(), g.pick(genDstPfx)))
	}
	if g.chance(0.25) {
		parts = append(parts, fmt.Sprintf("%s-i %s", not(), g.pick(genIfaces)))
	}
	if g.chance(0.6) {
		proto := g.pick([]string{"tcp", "udp"})
		parts = append(parts, "-p "+proto)
		switch x := g.r.IntN(4); x {
		case 0, 1:
			parts = append(parts, fmt.Sprintf("-m %s %s--dport %d", proto, not(), genPorts[g.r.IntN(len(genPorts))]))
		case 2:
			a, c := genPorts[g.r.IntN(len(genPorts))], genPorts[g.r.IntN(len(genPorts))]
			if a == c {
				c = genPorts[(g.r.IntN(len(genPorts)-1)+1+indexOf(genPorts, a))%len(genPorts)]
			}
			parts = append(parts, fmt.Sprintf("-m multiport %s--dports %d,%d", not(), a, c))
		case 3:
			lo := genPorts[g.r.IntN(len(genPorts))]
			parts = append(parts, fmt.Sprintf("-m %s --dport %d:%d", proto, lo-1, lo+100))
		}
	}
	if filter && g.chance(0.25) {
		parts = append(parts, fmt.Sprintf("-m conntrack %s--ctstate %s", not(), g.pick(genStates)))
	}
	if filter && g.marks && g.chance(0.35) {
		if g.chance(0.5) {
			parts = append(parts, fmt.Sprintf("-m mark %s--mark %s/0xff", not(), g.pick(genMarks)))
		} else {
			parts = append(parts, fmt.Sprintf("-m mark %s--mark %s", not(), g.pick(genMarks)))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

func indexOf(s []uint16, v uint16) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return 0
}
