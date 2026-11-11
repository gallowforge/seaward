package scan

import (
	"encoding/binary"
	"slices"

	"github.com/gallowforge/seaward/internal/rules"
)

// A port nothing listens on still answers when a rule sends its packets somewhere else. Which
// ports those are is worked out here, by going the way a packet goes: from every base chain it
// passes before routing, rule by rule, into every chain a rule jumps to, as far as each statement
// that rewrites the destination. What is known of the packet on that way, which ports it may have
// been sent to, is carried along. A statement that rewrites is often not in the rule that names
// the port: Kubernetes and firewalld both match the port in one chain and rewrite in another.

// portSet is a set of destination ports: ranges that do not overlap, in ascending order.
type portSet [][2]uint16

// allPorts is every port a packet can be sent to.
var allPorts = portSet{{1, 65535}}

// ports makes a set of ranges as they come. Ranges that overlap are run together; ranges that
// only touch are kept apart, so a rule that names its ports one by one is asked about them one
// by one.
func ports(spans [][2]uint16) portSet {
	out := make(portSet, 0, len(spans))
	for _, s := range spans {
		if s[0] == 0 {
			s[0] = 1
		}
		if s[1] >= s[0] {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(x, y [2]uint16) int {
		if x[0] != y[0] {
			return int(x[0]) - int(y[0])
		}
		return int(x[1]) - int(y[1])
	})
	n := 0
	for _, s := range out {
		if n > 0 && s[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], s[1])
			continue
		}
		out[n] = s
		n++
	}
	return out[:n]
}

// and is the ports that are in both sets.
func (a portSet) and(b portSet) portSet {
	var out portSet
	for i, j := 0, 0; i < len(a) && j < len(b); {
		lo, hi := max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
		if lo <= hi {
			out = append(out, [2]uint16{lo, hi})
		}
		if a[i][1] < b[j][1] {
			i++
		} else {
			j++
		}
	}
	return out
}

// way is what is known of a packet that has come as far as some point of the rules: whether it
// may be tcp, whether it may be udp, and which ports it may have been sent to. It is never
// narrower than the truth: a condition this cannot read narrows nothing, and neither does one
// that is false for the first packet of a connection and true for a later one (a port opened by
// knocking). A port asked about for nothing costs a line; a port not asked about is missing.
type way struct {
	tcp, udp bool
	ports    portSet
}

func (w way) empty() bool { return (!w.tcp && !w.udp) || len(w.ports) == 0 }

func (w way) key() string {
	k := make([]byte, 0, 1+4*len(w.ports))
	k = append(k, byte(btoi(w.tcp)|btoi(w.udp)<<1))
	for _, s := range w.ports {
		k = binary.LittleEndian.AppendUint16(binary.LittleEndian.AppendUint16(k, s[0]), s[1])
	}
	return string(k)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// narrowBy is the way of a packet that an element of a set with these key fields holds.
func narrowBy(w way, key []rules.Field, elems []rules.Elem) way {
	for idx, f := range key {
		if f.HasMask {
			continue
		}
		switch f.Name {
		case rules.FDport, rules.FCtOrigDport:
			// Before a rewrite the port a packet has and the port it was sent to are the same.
			var spans [][2]uint16
			any := false
			for _, el := range elems {
				if idx >= len(el) || el[idx].Kind != rules.AtomNum {
					any = true // a wildcard, or nothing this reads as a port
					break
				}
				spans = append(spans, [2]uint16{uint16(min(el[idx].Lo, 65535)), uint16(min(el[idx].Hi, 65535))})
			}
			if !any {
				w.ports = w.ports.and(ports(spans))
			}
		case rules.FL4Proto:
			tcp, udp, any := false, false, false
			for _, el := range elems {
				if idx >= len(el) || el[idx].Kind != rules.AtomNum {
					any = true
					break
				}
				tcp = tcp || (el[idx].Lo <= 6 && 6 <= el[idx].Hi)
				udp = udp || (el[idx].Lo <= 17 && 17 <= el[idx].Hi)
			}
			if !any {
				w.tcp, w.udp = w.tcp && tcp, w.udp && udp
			}
		}
	}
	return w
}

// narrow is the way of a packet that passes a match. A match that says "not", one that looks
// into a set this cannot read, and one that looks into a set the rules fill themselves as
// packets come narrow nothing: the packets that pass them are not known, or not for long.
func (b *builder) narrow(w way, m *rules.Match) way {
	set := m.Values
	if set == nil {
		set = b.rs.Sets[m.SetRef]
	}
	if m.Neg || set == nil || set.Incomplete || set.Dynamic {
		return w
	}
	return narrowBy(w, m.Key, set.Elems)
}

const (
	// As deep as the engine follows chains that jump into each other.
	rewriteDepth = 64
	// How many rules are looked at before the search gives up. A machine with ten thousand
	// published services has a few rules in a few chains for each and stays far below this;
	// what goes beyond it is chains of overlapping port ranges that call each other.
	rewriteSteps = 1 << 20
)

// rewriteSearch goes through one table from its base chains.
type rewriteSearch struct {
	b     *builder
	t     *rules.Table
	seen  map[string]bool // a chain entered with a way: once is enough
	open  map[string]bool // the chains the search is inside of right now, each with its way
	steps *int
	found *[]way
	lost  *bool // the search gave up somewhere, so it did not see every way
}

func (s *rewriteSearch) chain(name string, w way, depth int) {
	if w.empty() || *s.lost {
		return
	}
	c := s.t.Chains[name]
	if c == nil {
		// The engine cannot follow a jump to a chain it does not have; whatever the packets on
		// this way do, they are worth asking about.
		*s.found = append(*s.found, w)
		return
	}
	if depth > rewriteDepth || *s.steps >= rewriteSteps {
		*s.lost = true
		return
	}
	key := name + "\x00" + w.key()
	if s.open[key] {
		// Chains that jump in a circle. The kernel loads no such rules; the engine follows a
		// listing that has them until it is too deep and decides nothing, which is worth a row.
		*s.found = append(*s.found, w)
		return
	}
	if s.seen[key] {
		return
	}
	s.seen[key], s.open[key] = true, true
	defer delete(s.open, key)
	for _, r := range c.Rules {
		if *s.steps++; *s.steps > rewriteSteps {
			*s.lost = true
			return
		}
		cur := w
		for _, x := range r.Exprs {
			switch x := x.(type) {
			case *rules.Match:
				cur = s.b.narrow(cur, x)
			case *rules.DNAT, *rules.Redirect, *rules.UnknownStmt:
				// A rewrite, or a statement the engine cannot follow: before routing that may be
				// one too (TPROXY, a dnat with a target this cannot read).
				*s.found = append(*s.found, cur)
			case *rules.Verdict:
				if x.Kind == rules.Jump || x.Kind == rules.Goto {
					s.chain(x.Chain, cur, depth+1)
				}
			case *rules.VerdictMap:
				s.vmap(x, cur, depth)
			}
			if cur.empty() {
				break
			}
		}
	}
}

// vmap follows every entry of a verdict map that leads into another chain, each with the way
// narrowed to what the entry holds.
func (s *rewriteSearch) vmap(m *rules.VerdictMap, w way, depth int) {
	follow := func(el rules.Elem, v rules.Verdict) {
		if v.Kind == rules.Jump || v.Kind == rules.Goto {
			s.chain(v.Chain, narrowBy(w, m.Key, []rules.Elem{el}), depth+1)
		}
	}
	if m.SetRef == "" {
		for _, en := range m.Entries {
			follow(en.Key, en.Verdict)
		}
		return
	}
	set := s.b.rs.Sets[m.SetRef]
	if set == nil || set.Incomplete {
		// The engine stops at a map it cannot read: where its entries lead is not known.
		*s.found = append(*s.found, w)
		return
	}
	for i, el := range set.Elems {
		if i < len(set.Verdicts) {
			follow(el, set.Verdicts[i])
		}
	}
}

// rewritten lists the ways on which a packet from outside can reach a statement that sends it
// somewhere else. lost is true when the rules were too tangled to go through: then every port
// may be one of them.
func (b *builder) rewritten() (found []way, lost bool) {
	steps := 0
	for _, t := range b.rs.Tables {
		s := &rewriteSearch{b: b, t: t, seen: map[string]bool{}, open: map[string]bool{}, steps: &steps, found: &found, lost: &lost}
		for _, name := range t.Order {
			c := t.Chains[name]
			// A destination can only change before the routing decision: on arrival and in
			// prerouting. That is where the engine applies a rewrite, too.
			if c == nil || !c.Base || (c.Hook != rules.HookIngress && c.Hook != rules.HookPrerouting) {
				continue
			}
			s.chain(name, way{tcp: true, udp: true, ports: allPorts}, 0)
		}
	}
	return found, lost
}
