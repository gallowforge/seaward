package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

const (
	maxDepth    = 64  // chains nested by jumps
	maxBranches = 128 // ways through the conditions the model cannot decide
)

// Run walks one probe through a ruleset on a machine.
func Run(rs *rules.Ruleset, h *host.Host, p Probe) Result {
	return New(rs, h).Run(p)
}

// Run walks one probe. Where a condition cannot be decided it walks both answers; the result
// stands when every way through ends the same.
//
// When some of the machine's rules for the packet's family could not be read, nothing is decided:
// a rule nobody read may stop a packet the known rules let through, or send one they stop
// somewhere else first.
func (e *Engine) Run(p Probe) Result {
	r := e.run(p)
	fam := "ip"
	if p.Dst.Unmap().Is6() {
		fam = "ip6"
	}
	var unread []string
	for _, u := range e.rs.Unread {
		if u.Family == "" || u.Family == fam {
			unread = append(unread, u.Why)
		}
	}
	if len(unread) == 0 {
		return r
	}
	switch r.Class {
	case Undecided:
	case Filtered, Rejected:
		r.Possible = []Class{Open, r.Class}
		r.Class = Undecided
	default:
		r.Possible = []Class{r.Class, Filtered}
		r.Class = Undecided
	}
	r.Unknowns = append(append([]string(nil), r.Unknowns...), unread...)
	return r
}

func (e *Engine) run(p Probe) Result {
	var all []Result
	var whys []string
	seen := map[string]bool{}
	var choices []bool
	for {
		if len(all) >= maxBranches {
			return Result{
				Class:    Undecided,
				Steps:    all[0].Steps,
				Unknowns: append(whys, "there are more conditions the model cannot decide than it will follow"),
				Possible: classes(all),
			}
		}
		w := &walker{e: e, choices: choices, memo: map[any]bool{}}
		all = append(all, w.walk(p))
		for _, y := range w.whys {
			if !seen[y] {
				seen[y] = true
				whys = append(whys, y)
			}
		}
		// The next way through: flip the last question that was answered yes.
		choices = w.choices
		i := len(choices) - 1
		for i >= 0 && !choices[i] {
			i--
		}
		if i < 0 {
			break
		}
		choices = append([]bool(nil), choices[:i+1]...)
		choices[i] = false
	}
	first := all[0]
	same := first.Class != Undecided
	for _, r := range all[1:] {
		if r.Class != first.Class || r.Listener != first.Listener || r.Container != first.Container ||
			r.FinalDst != first.FinalDst || r.FinalPort != first.FinalPort {
			same = false
		}
	}
	if same {
		first.Unknowns = whys
		return first
	}
	return Result{
		Class:     Undecided,
		Steps:     first.Steps,
		FinalDst:  first.FinalDst,
		FinalPort: first.FinalPort,
		Unknowns:  whys,
		Possible:  classes(all),
	}
}

func classes(all []Result) []Class {
	seen := map[Class]bool{}
	var out []Class
	for _, r := range all {
		if r.Class != Undecided && !seen[r.Class] {
			seen[r.Class] = true
			out = append(out, r.Class)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// verdict is how a chain, or a whole hook, ended.
type verdict int

const (
	vNone   verdict = iota // nothing decided: the chain ran off its end or returned
	vAccept                // let through
	vDrop
	vReject
	vStop // the walk cannot go on; walker.stop says why
)

// kStop is the rule outcome for a statement the model cannot follow.
const kStop rules.VerdictKind = -1

// pkt is the packet as it travels: rules may rewrite it.
type pkt struct {
	v6         bool
	src, dst   netip.Addr
	proto      uint32
	sport      uint16
	dport      uint16
	iif, oif   string
	mark       uint32
	ctmark     uint32
	origDst    netip.Addr
	origDport  uint16
	rewritten  bool // a rule changed the destination
	natDone    bool // a nat chain of the current hook has set up the connection's mapping
	untracked  bool // taken out of connection tracking
	ctSeen     bool // connection tracking has seen the packet
	pastRoute  bool
	localInput bool
}

type walker struct {
	e *Engine
	p pkt

	steps   []Step
	effects int // steps that must stay even when their chain decides nothing

	choices []bool       // answers to the undecidable conditions, in the order they come up
	ci      int          // how many of them have come up
	memo    map[any]bool // one answer per condition per walk
	whys    []string
	stop    string

	hook string
	bc   baseChain
}

// ask answers a condition the model cannot decide. The first time through it says yes; Run flips
// the answers one at a time.
func (w *walker) ask(key any, why string) bool {
	if v, ok := w.memo[key]; ok {
		return v
	}
	if w.ci == len(w.choices) {
		w.choices = append(w.choices, true)
	}
	v := w.choices[w.ci]
	w.ci++
	w.memo[key] = v
	w.whys = append(w.whys, why)
	return v
}

func (w *walker) step(kind StepKind, r *rules.Rule, chain, effect string) {
	s := Step{Kind: kind, Hook: w.hook, Effect: effect}
	if kind == StepRule || kind == StepJump || kind == StepPolicy {
		s.Family, s.Table, s.Chain = w.bc.t.Family, w.bc.t.Name, chain
	}
	if r != nil {
		s.Rule = r.Text
	}
	w.steps = append(w.steps, s)
}

func (w *walker) result(c Class) Result {
	if n := len(w.steps); n > 0 {
		w.steps[n-1].Decisive = true
	}
	r := Result{Class: c, Steps: w.steps, FinalDst: w.p.dst, FinalPort: w.p.dport, Rewritten: w.p.rewritten}
	if c == Undecided {
		r.Unknowns = []string{w.stop}
		w.whys = append(w.whys, w.stop)
	}
	return r
}

func (w *walker) end(v verdict) Result {
	switch v {
	case vDrop:
		return w.result(Filtered)
	case vReject:
		return w.result(Rejected)
	}
	if w.stop == "" {
		w.stop = "the walk ended in a way the model does not know"
	}
	return w.result(Undecided)
}

func (w *walker) halt(why string) verdict {
	w.stop = why
	return vStop
}

func protoNum(name string) (uint32, bool) {
	switch name {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "sctp":
		return 132, true
	case "dccp":
		return 33, true
	case "udplite":
		return 136, true
	}
	return 0, false
}

func protoName(n uint32) string {
	switch n {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 132:
		return "sctp"
	case 33:
		return "dccp"
	case 136:
		return "udplite"
	}
	return fmt.Sprint(n)
}

func hostPort(a netip.Addr, port uint16) string {
	return netip.AddrPortFrom(a, port).String()
}

func (w *walker) walk(pr Probe) Result {
	e := w.e
	p := &w.p
	p.src, p.dst = pr.Src.Unmap(), pr.Dst.Unmap()
	p.v6 = p.dst.Is6()
	p.sport, p.dport = pr.Sport, pr.Dport
	if p.sport == 0 {
		p.sport = 40000
	}
	p.iif = pr.Iif
	p.origDst, p.origDport = p.dst, p.dport
	var ok bool
	if p.proto, ok = protoNum(pr.Proto); !ok {
		w.stop = "the model does not follow the protocol " + pr.Proto
		return w.result(Undecided)
	}
	if !p.src.IsValid() || !p.dst.IsValid() || p.src.Is6() != p.v6 {
		w.stop = "the probe has no usable source and destination address"
		return w.result(Undecided)
	}
	if p.iif == "" {
		if p.iif, ok = e.IifFor(p.src); !ok {
			w.stop = "this machine has no route to " + p.src.String() + ", so the interface its packets arrive on is not known"
			return w.result(Undecided)
		}
	}

	if v := w.runHook(rules.HookPrerouting); v != vAccept {
		return w.end(v)
	}
	p.ctSeen = true
	p.pastRoute = true

	// The routing decision.
	w.hook = "route"
	switch t := e.addrType(p.dst); t {
	case rules.AddrLocal, rules.AddrBroadcast:
		in := e.ifs[p.iif]
		fromOutside := in == nil || !in.Loopback
		if fromOutside && (p.dst.IsLoopback() || (p.dst.Is4() && loop4.Contains(p.dst))) {
			if p.v6 || !(e.h.RouteLocalnet[p.iif] || e.h.RouteLocalnet["all"]) {
				w.step(StepRoute, nil, "", "dropped by the kernel: "+p.dst.String()+" is a loopback address and the packet came from outside")
				return w.result(Filtered)
			}
		}
		p.localInput = true
		w.step(StepRoute, nil, "", "for this machine: "+p.dst.String()+" is one of its own addresses")
		if v := w.runHook(rules.HookInput); v != vAccept {
			return w.end(v)
		}
		return w.deliverLocal()
	case rules.AddrMulticast:
		w.stop = "delivery to the multicast address " + p.dst.String() + " is not modelled"
		return w.result(Undecided)
	case rules.AddrBlackhole, rules.AddrUnreachable:
		w.step(StepRoute, nil, "", "dropped: the route for "+p.dst.String()+" throws packets away")
		return w.result(Filtered)
	case rules.AddrProhibit:
		w.step(StepRoute, nil, "", "refused: the route for "+p.dst.String()+" is marked prohibited")
		return w.result(Rejected)
	}
	fwd := e.h.Forward4
	knob := "net.ipv4.ip_forward"
	if p.v6 {
		fwd, knob = e.h.Forward6, "net.ipv6.conf.all.forwarding"
	}
	if !fwd {
		w.step(StepRoute, nil, "", "dropped: "+p.dst.String()+" is another machine and this one does not forward packets ("+knob+" is off)")
		return w.result(Filtered)
	}
	r, ok := e.route(p.dst)
	if !ok || r.Dev == "" {
		w.step(StepRoute, nil, "", "dropped: there is no route to "+p.dst.String())
		return w.result(Filtered)
	}
	p.oif = r.Dev
	w.step(StepRoute, nil, "", "forwarded: "+p.dst.String()+" is reached through "+r.Dev)
	if v := w.runHook(rules.HookForward); v != vAccept {
		return w.end(v)
	}
	if v := w.runHook(rules.HookPostrouting); v != vAccept {
		return w.end(v)
	}
	return w.deliverForward()
}

// sees reports whether a table handles this packet's IP version.
func (w *walker) sees(t *rules.Table) bool {
	switch t.Family {
	case "ip":
		return !w.p.v6
	case "ip6":
		return w.p.v6
	case "inet":
		return true
	}
	return false
}

// runHook runs every base chain of a hook. vAccept means the packet is through.
func (w *walker) runHook(hook string) verdict {
	p := &w.p
	w.hook = hook
	p.natDone = false
	for _, bc := range w.e.hooks[hook] {
		if !w.sees(bc.t) {
			continue
		}
		if hook == rules.HookPrerouting && bc.eff > prioConntrack {
			p.ctSeen = true
		}
		nat := bc.c.Type == "nat"
		if nat && (p.untracked || p.natDone) {
			continue
		}
		w.bc = bc
		v := w.chain(bc.c, 0)
		switch v {
		case vStop, vDrop, vReject:
			return v
		case vNone:
			if bc.c.Policy == rules.Drop {
				w.step(StepPolicy, nil, bc.c.Name, "policy drop: no rule let it through")
				return vDrop
			}
			if !nat && (hook == rules.HookInput || hook == rules.HookForward) {
				w.step(StepPolicy, nil, bc.c.Name, "policy accept: no rule stopped it")
			}
		}
	}
	return vAccept
}

// chain runs one chain. vNone means it decided nothing.
func (w *walker) chain(c *rules.Chain, depth int) verdict {
	if depth > maxDepth {
		return w.halt("the chains of table " + w.bc.t.Name + " jump into each other deeper than the model follows")
	}
	for _, r := range c.Rules {
		k, target := w.rule(c, r)
		switch k {
		case rules.Accept:
			return vAccept
		case rules.Drop:
			return vDrop
		case rules.Reject:
			return vReject
		case rules.Return:
			return vNone
		case kStop:
			return vStop
		case rules.Jump, rules.Goto:
			next := w.bc.t.Chains[target]
			if next == nil {
				return w.halt("a rule in chain " + c.Name + " jumps to chain " + target + ", which is not in the ruleset")
			}
			mark, eff := len(w.steps), w.effects
			w.step(StepJump, r, c.Name, "to chain "+target)
			if v := w.chain(next, depth+1); v != vNone {
				return v
			}
			if w.effects == eff {
				w.steps = w.steps[:mark]
			}
			if k == rules.Goto {
				return vNone
			}
		}
	}
	return vNone
}

// rule runs one rule. A zero kind means the rule did not end the chain.
func (w *walker) rule(c *rules.Chain, r *rules.Rule) (rules.VerdictKind, string) {
	p := &w.p
	nat := w.bc.c.Type == "nat"
	for _, x := range r.Exprs {
		switch x := x.(type) {
		case *rules.Match:
			ok, why := w.match(x)
			if why != "" {
				ok = w.ask(x, why)
			}
			if !ok {
				return 0, ""
			}
		case *rules.Unknown:
			if !w.ask(x, x.Why) {
				return 0, ""
			}
		case *rules.Always, *rules.Noop:
		case *rules.Never:
			return 0, ""
		case *rules.Notrack:
			if !p.ctSeen && !p.untracked {
				p.untracked = true
				w.step(StepRule, r, c.Name, "taken out of connection tracking: no address rewriting applies")
				w.effects++
			}
		case *rules.Verdict:
			if k, target, done := w.verdict(c, r, *x, nat); done {
				return k, target
			}
		case *rules.VerdictMap:
			v, found, why := w.vmap(x)
			if why != "" {
				return w.unfollowed(c, r, why)
			}
			if !found {
				return 0, "" // no entry for this packet: the rule ends here, as a failed match would
			}
			if k, target, done := w.verdict(c, r, v, nat); done {
				return k, target
			}
		case *rules.DNAT:
			if !nat || p.pastRoute {
				continue
			}
			to, port := p.dst, p.dport
			if x.Addr.IsValid() {
				if x.Addr.Unmap().Is6() != p.v6 {
					continue
				}
				to = x.Addr.Unmap()
			}
			if x.Port != 0 {
				port = x.Port
			}
			w.rewrite(c, r, to, port)
			return rules.Accept, ""
		case *rules.Redirect:
			if !nat || p.pastRoute {
				continue
			}
			to, ok := w.e.firstAddr(p.iif, p.v6)
			if !ok {
				w.step(StepRule, r, c.Name, "drop: redirect has no address to use on "+p.iif)
				return rules.Drop, ""
			}
			port := p.dport
			if x.Port != 0 {
				port = x.Port
			}
			w.rewrite(c, r, to, port)
			return rules.Accept, ""
		case *rules.SetMark:
			if x.Ct {
				p.ctmark = (p.ctmark & x.And) ^ x.Xor
			} else {
				p.mark = (p.mark & x.And) ^ x.Xor
			}
		case *rules.CopyMark:
			if x.ToCt {
				p.ctmark = (p.ctmark &^ x.Mask) | (p.mark & x.Mask)
			} else {
				p.mark = (p.mark &^ x.Mask) | (p.ctmark & x.Mask)
			}
		case *rules.UnknownStmt:
			return w.unfollowed(c, r, x.Why)
		}
	}
	return 0, ""
}

func (w *walker) unfollowed(c *rules.Chain, r *rules.Rule, why string) (rules.VerdictKind, string) {
	w.step(StepRule, r, c.Name, "cannot be followed: "+why)
	w.stop = why
	return kStop, ""
}

// verdict applies a verdict statement. done is false for "continue", which only ends the rule's
// say in the matter.
func (w *walker) verdict(c *rules.Chain, r *rules.Rule, v rules.Verdict, nat bool) (rules.VerdictKind, string, bool) {
	switch v.Kind {
	case rules.Accept:
		if !nat {
			w.step(StepRule, r, c.Name, "accept")
		}
	case rules.Drop:
		w.step(StepRule, r, c.Name, "drop")
	case rules.Reject:
		w.step(StepRule, r, c.Name, "reject: the sender is told")
	case rules.Continue:
		return 0, "", false // on with the rest of the rule; as its last word, on to the next rule
	case rules.Return, rules.Jump, rules.Goto:
	default:
		return 0, "", false
	}
	return v.Kind, v.Chain, true
}

func (w *walker) rewrite(c *rules.Chain, r *rules.Rule, to netip.Addr, port uint16) {
	p := &w.p
	p.natDone = true
	if to != p.dst || port != p.dport {
		p.dst, p.dport = to, port
		p.rewritten = true
	}
	w.step(StepRule, r, c.Name, "destination becomes "+hostPort(to, port))
	w.effects++
}

// value is one field of the packet.
type value struct {
	kind int
	a    netip.Addr
	n    uint32
	s    string
}

const (
	kAddr = iota + 1
	kNum
	kStr
)

// field reads a field of the packet. ok is false when the packet has no such field.
func (w *walker) field(f rules.Field) (value, bool) {
	p := &w.p
	num := func(n uint32) (value, bool) {
		if f.HasMask {
			n &= f.Mask
		}
		return value{kind: kNum, n: n}, true
	}
	flag := func(b bool) (value, bool) {
		if b {
			return num(1)
		}
		return num(0)
	}
	tracked := p.ctSeen && !p.untracked
	switch f.Name {
	case rules.FSaddr:
		return value{kind: kAddr, a: p.src}, true
	case rules.FDaddr:
		return value{kind: kAddr, a: p.dst}, true
	case rules.FSport:
		return num(uint32(p.sport))
	case rules.FDport:
		return num(uint32(p.dport))
	case rules.FL4Proto:
		return num(p.proto)
	case rules.FNFProto:
		if p.v6 {
			return num(6)
		}
		return num(4)
	case rules.FIifName:
		return value{kind: kStr, s: p.iif}, true
	case rules.FOifName:
		return value{kind: kStr, s: p.oif}, true
	case rules.FMark:
		return num(p.mark)
	case rules.FCtMark:
		if !tracked {
			return value{}, false
		}
		return num(p.ctmark)
	case rules.FCtState:
		switch {
		case p.untracked:
			return num(rules.CtUntracked)
		case !p.ctSeen:
			return num(rules.CtInvalid)
		}
		return num(rules.CtNew)
	case rules.FCtStatusDNAT:
		if !tracked {
			return value{}, false
		}
		return flag(p.rewritten)
	case rules.FCtStatusSNAT:
		if !tracked {
			return value{}, false
		}
		return num(0)
	case rules.FCtOrigDaddr:
		if !tracked {
			return value{}, false
		}
		return value{kind: kAddr, a: p.origDst}, true
	case rules.FCtOrigDport:
		if !tracked {
			return value{}, false
		}
		return num(uint32(p.origDport))
	case rules.FCtDirection:
		if !tracked {
			return value{}, false
		}
		return num(0)
	case rules.FFibDaddrType:
		return num(w.e.addrType(p.dst))
	case rules.FFibSaddrType:
		return num(w.e.addrType(p.src))
	case rules.FFibDaddrTypeIif:
		return num(w.e.addrTypeOn(p.dst, p.iif))
	case rules.FFibSaddrTypeIif:
		return num(w.e.addrTypeOn(p.src, p.iif))
	case rules.FRpfOK:
		dev, ok := w.e.IifFor(p.src)
		return flag(ok && dev == p.iif)
	case rules.FPktType:
		switch w.e.addrType(p.origDst) {
		case rules.AddrBroadcast:
			return num(rules.PktBroadcast)
		case rules.AddrMulticast:
			return num(rules.PktMulticast)
		}
		return num(rules.PktHost)
	case rules.FTCPFlags:
		if p.proto != 6 {
			return value{}, false
		}
		return num(2) // SYN
	case rules.FIPSecIn:
		return num(0)
	}
	// ICMP fields: a probe is never ICMP.
	return value{}, false
}

// holds reports whether an atom holds a value. comparable is false when they are different kinds
// of thing, such as an IPv4 network and an IPv6 address.
func holds(a rules.Atom, v value) (has, comparable bool) {
	switch a.Kind {
	case rules.AtomAny:
		return true, true
	case rules.AtomPrefix:
		if v.kind != kAddr || !a.Prefix.IsValid() || a.Prefix.Addr().Is4() != v.a.Is4() {
			return false, false
		}
		return a.Prefix.Contains(v.a), true
	case rules.AtomRange:
		if v.kind != kAddr || !a.AddrLo.IsValid() || !a.AddrHi.IsValid() || a.AddrLo.Is4() != v.a.Is4() {
			return false, false
		}
		return a.AddrLo.Compare(v.a) <= 0 && v.a.Compare(a.AddrHi) <= 0, true
	case rules.AtomNum:
		if v.kind != kNum {
			return false, false
		}
		return a.Lo <= v.n && v.n <= a.Hi, true
	case rules.AtomStr:
		if v.kind != kStr {
			return false, false
		}
		return a.S == v.s, true
	case rules.AtomStrPfx:
		if v.kind != kStr {
			return false, false
		}
		return strings.HasPrefix(v.s, a.S), true
	}
	return false, false
}

// find looks a key up among elements. foreign is true when there were elements and none of them
// could be compared with the key at all: the rule is about the other IP version.
func find(elems []rules.Elem, key []value) (idx int, foreign bool) {
	foreign = len(elems) > 0
	for i, el := range elems {
		if len(el) != len(key) {
			continue
		}
		all, cmp := true, true
		for j, a := range el {
			has, ok := holds(a, key[j])
			if !ok {
				cmp = false
			}
			if !has {
				all = false
			}
		}
		if cmp {
			foreign = false
		}
		if all && cmp {
			return i, false
		}
	}
	return -1, foreign
}

func (w *walker) key(fields []rules.Field) ([]value, bool) {
	key := make([]value, len(fields))
	for i, f := range fields {
		v, ok := w.field(f)
		if !ok {
			return nil, false
		}
		key[i] = v
	}
	return key, true
}

// match decides a match. A non-empty why means it cannot be decided.
func (w *walker) match(m *rules.Match) (ok bool, why string) {
	set := m.Values
	if set == nil {
		if set = w.e.rs.Sets[m.SetRef]; set == nil {
			return false, "the set " + setName(m.SetRef) + " is not in the snapshot"
		}
	}
	key, have := w.key(m.Key)
	if !have {
		return false, ""
	}
	i, foreign := find(set.Elems, key)
	if foreign {
		return false, ""
	}
	if set.Incomplete {
		if set.Why != "" {
			return false, set.Why
		}
		return false, "the contents of the set " + set.Name + " could not be read"
	}
	return (i >= 0) != m.Neg, ""
}

// vmap looks the packet up in a verdict map.
func (w *walker) vmap(m *rules.VerdictMap) (v rules.Verdict, found bool, why string) {
	key, have := w.key(m.Key)
	if !have {
		return v, false, ""
	}
	if m.SetRef == "" {
		elems := make([]rules.Elem, len(m.Entries))
		for i, en := range m.Entries {
			elems[i] = en.Key
		}
		if i, _ := find(elems, key); i >= 0 {
			return m.Entries[i].Verdict, true, ""
		}
		return v, false, ""
	}
	set := w.e.rs.Sets[m.SetRef]
	switch {
	case set == nil:
		return v, false, "the verdict map " + setName(m.SetRef) + " is not in the snapshot"
	case set.Incomplete:
		if set.Why != "" {
			return v, false, set.Why
		}
		return v, false, "the contents of the verdict map " + set.Name + " could not be read"
	}
	if i, _ := find(set.Elems, key); i >= 0 {
		if i >= len(set.Verdicts) {
			return v, false, "the verdict map " + set.Name + " has an entry without a verdict"
		}
		return set.Verdicts[i], true, ""
	}
	return v, false, ""
}

// socket finds the listening socket a packet is handed to in a network namespace ("" is the
// machine itself). A socket bound to the exact address wins over one bound to every address.
func (e *Engine) socket(ns string, p *pkt) *host.Listener {
	name := protoName(p.proto)
	var wild *host.Listener
	for _, l := range e.socks[ns] {
		if l.Proto != name || l.Port != p.dport {
			continue
		}
		if ns == "" && l.Dev != "" && l.Dev != p.iif {
			continue
		}
		a := l.Addr.Unmap().WithZone("")
		switch {
		case !a.IsValid():
			if wild == nil {
				wild = l
			}
		case a == p.dst:
			return l
		case a.IsUnspecified():
			if a.Is4() != p.v6 || (a.Is6() && !p.v6 && l.DualStack) {
				if wild == nil {
					wild = l
				}
			}
		}
	}
	return wild
}

func who(l *host.Listener) string {
	if l.Process != "" {
		return l.Process
	}
	return "a program"
}

func (w *walker) deliverLocal() Result {
	p := &w.p
	w.hook = "deliver"
	if w.e.h.NoListenerData {
		w.stop = "the list of listening programs is not in the snapshot"
		return w.result(Undecided)
	}
	l := w.e.socket("", p)
	if l == nil {
		w.step(StepDeliver, nil, "", "nothing is listening on "+protoName(p.proto)+" port "+fmt.Sprint(p.dport)+" at "+p.dst.String())
		return w.result(Closed)
	}
	w.step(StepDeliver, nil, "", who(l)+" is listening on "+hostPort(l.Addr, l.Port))
	r := w.result(Open)
	r.Listener = l
	return r
}

func (w *walker) deliverForward() Result {
	p := &w.p
	w.hook = "deliver"
	c := w.e.ctr[p.dst]
	if c == nil {
		w.step(StepDeliver, nil, "", "handed on to "+hostPort(p.dst, p.dport)+" through "+p.oif)
		return w.result(Forwarded)
	}
	if _, looked := w.e.socks[c.ID]; !looked {
		w.step(StepDeliver, nil, "", "handed to container "+c.Name+" at "+hostPort(p.dst, p.dport)+"; what listens inside it was not captured")
		r := w.result(Forwarded)
		r.Container = c
		return r
	}
	l := w.e.socket(c.ID, p)
	if l == nil {
		w.step(StepDeliver, nil, "", "handed to container "+c.Name+", where nothing is listening on "+protoName(p.proto)+" port "+fmt.Sprint(p.dport))
		r := w.result(Closed)
		r.Container = c
		return r
	}
	w.step(StepDeliver, nil, "", "handed to container "+c.Name+", where "+who(l)+" is listening on port "+fmt.Sprint(l.Port))
	r := w.result(Open)
	r.Listener, r.Container = l, c
	return r
}
