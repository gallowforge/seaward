package nft

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// rule translates one rule of the listing. It gives more than one model rule only for a statement
// that picks one of several targets from a map: one rule per target, each with the same text.
func (p *parser) rule(t *table, n *node) []*rules.Rule {
	o := n.obj()
	c := &ctx{p: p, t: t, nf: map[uint32]bool{}, l4: map[uint32]bool{}, altAt: -1}
	en := o.get("expr")
	exprs := en.arr()
	if !en.isArr() {
		// nft writes every rule as a list of parts, even an empty one.
		c.stop("this rule is not written the way nft writes it")
	}
	for i, e := range exprs {
		c.last = i == len(exprs)-1
		start := len(c.out)
		c.expr(e)
		// Whatever the translation did not look at is something it did not understand.
		if u := e.unread(); u != "" && !hasUnknown(c.out[start:]) {
			kind, _ := e.obj().onePeek()
			why := fmt.Sprintf("this rule holds something seaward does not understand (the word %q in its %s)", clip(u), clip(kind))
			var x rules.Expr = &rules.UnknownStmt{Why: why}
			if kind == "match" {
				x = &rules.Unknown{Why: why}
			}
			c.out = append(c.out[:start], append([]rules.Expr{x}, c.out[start:]...)...)
			if c.altAt >= start {
				c.altAt++
			}
		}
	}
	text := ruleText(o, t.family)
	if c.alts == nil {
		return []*rules.Rule{{Text: text, Exprs: c.out}}
	}
	var out []*rules.Rule
	for _, alt := range c.alts {
		xs := append([]rules.Expr{}, c.out[:c.altAt]...)
		xs = append(xs, alt...)
		xs = append(xs, c.out[c.altAt:]...)
		out = append(out, &rules.Rule{Text: text, Exprs: xs})
	}
	return out
}

func hasUnknown(xs []rules.Expr) bool {
	for _, x := range xs {
		switch x.(type) {
		case *rules.Unknown, *rules.UnknownStmt:
			return true
		}
	}
	return false
}

// verdictOf reads a verdict: {"accept": null}, {"jump": {"target": "chain"}}.
func verdictOf(n *node) (rules.Verdict, bool) {
	key, v := n.obj().one()
	switch key {
	case "accept":
		return rules.Verdict{Kind: rules.Accept}, true
	case "drop":
		return rules.Verdict{Kind: rules.Drop}, true
	case "return":
		return rules.Verdict{Kind: rules.Return}, true
	case "continue":
		return rules.Verdict{Kind: rules.Continue}, true
	case "jump", "goto":
		target, ok := v.obj().get("target").str()
		if !ok {
			return rules.Verdict{}, false
		}
		if key == "jump" {
			return rules.Verdict{Kind: rules.Jump, Chain: target}, true
		}
		return rules.Verdict{Kind: rules.Goto, Chain: target}, true
	}
	return rules.Verdict{}, false
}

// noops are the statements that never change whether a first packet gets through.
var noops = map[string]string{
	"counter":        "counter",
	"log":            "log",
	"masquerade":     "masquerade",
	"snat":           "source NAT (snat)",
	"flow":           "flow offload (flow add)",
	"dup":            "copy the packet elsewhere (dup)",
	"last":           "last-used time (last)",
	"ct helper":      "connection tracking settings (ct helper)",
	"ct timeout":     "connection tracking settings (ct timeout)",
	"ct expectation": "connection tracking settings (ct expectation)",
}

// expr translates one expression of a rule.
func (c *ctx) expr(n *node) {
	key, v := n.obj().one()
	o := v.obj()
	if what, ok := noops[key]; ok {
		v.done()
		c.add(&rules.Noop{What: what})
		return
	}
	switch key {
	case "":
		c.stop("this rule holds something that is not written the way nft writes it")
	case "match":
		c.match(o)
	case "accept", "drop", "return", "jump", "goto":
		vd, ok := verdictOf(n)
		if !ok {
			c.stop(fmt.Sprintf("the %s statement does not name a chain seaward can read", key))
			return
		}
		c.add(&vd)
	case "continue":
		// In the middle of a rule "continue" does nothing: the rest of the rule still runs.
		if c.last {
			c.add(&rules.Verdict{Kind: rules.Continue})
		} else {
			c.add(&rules.Noop{What: "continue"})
		}
	case "vmap":
		c.vmap(o)
	case "limit":
		c.limit(v)
	case "quota":
		v.done()
		c.unknown("the quota statement depends on how much traffic has already passed, which seaward does not model")
	case "ct count":
		over, _ := o.get("inv").boolean()
		val, ok := o.get("val").num()
		if !ok {
			c.unknown("the ct count statement has a number seaward cannot read")
			return
		}
		// A first packet is its sender's only connection: one is over nothing but zero.
		if over == (val == 0) {
			c.add(&rules.Always{What: "connection count (ct count): a first packet is its sender's only connection"})
		} else {
			c.add(&rules.Never{What: "connection count (ct count): a first packet is its sender's only connection"})
		}
	case "reject":
		switch o.text("type") {
		case "icmp":
			c.need(keyPart{nf: 4})
		case "icmpv6":
			c.need(keyPart{nf: 6})
		}
		v.done()
		c.add(&rules.Verdict{Kind: rules.Reject})
	case "notrack":
		c.add(&rules.Notrack{})
	case "dnat", "redirect":
		c.nat(key, v)
	case "mangle":
		c.mangle(o)
	case "set", "map":
		// Adding the sender to a set or a meter. What is attached to the element (a rate limit
		// per address) still decides whether the rule goes on.
		inner := o.get("stmt")
		what := "add to a set"
		if o.text("op") == "delete" {
			what = "remove from a set"
		}
		o.get("elem").done()
		o.get("data").done()
		if _, ok := o.get("set").str(); !ok && key == "set" {
			c.stop("the set statement does not name a set seaward can read")
			return
		}
		o.get("map")
		c.add(&rules.Noop{What: what})
		for _, s := range inner.arr() {
			c.expr(s)
		}
	case "meter":
		inner := o.get("stmt")
		o.get("key").done()
		o.get("name")
		o.get("size")
		c.add(&rules.Noop{What: "add to a meter"})
		if !inner.null() {
			c.expr(inner)
		}
	case "queue":
		v.done()
		c.stop("the queue statement passes the packet to a program that decides its fate")
	case "tproxy":
		v.done()
		c.stop("the tproxy statement hands the packet to a local proxy socket, which seaward does not follow")
	case "synproxy":
		v.done()
		c.stop("the synproxy statement answers the TCP handshake itself before it lets the connection through")
	case "fwd":
		v.done()
		c.stop("the fwd statement sends the packet straight out of another interface, which seaward does not follow")
	case "xt":
		c.xt(o)
	default:
		c.stop(fmt.Sprintf("the %s statement is not one seaward understands", clip(key)))
	}
}

// unitBytes is the size of the units nft uses for byte rates.
var unitBytes = map[string]uint64{"bytes": 1, "kbytes": 1 << 10, "mbytes": 1 << 20, "gbytes": 1 << 30}

// limit translates a rate limit. A probe is the first packet, and a limit starts with its burst
// available, so a limit lets it through and a "limit rate over" does not.
func (c *ctx) limit(v *node) {
	over := false
	if name, ok := v.str(); ok {
		if over, ok = c.t.limits[name]; !ok {
			c.unknown(fmt.Sprintf("the rule uses a named limit (%s) that is not in the listing", clip(name)))
			return
		}
	} else {
		o := v.obj()
		if o == nil {
			c.unknown("the limit statement is not written the way nft writes it")
			return
		}
		over, _ = o.get("inv").boolean()
		if unit, ok := o.get("rate_unit").str(); ok && unit != "packets" {
			// A byte limit lets a packet through when the packet is no longer than rate plus burst.
			rate, _ := o.get("rate").num()
			burst, _ := o.get("burst").num()
			bu, _ := o.get("burst_unit").str()
			if unitBytes[unit] == 0 || rate > 1<<40 || burst > 1<<40 || rate*unitBytes[unit]+burst*unitBytes[bu] < 1500 {
				v.done()
				c.unknown("the limit statement allows so few bytes that even a first packet may be over it, depending on its size")
				return
			}
		}
		// Only what is known to be there counts as read: a word this reader has never seen in a
		// limit may change what the limit does.
		for _, k := range []string{"rate", "burst", "per", "rate_unit", "burst_unit"} {
			o.get(k)
		}
	}
	if over {
		c.add(&rules.Never{What: "over the rate limit (limit rate over): a first packet never is"})
	} else {
		c.add(&rules.Always{What: "rate limit (limit rate): its burst lets a first packet through"})
	}
}

// vmap translates a verdict map.
func (c *ctx) vmap(o *object) {
	fields, kinds, name, why := c.keys(o.get("key"))
	data := o.get("data")
	if why != "" {
		c.stop(fmt.Sprintf("this rule picks its verdict from a map keyed on %s, which seaward cannot follow", clip(name)))
		return
	}
	vm := &rules.VerdictMap{Key: fields}
	entries, known := []rules.VmapEntry(nil), true
	if s, ok := data.str(); ok && strings.HasPrefix(s, "@") {
		vm.SetRef = rules.SetKey(c.t.family, c.t.name, s[1:])
		si := c.t.sets[s[1:]]
		switch {
		case si == nil || si.set.Incomplete:
			known = false // the engine says what is missing
		case !si.verdict:
			c.stop(fmt.Sprintf("the rule uses the map %s to pick a verdict, and it is not a verdict map", clip(s[1:])))
			return
		default:
			for i, e := range si.set.Elems {
				entries = append(entries, rules.VmapEntry{Key: e, Verdict: si.set.Verdicts[i]})
			}
		}
	} else {
		k, sv := data.obj().one()
		bad := k != "set" || !sv.isArr()
		var star *rules.VmapEntry
		for _, e := range sv.arr() {
			pair := e.arr()
			if len(pair) != 2 {
				bad = true
				break
			}
			vd, ok := verdictOf(pair[1])
			if !ok {
				bad = true
				break
			}
			if s, isStr := unwrap(pair[0]).str(); isStr && s == "*" {
				star = &rules.VmapEntry{Key: make(rules.Elem, len(kinds)), Verdict: vd}
				continue
			}
			el, ok := elemOf(kinds, pair[0])
			if !ok {
				bad = true
				break
			}
			entries = append(entries, rules.VmapEntry{Key: el, Verdict: vd})
		}
		if bad {
			c.stop(fmt.Sprintf("the verdict map keyed on %s has an entry seaward cannot read", clip(name)))
			return
		}
		if star != nil {
			entries = append(entries, *star) // the catch-all is used only when nothing else matches
		}
		vm.Entries = entries
	}
	if c.last {
		c.add(vm)
		return
	}
	// More of the rule follows the map. The kernel ends the rule when the map has no entry for the
	// packet, and an entry that says "continue" goes on with the rest of the rule.
	guard := &rules.Match{Key: fields, SetRef: vm.SetRef}
	if vm.SetRef == "" {
		guard.Values = &rules.Set{}
		for _, e := range entries {
			guard.Values.Elems = append(guard.Values.Elems, e.Key)
		}
	}
	c.add(guard)
	var rest []rules.VmapEntry
	catchAll := false
	for _, e := range entries {
		if e.Verdict.Kind != rules.Continue {
			rest = append(rest, e)
			catchAll = catchAll || isAny(e.Key)
		}
	}
	switch {
	case !known || len(rest) == len(entries):
		c.add(vm)
	case catchAll:
		c.stop(fmt.Sprintf("the verdict map keyed on %s mixes \"continue\" with a catch-all entry in the middle of a rule, which seaward cannot represent", clip(name)))
	case len(rest) > 0:
		c.add(&rules.VerdictMap{Key: fields, Entries: rest})
	}
}

// isAny reports an element that matches every packet: the "*" entry of a map.
func isAny(e rules.Elem) bool {
	for _, a := range e {
		if a.Kind != rules.AtomAny {
			return false
		}
	}
	return true
}

// natTarget is where a dnat or redirect sends the packet.
type natTarget struct {
	a, ahi netip.Addr
	p, phi uint16
}

func (t natTarget) expr(redirect bool) rules.Expr {
	if redirect {
		return &rules.Redirect{Port: t.p, PortHi: t.phi}
	}
	return &rules.DNAT{Addr: t.a, AddrHi: t.ahi, Port: t.p, PortHi: t.phi}
}

func plainAddr(n *node) (netip.Addr, bool) {
	s, ok := n.str()
	if !ok {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	return a, err == nil && a.Zone() == ""
}

// natAddr reads the address of a nat target: one address, a range, or a network.
func natAddr(n *node) (lo, hi netip.Addr, ok bool) {
	if a, ok := plainAddr(n); ok {
		return a, netip.Addr{}, true
	}
	key, v := n.obj().one()
	switch key {
	case "range":
		xs := v.arr()
		if len(xs) != 2 {
			break
		}
		lo, ok1 := plainAddr(xs[0])
		hi, ok2 := plainAddr(xs[1])
		if !ok1 || !ok2 || lo.Is4() != hi.Is4() || hi.Less(lo) {
			break
		}
		return lo, hi, true
	case "prefix":
		po := v.obj()
		a, ok1 := plainAddr(po.get("addr"))
		l, ok2 := po.get("len").num()
		if !ok1 || !ok2 || l > uint64(a.BitLen()) {
			break
		}
		pfx := netip.PrefixFrom(a, int(l)).Masked()
		b := pfx.Addr().AsSlice()
		for i := pfx.Bits(); i < len(b)*8; i++ {
			b[i/8] |= 1 << uint(7-i%8)
		}
		last, _ := netip.AddrFromSlice(b)
		if last == pfx.Addr() {
			return pfx.Addr(), netip.Addr{}, true
		}
		return pfx.Addr(), last, true
	}
	return netip.Addr{}, netip.Addr{}, false
}

// natPort reads the port of a nat target: one port or a range.
func natPort(n *node) (lo, hi uint16, ok bool) {
	if v, ok := n.num(); ok {
		return uint16(v), 0, v >= 1 && v <= 0xffff
	}
	if key, v := n.obj().one(); key == "range" {
		xs := v.arr()
		if len(xs) == 2 {
			a, ok1 := xs[0].num()
			b, ok2 := xs[1].num()
			if ok1 && ok2 && a >= 1 && a <= b && b <= 0xffff {
				return uint16(a), uint16(b), true
			}
		}
	}
	return 0, 0, false
}

// nat translates dnat and redirect.
func (c *ctx) nat(key string, v *node) {
	o := v.obj() // nil for a bare "redirect"
	redirect := key == "redirect"
	if (o == nil && !v.null()) || (!redirect && !o.has("addr") && !o.has("port")) {
		v.done()
		c.stop(fmt.Sprintf("the %s statement names a target seaward cannot read", key))
		return
	}
	fam := o.text("family")
	switch fam {
	case "ip":
		c.need(keyPart{nf: 4})
	case "ip6":
		c.need(keyPart{nf: 6})
	}
	netmap := o.has("type_flags")
	for _, f := range o.get("flags").strs() {
		netmap = netmap || f == "netmap"
	}
	if netmap {
		c.stop(fmt.Sprintf("the %s statement maps a whole network onto another one, which seaward does not model", key))
		return
	}
	an, pn := o.get("addr"), o.get("port")
	var mapN *node
	inPort := false
	if k, m := an.obj().onePeek(); k == "map" {
		an.obj().one()
		mapN = m
	} else if k, m := pn.obj().onePeek(); k == "map" {
		pn.obj().one()
		mapN, inPort = m, true
	}
	var fixed natTarget
	ok := true
	if !an.null() && (mapN == nil || inPort) {
		fixed.a, fixed.ahi, ok = natAddr(an)
		ok = ok && !redirect && (fam != "ip" || fixed.a.Is4()) && (fam != "ip6" || fixed.a.Is6())
	}
	if ok && !pn.null() && (mapN == nil || !inPort) {
		fixed.p, fixed.phi, ok = natPort(pn)
	}
	if !ok {
		c.stop(fmt.Sprintf("the %s statement names a target seaward cannot read", key))
		return
	}
	if mapN == nil {
		c.add(fixed.expr(redirect))
		return
	}
	c.natMap(key, redirect, inPort, fixed, mapN.obj())
}

// natMap translates a dnat or redirect that looks its target up in a map.
func (c *ctx) natMap(key string, redirect, inPort bool, fixed natTarget, m *object) {
	fields, kinds, name, why := c.keys(m.get("key"))
	data := m.get("data")
	if why != "" {
		c.stop(fmt.Sprintf("the %s statement picks its target from a map keyed on %s, which seaward cannot follow", key, clip(name)))
		return
	}
	var elems []rules.Elem
	var vals []*node
	ref := ""
	if s, ok := data.str(); ok && strings.HasPrefix(s, "@") {
		si := c.t.sets[s[1:]]
		switch {
		case si == nil:
			c.stop(fmt.Sprintf("the %s statement takes its target from the map %s, which is not in the listing", key, clip(s[1:])))
			return
		case si.set.Incomplete:
			c.stop(si.set.Why)
			return
		case !si.isMap || si.verdict || len(si.data) != len(si.set.Elems):
			c.stop(fmt.Sprintf("the %s statement takes its target from %s, which is not a map of targets", key, clip(s[1:])))
			return
		}
		elems, vals = si.set.Elems, si.data
		ref = rules.SetKey(c.t.family, c.t.name, s[1:])
	} else {
		k, sv := data.obj().one()
		bad := k != "set" || !sv.isArr()
		var star *node
		for _, e := range sv.arr() {
			pair := e.arr()
			if len(pair) != 2 {
				bad = true
				break
			}
			if s, isStr := unwrap(pair[0]).str(); isStr && s == "*" {
				star = pair[1]
				continue
			}
			el, ok := elemOf(kinds, pair[0])
			if !ok {
				bad = true
				break
			}
			elems, vals = append(elems, el), append(vals, pair[1])
		}
		if bad {
			c.stop(fmt.Sprintf("the %s statement takes its target from a map with an entry seaward cannot read", key))
			return
		}
		if star != nil {
			elems, vals = append(elems, make(rules.Elem, len(kinds))), append(vals, star)
		}
	}
	// Entries that lead to the same target make one group.
	type group struct {
		to    natTarget
		elems []rules.Elem
		any   bool
	}
	var groups []*group
	byTarget := map[natTarget]*group{}
	for i, el := range elems {
		to, ok := fixed, false
		switch {
		case inPort || redirect:
			to.p, to.phi, ok = natPort(vals[i])
		default:
			an := vals[i]
			if k, cv := an.obj().onePeek(); k == "concat" && len(cv.arr()) == 2 {
				an.obj().one()
				an = cv.arr()[0]
				if to.p, to.phi, ok = natPort(cv.arr()[1]); !ok {
					break
				}
			}
			to.a, to.ahi, ok = natAddr(an)
		}
		if !ok {
			c.stop(fmt.Sprintf("the %s statement takes its target from a map with an entry seaward cannot read", key))
			return
		}
		g := byTarget[to]
		if g == nil {
			g = &group{to: to}
			byTarget[to] = g
			groups = append(groups, g)
		}
		g.elems = append(g.elems, el)
		g.any = g.any || isAny(el)
	}
	all := &rules.Match{Key: fields, SetRef: ref}
	if ref == "" {
		all.Values = &rules.Set{Elems: elems}
	}
	switch {
	case len(groups) <= 1:
		// No entry at all: nothing matches and the rule ends there.
		c.add(all)
		if len(groups) == 1 {
			c.add(groups[0].to.expr(redirect))
		}
	case c.alts != nil || len(groups) > 256 || !repeatable(c.out):
		c.add(all)
		c.stop(fmt.Sprintf("the %s statement picks one of %d targets from a map, in a rule seaward cannot split up", key, len(groups)))
	default:
		// One model rule per target. The group with the catch-all goes last: it is used only when
		// no other entry matches.
		c.altAt = len(c.out)
		var last []rules.Expr
		for _, g := range groups {
			alt := []rules.Expr{&rules.Match{Key: fields, Values: &rules.Set{Elems: g.elems}}, g.to.expr(redirect)}
			if g.any {
				last = alt
				continue
			}
			c.alts = append(c.alts, alt)
		}
		if last != nil {
			c.alts = append(c.alts, last)
		}
	}
}

// repeatable reports whether running these expressions more than once changes nothing.
func repeatable(xs []rules.Expr) bool {
	for _, x := range xs {
		switch x.(type) {
		case *rules.Match, *rules.Unknown, *rules.Always, *rules.Never, *rules.Noop, *rules.Notrack:
		default:
			return false
		}
	}
	return true
}

// markForm is a mark value written as (base AND and) XOR xor, where base is a constant zero, the
// packet mark or the connection mark.
type markForm struct {
	base     int // 0 constant, 1 packet mark, 2 connection mark
	and, xor uint32
}

func markOf(n *node) (markForm, bool) {
	if v, ok := n.u32(); ok {
		return markForm{xor: v}, true
	}
	key, v := n.obj().one()
	switch key {
	case "meta":
		if v.obj().text("key") == "mark" {
			return markForm{base: 1, and: ^uint32(0)}, true
		}
	case "ct":
		if o := v.obj(); o.text("key") == "mark" && !o.has("dir") {
			return markForm{base: 2, and: ^uint32(0)}, true
		}
	case "&", "|", "^":
		xs := v.arr()
		if len(xs) != 2 {
			break
		}
		l, ok1 := markOf(xs[0])
		r, ok2 := markOf(xs[1])
		if !ok1 || !ok2 {
			break
		}
		if l.base == 0 {
			l, r = r, l
		}
		if r.base != 0 {
			break // two marks combined: not one mask and one value
		}
		k := r.xor
		switch key {
		case "&":
			l.and &= k
			l.xor &= k
		case "|":
			l.and &^= k
			l.xor |= k
		case "^":
			l.xor ^= k
		}
		return l, true
	}
	return markForm{}, false
}

// mangle translates the statements that change something: marks, and the header tweaks that do
// not decide anything.
func (c *ctx) mangle(o *object) {
	keyN, val := o.get("key"), o.get("value")
	kind, kv := keyN.obj().one()
	ko := kv.obj()
	switch kind {
	case "meta":
		switch k := ko.text("key"); k {
		case "mark":
			c.setMark(false, val)
		case "nftrace":
			val.done()
			c.add(&rules.Noop{What: "trace (meta nftrace)"})
		case "priority", "secmark":
			val.done()
			c.add(&rules.Noop{What: "traffic class or label (meta " + k + ")"})
		default:
			c.stop(fmt.Sprintf("the rule changes how the kernel treats the packet (meta %s set), which seaward does not model", clip(k)))
		}
	case "ct":
		switch k := ko.text("key"); {
		case k == "mark" && !ko.has("dir"):
			c.setMark(true, val)
		case k == "zone" || k == "label" || k == "event" || k == "secmark" || k == "helper":
			ko.get("dir")
			val.done()
			c.add(&rules.Noop{What: "connection tracking settings (ct " + k + ")"})
		default:
			c.stop(fmt.Sprintf("the rule changes what the kernel remembers about the connection (ct %s set), which seaward does not model", clip(k)))
		}
	case "tcp option":
		kv.done()
		val.done()
		c.add(&rules.Noop{What: "TCP MSS clamping or another TCP option change (tcp option)"})
	case "payload":
		proto, field := ko.text("protocol"), ko.text("field")
		switch field {
		case "dscp", "ecn", "ttl", "hoplimit", "flowlabel", "id", "checksum":
			val.done()
			c.add(&rules.Noop{What: "header change (" + clip(proto+" "+field) + ")"})
		default:
			c.stop(fmt.Sprintf("the rule rewrites part of the packet by hand (%s set), which seaward does not follow", clip(proto+" "+field)))
		}
	default:
		c.stop("the rule changes part of the packet in a way seaward does not follow")
	}
}

// setMark translates "meta mark set" and "ct mark set".
func (c *ctx) setMark(ct bool, val *node) {
	f, ok := markOf(val)
	if !ok {
		word := "packet"
		if ct {
			word = "connection"
		}
		c.stop(fmt.Sprintf("the rule sets the %s mark from a value seaward cannot work out", word))
		return
	}
	own := 1
	if ct {
		own = 2
	}
	switch {
	case f.base == 0 || f.base == own:
		c.add(&rules.SetMark{Ct: ct, And: f.and, Xor: f.xor})
	case f.and == ^uint32(0) && f.xor == 0:
		c.add(&rules.CopyMark{ToCt: ct, Mask: ^uint32(0)})
	default:
		// (other mark AND and) XOR xor, in three steps.
		c.add(&rules.SetMark{Ct: ct})
		c.add(&rules.CopyMark{ToCt: ct, Mask: f.and})
		if f.xor != 0 {
			c.add(&rules.SetMark{Ct: ct, And: ^uint32(0), Xor: f.xor})
		}
	}
}

// xtNoop are the iptables targets that never decide anything, whatever their options.
var xtNoop = map[string]string{
	"LOG": "log", "NFLOG": "log", "ULOG": "log", "AUDIT": "audit record", "TRACE": "trace",
	"MASQUERADE": "masquerade", "SNAT": "source NAT", "TCPMSS": "TCP MSS clamping",
	"TOS": "header change", "DSCP": "header change", "TTL": "header change", "HL": "header change",
	"ECN": "header change", "TCPOPTSTRIP": "header change", "CHECKSUM": "checksum fix",
	"CLASSIFY": "traffic class", "SECMARK": "security label", "CONNSECMARK": "security label",
	"SET": "add to a set", "RATEEST": "rate estimate", "IDLETIMER": "idle timer", "LED": "LED trigger",
	"TEE": "copy the packet elsewhere",
}

// xt translates what iptables wrote in its own format. The nft listing gives the name of the
// match or target and nothing else, so only the ones whose name says it all can be read. settle.go
// uses the iptables-save printing of such a rule whenever it can.
func (c *ctx) xt(o *object) {
	typ, name := o.text("type"), o.text("name")
	if typ == "match" {
		if name == "comment" {
			c.add(&rules.Always{What: "comment"})
			return
		}
		c.unknown(fmt.Sprintf("this condition was written by iptables (the %s match) and the nft listing does not say what it checks", clip(name)))
		return
	}
	switch what, harmless := xtNoop[name]; {
	case name == "REJECT":
		c.add(&rules.Verdict{Kind: rules.Reject})
	case name == "NOTRACK":
		c.add(&rules.Notrack{})
	case harmless:
		c.add(&rules.Noop{What: what + " (" + name + ")"})
	default:
		c.stop(fmt.Sprintf("this action was written by iptables (the %s target) and the nft listing does not say what it does", clip(name)))
	}
}
