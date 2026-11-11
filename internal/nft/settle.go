package nft

import (
	"fmt"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// settle makes one table out of the two listings of a table iptables made on the nf_tables
// backend: sh is what iptables-save printed, t is the same table in the nft listing.
//
// Neither is complete. The nft listing shows most of what iptables wrote as "xt" expressions that
// carry a name and nothing else, so for those rules iptables-save is the only reading. But the nft
// tool can add rules to the same table, and iptables-save 1.8.13 misprints what it has no words
// for without saying so: "tcp dport { 25, 587 } accept" comes out as "-p tcp -j ACCEPT" and a
// lookup in a named set as an unconditional "-j ACCEPT". So the chains and their order, hooks,
// priorities and policies come from the nft listing, and each rule comes from the listing that
// can be trusted for it: iptables-save when the rule holds an xt expression or is written
// entirely the way iptables-nft itself writes rules, the nft listing for everything else.
//
// The two listings are matched by position, which only works while they agree on how many rules
// a chain has. Where they do not (iptables-save gives up in the middle of a table for some rules)
// the chain is read from the nft listing alone and a note says so.
func (p *parser) settle(t *table, sh *rules.Table) *rules.Table {
	out := &rules.Table{Family: t.family, Name: t.name, Origin: sh.Origin, Chains: map[string]*rules.Chain{}}
	where := fmt.Sprintf("table %s %s", t.family, clip(t.name))
	const lost = "seaward read it from the nft listing, where conditions written by iptables show only their names"
	for _, name := range t.order {
		c := t.chains[name]
		nc := *c.c
		sc := sh.Chains[name]
		switch {
		case sc == nil:
			nc.Rules = p.rulesOf(t, c.raw)
			if len(c.raw) > 0 {
				p.note(fmt.Sprintf("the chain %s of %s is in the nft listing and not in what iptables-save printed; %s", clip(name), where, lost))
			}
		case len(sc.Rules) != len(c.raw):
			nc.Rules = p.rulesOf(t, c.raw)
			p.note(fmt.Sprintf("iptables-save printed %s for the chain %s of %s and the nft listing has %d; %s", nRules(len(sc.Rules)), clip(name), where, len(c.raw), lost))
		default:
			for i, r := range c.raw {
				if sr := sc.Rules[i]; sr != nil && iptablesReads(r.obj()) {
					cp := *sr
					cp.Exprs = append([]rules.Expr(nil), sr.Exprs...)
					nc.Rules = append(nc.Rules, &cp)
					continue
				}
				nc.Rules = append(nc.Rules, p.rule(t, r)...)
			}
		}
		out.Chains[name] = &nc
		out.Order = append(out.Order, name)
	}
	// iptables-save prints the built-in chains of a table even when the kernel does not have them
	// (INPUT and OUTPUT of a nat table that only ever got a PREROUTING rule). An empty one is
	// that; one with rules is a real disagreement.
	for _, name := range sh.Order {
		if sc := sh.Chains[name]; sc != nil && t.chains[name] == nil && len(sc.Rules) > 0 {
			p.note(fmt.Sprintf("iptables-save printed a chain %s with %s in %s that the nft listing does not have; seaward left it out, since the nft listing is what the kernel holds", clip(name), nRules(len(sc.Rules)), where))
		}
	}
	return out
}

func nRules(n int) string {
	if n == 1 {
		return "1 rule"
	}
	return fmt.Sprintf("%d rules", n)
}

// iptablesReads reports whether iptables-save can be trusted for this rule of the nft listing:
// the rule holds an xt expression, which only iptables writes and only iptables can print, or it
// is plain.
func iptablesReads(o *object) bool {
	exprs := o.peek("expr").arr()
	for _, e := range exprs {
		if k, _ := e.obj().onePeek(); k == "xt" {
			return true
		}
	}
	return plainRule(exprs)
}

// plainRule reports whether a rule is written entirely the way iptables-nft 1.8.13 writes one
// natively (found by experiment, see testdata/iptables.json and testdata/iptables-more.json):
// address, interface, protocol, port, TCP flag, fragment and mark comparisons, a counter, a rate
// limit, an NFLOG, a TRACE and the plain verdicts, each field at most once. Such a rule reads the
// same in both listings, which TestPlainRulesReadTheSame checks; anything else in a rule without
// xt was put there by the nft tool and is read from the nft listing. It looks without marking
// anything as read.
func plainRule(exprs []*node) bool {
	seen := map[string]bool{}
	once := func(what string) bool {
		if seen[what] {
			return false
		}
		seen[what] = true
		return true
	}
	// A rule iptables wrote is about one transport protocol at most: "-p udp" and a tcp port in
	// the same rule is the nft tool's doing.
	l4 := ""
	proto := func(name string) bool {
		if l4 != "" && l4 != name {
			return false
		}
		l4 = name
		return true
	}
	for _, e := range exprs {
		key, v := e.obj().onePeek()
		o := v.obj()
		switch key {
		case "accept", "drop", "return":
			if !v.null() || !once("verdict") {
				return false
			}
		case "jump", "goto":
			if _, ok := o.peek("target").str(); !ok || len(o.m) != 1 || !once("verdict") {
				return false
			}
		case "counter":
			if o == nil || !only(o, "packets", "bytes") || !once("counter") {
				return false
			}
		case "limit":
			if o == nil || !only(o, "rate", "burst", "per") || !once("limit") {
				return false
			}
		case "log":
			if o == nil || !o.has("group") || !only(o, "group", "prefix", "snaplen", "queue-threshold") || !once("log") {
				return false
			}
		case "mangle":
			k, kv := o.peek("key").obj().onePeek()
			name, _ := kv.obj().peek("key").str()
			val, ok := o.peek("value").num()
			if k != "meta" || name != "nftrace" || !ok || val != 1 || !only(o, "key", "value") || !once("trace") {
				return false
			}
		case "match":
			if !only(o, "op", "left", "right") {
				return false
			}
			op, _ := o.peek("op").str()
			what, pr := plainMatch(op, o.peek("left"), o.peek("right"))
			if what == "" || !once(what) || (pr != "" && !proto(pr)) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// only reports that the object has no key beyond the ones named.
func only(o *object, keys ...string) bool {
	if o == nil {
		return false
	}
next:
	for k := range o.m {
		for _, want := range keys {
			if k == want {
				continue next
			}
		}
		return false
	}
	return true
}

// plainMatch names the field a comparison is about when it is one iptables-nft writes natively,
// and the transport protocol it belongs to. An empty name means it is not.
func plainMatch(op string, left, right *node) (what, proto string) {
	eq := op == "==" || op == "!="
	isNum := func(n *node) bool { _, ok := n.num(); return ok }
	key, v := left.obj().onePeek()
	o := v.obj()
	field := func(n *object) string {
		p, _ := n.peek("protocol").str()
		f, _ := n.peek("field").str()
		if !only(n, "protocol", "field") {
			return ""
		}
		return p + " " + f
	}
	switch key {
	case "payload":
		switch f := field(o); f {
		case "ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr":
			// an address, or a network
			if s, ok := right.str(); eq && ok && !strings.HasPrefix(s, "@") {
				return f[strings.Index(f, " ")+1:], ""
			}
			if k, pv := right.obj().onePeek(); eq && k == "prefix" && only(pv.obj(), "addr", "len") {
				return f[strings.Index(f, " ")+1:], ""
			}
		case "ip protocol":
			if _, ok := right.str(); eq && (ok || isNum(right)) {
				return "protocol", "any"
			}
		case "tcp sport", "tcp dport", "udp sport", "udp dport":
			ok := isNum(right)
			if k, rv := right.obj().onePeek(); k == "range" && len(rv.arr()) == 2 {
				ok = isNum(rv.arr()[0]) && isNum(rv.arr()[1])
			}
			if eq && ok {
				return f[4:], f[:3]
			}
		case "tcp flags":
			// --tcp-flags ALL NONE: none of the flags
			if _, ok := flagBitsPeek(right); op == "!" && ok && right.isArr() {
				return "flags", "tcp"
			}
		}
	case "meta":
		name, _ := o.peek("key").str()
		if !only(o, "key") {
			return "", ""
		}
		switch name {
		case "iifname", "oifname":
			if _, ok := right.str(); eq && ok {
				return name, ""
			}
		case "l4proto":
			if _, ok := right.str(); eq && (ok || isNum(right)) {
				return "protocol", "any"
			}
		case "mark":
			if eq && isNum(right) {
				return "mark", ""
			}
		}
	case "&":
		xs := v.arr()
		if len(xs) != 2 || !eq {
			return "", ""
		}
		k, inner := xs[0].obj().onePeek()
		switch io := inner.obj(); {
		case k == "meta":
			if name, _ := io.peek("key").str(); name == "mark" && only(io, "key") && isNum(xs[1]) && isNum(right) {
				return "mark", ""
			}
		case k == "payload":
			switch f := field(io); f {
			case "ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr":
				// a mask with gaps: -s 198.51.0.0/255.255.0.255
				_, ok1 := xs[1].str()
				_, ok2 := right.str()
				if ok1 && ok2 {
					return f[strings.Index(f, " ")+1:], ""
				}
			case "tcp flags":
				_, ok1 := flagBitsPeek(xs[1])
				_, ok2 := flagBitsPeek(right)
				if ok1 && ok2 {
					return "flags", "tcp"
				}
			case "ip frag-off":
				m, ok1 := xs[1].num()
				z, ok2 := right.num()
				if ok1 && ok2 && m == 0x1fff && z == 0 {
					return "fragment", ""
				}
			}
		}
	}
	return "", ""
}

// flagBitsPeek is flagBits without marking anything as read.
func flagBitsPeek(n *node) (uint32, bool) {
	if k, v := n.obj().onePeek(); k == "|" {
		n = v
	} else if n.obj() != nil {
		return 0, false
	}
	if !n.isArr() {
		return number(kTCPFlags, n)
	}
	var bits uint32
	for _, x := range n.arr() {
		b, ok := flagBitsPeek(x)
		if !ok {
			return 0, false
		}
		bits |= b
	}
	return bits, true
}
