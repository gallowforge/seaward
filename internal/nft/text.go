package nft

import (
	"fmt"
	"strconv"
	"strings"
)

// text.go rebuilds a rule in nft's own syntax from its JSON form, for Rule.Text. It follows what
// "nft list ruleset" prints closely enough that a rule can be found again in that listing; a part
// it cannot rebuild is shown as <name>. It runs after the rule was translated, so it may read
// keys freely.

// kHex is a kind for this file only: numbers printed in hexadecimal, as nft does after a mask.
const (
	kHex    kind = -1 // numbers printed in hexadecimal
	kQuoted kind = -2 // names printed in quotes
	kSpan   kind = -3 // seconds printed as a time span
)

type texter struct {
	data   []kind // the kind of the values a map hands out, when the statement says
	family string
}

// ruleText is the rule as nft would print it.
func ruleText(o *object, family string) string {
	x := texter{family: family}
	var parts []string
	for _, e := range o.peek("expr").arr() {
		parts = append(parts, x.stmt(e))
	}
	if s, ok := o.peek("comment").str(); ok {
		parts = append(parts, "comment "+quote(s))
	}
	return strings.Join(parts, " ")
}

func quote(s string) string { return `"` + s + `"` }

func peekText(o *object, k string) string {
	s, _ := o.peek(k).str()
	return s
}

// scalar prints a string or a number as it stands.
func scalar(n *node) string {
	if s, ok := n.str(); ok {
		return s
	}
	if n != nil {
		if j, ok := n.v.(fmt.Stringer); ok {
			return j.String()
		}
	}
	return "?"
}

// span prints seconds the way nft prints a timeout: 1h30m.
func span(n *node) string {
	v, ok := n.num()
	if !ok {
		return scalar(n)
	}
	if v == 0 {
		return "0s"
	}
	out := ""
	for _, u := range []struct {
		n uint64
		s string
	}{{86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}} {
		if v >= u.n {
			out += strconv.FormatUint(v/u.n, 10) + u.s
			v %= u.n
		}
	}
	return out
}

func kindAt(ks []kind, i, n int) kind {
	if len(ks) == n && i < len(ks) {
		return ks[i]
	}
	if len(ks) == 1 && n == 1 {
		return ks[0]
	}
	return kNone
}

// key prints something a rule looks at, and says what kind of values it is compared against.
func (x texter) key(n *node) (string, []kind) {
	name, v := n.obj().onePeek()
	o := v.obj()
	switch name {
	case "payload":
		if o.has("base") {
			return fmt.Sprintf("@%s,%s,%s", peekText(o, "base"), scalar(o.peek("offset")), scalar(o.peek("len"))), []kind{kHex}
		}
		p := payloadKey(o)
		return p.name, []kind{p.k}
	case "meta":
		p := metaKey(o)
		switch peekText(o, "key") {
		case "hour", "day", "time", "iifkind", "oifkind", "ibrname", "obrname":
			p.k = kQuoted
		}
		return p.name, []kind{p.k}
	case "ct":
		p := ctKey(o, x.family)
		switch peekText(o, "key") {
		case "helper":
			p.k = kQuoted
		case "expiration":
			p.k = kSpan
		}
		return p.name, []kind{p.k}
	case "concat":
		var names []string
		var ks []kind
		for _, part := range v.arr() {
			s, k := x.key(part)
			names = append(names, s)
			ks = append(ks, kindAt(k, 0, 1))
		}
		return strings.Join(names, " . "), ks
	case "&", "|", "^", "<<", ">>":
		xs := v.arr()
		if len(xs) != 2 {
			break
		}
		left, ks := x.key(xs[0])
		if len(ks) == 1 && ks[0] == kNone {
			ks = []kind{kHex}
		}
		right := x.val(xs[1], ks)
		if strings.Contains(right, " | ") {
			right = "(" + right + ")"
		}
		return left + " " + name + " " + right, ks
	case "fib":
		return "fib " + strings.Join(o.peek("flags").strs(), " . ") + " " + peekText(o, "result"), []kind{kFibType}
	case "numgen":
		s := "numgen " + peekText(o, "mode") + " mod " + scalar(o.peek("mod"))
		if off, ok := o.peek("offset").num(); ok && off != 0 {
			s += " offset " + strconv.FormatUint(off, 10)
		}
		return s, []kind{kNone}
	case "jhash", "symhash":
		s := name
		if e := o.peek("expr"); e != nil {
			inner, _ := x.key(e)
			s += " " + inner
		}
		return s + " mod " + scalar(o.peek("mod")), []kind{kNone}
	case "osf":
		return name + " " + peekText(o, "key"), []kind{kQuoted}
	case "rt", "socket":
		return name + " " + peekText(o, "key"), []kind{kNone}
	case "ipsec":
		return strings.TrimSpace("ipsec " + peekText(o, "dir") + " " + peekText(o, "key")), []kind{kNone}
	case "exthdr":
		// nft prints "rt type 0" for a field of an extension header, "exthdr frag exists" for the header
		if f := peekText(o, "field"); f != "" {
			return peekText(o, "name") + " " + f, []kind{kNone}
		}
		return "exthdr " + peekText(o, "name"), []kind{kNone}
	case "tcp option", "ip option", "sctp chunk":
		return strings.TrimSpace(name + " " + peekText(o, "name") + " " + peekText(o, "field")), []kind{kNone}
	case "map":
		left, ks := x.key(o.peek("key"))
		return left + " map " + x.val(o.peek("data"), ks), []kind{kNone}
	}
	if name == "" {
		return "<?>", []kind{kNone}
	}
	return "<" + clip(name) + ">", []kind{kNone}
}

// maxShown is how many elements of a set written into a rule the text shows before it trails off.
const maxShown = 16

// val prints a value: what a key is compared against, an element of a set, a target.
func (x texter) val(n *node, ks []kind) string {
	k := kindAt(ks, 0, 1)
	if s, ok := n.str(); ok {
		if (k == kIfname || k == kIface || k == kQuoted) && !strings.HasPrefix(s, "@") {
			return quote(s)
		}
		return s
	}
	if v, ok := n.num(); ok {
		switch k {
		case kMark:
			return fmt.Sprintf("0x%08x", v)
		case kHex:
			return fmt.Sprintf("0x%x", v)
		case kSpan:
			return span(n)
		}
		return strconv.FormatUint(v, 10)
	}
	if b, ok := n.boolean(); ok {
		if b {
			return "exists"
		}
		return "missing"
	}
	if n.isArr() {
		var parts []string
		for _, e := range n.arr() {
			parts = append(parts, x.val(e, ks))
		}
		return strings.Join(parts, ",")
	}
	name, v := n.obj().onePeek()
	o := v.obj()
	switch name {
	case "prefix":
		return scalar(o.peek("addr")) + "/" + scalar(o.peek("len"))
	case "range":
		xs := v.arr()
		if len(xs) != 2 {
			break
		}
		return x.val(xs[0], ks) + "-" + x.val(xs[1], ks)
	case "set":
		var parts []string
		for _, e := range v.arr() {
			if pair := e.arr(); e.isArr() && len(pair) == 2 {
				parts = append(parts, x.val(pair[0], ks)+" : "+x.val(pair[1], x.data))
				continue
			}
			parts = append(parts, x.val(e, ks))
		}
		if len(parts) > maxShown {
			parts = append(parts[:maxShown], "...")
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	case "concat":
		xs := v.arr()
		var parts []string
		for i, e := range xs {
			parts = append(parts, x.val(e, []kind{kindAt(ks, i, len(xs))}))
		}
		return strings.Join(parts, " . ")
	case "|":
		if xs := v.arr(); len(xs) > 0 && xs[0].obj() == nil {
			var parts []string
			for _, e := range xs {
				parts = append(parts, x.val(e, ks))
			}
			return strings.Join(parts, " | ")
		}
	case "elem":
		s := x.val(o.peek("val"), ks)
		if t := o.peek("timeout"); t != nil {
			s += " timeout " + span(t)
		}
		return s
	case "accept", "drop", "return", "continue":
		return name
	case "jump", "goto":
		return name + " " + peekText(o, "target")
	case "":
		return "<?>"
	}
	s, _ := x.key(n)
	return s
}

// bitmask kinds are the ones nft prints "==" for: without it "tcp flags syn" means "syn is set".
func bitmask(ks []kind) bool {
	k := kindAt(ks, 0, 1)
	return k == kTCPFlags || k == kCtState || k == kCtStatus
}

func (x texter) match(o *object) string {
	op := peekText(o, "op")
	left, right := o.peek("left"), o.peek("right")
	lt, ks := x.key(left)
	lk, lv := left.obj().onePeek()
	if lk == "fib" && peekText(lv.obj(), "result") != "type" {
		// "fib saddr . iif oif missing" is printed as a check
		ks = []kind{kIface}
		if _, isBool := right.boolean(); isBool {
			lt = strings.TrimSuffix(lt, " oif") + " check"
		}
	}
	rt := x.val(right, ks)
	binop := lk == "&" || lk == "|" || lk == "^"
	switch op {
	case "==":
		str, isStr := right.str()
		_, isNum := right.num()
		rk, _ := right.obj().onePeek()
		isStr = isStr && !strings.HasPrefix(str, "@") // a lookup in a named set
		if binop || (bitmask(ks) && (isStr || isNum || rk == "|")) {
			return lt + " == " + rt
		}
		return lt + " " + rt
	case "in", "":
		return lt + " " + rt
	}
	return lt + " " + clip(op) + " " + rt
}

// flags prints a flag list after a statement: "random,persistent".
func flagList(n *node) string {
	fs := n.strs()
	if len(fs) == 0 {
		return ""
	}
	return " " + strings.Join(fs, ",")
}

// stmt prints one expression of a rule.
func (x texter) stmt(n *node) string {
	name, v := n.obj().onePeek()
	o := v.obj()
	switch name {
	case "match":
		return x.match(o)
	case "accept", "drop", "return", "continue":
		return name
	case "jump", "goto":
		return name + " " + peekText(o, "target")
	case "vmap":
		left, ks := x.key(o.peek("key"))
		return left + " vmap " + x.val(o.peek("data"), ks)
	case "counter":
		if s, ok := v.str(); ok {
			return "counter name " + quote(s)
		}
		if o == nil {
			return "counter"
		}
		return "counter packets " + scalar(o.peek("packets")) + " bytes " + scalar(o.peek("bytes"))
	case "log":
		s := "log"
		if p, ok := o.peek("prefix").str(); ok {
			s += " prefix " + quote(p)
		}
		for _, k := range []string{"level", "group", "snaplen", "queue-threshold"} {
			if o.has(k) {
				s += " " + k + " " + scalar(o.peek(k))
			}
		}
		if fs := o.peek("flags").strs(); len(fs) > 0 {
			s += " flags " + strings.Join(fs, ",")
		}
		return s
	case "limit":
		if s, ok := v.str(); ok {
			return "limit name " + quote(s)
		}
		s := "limit rate "
		if over, _ := o.peek("inv").boolean(); over {
			s += "over "
		}
		s += scalar(o.peek("rate"))
		unit := peekText(o, "rate_unit")
		if unit != "" && unit != "packets" {
			s += " " + unit
		}
		s += "/" + peekText(o, "per")
		if b, ok := o.peek("burst").num(); ok && b > 0 {
			bu := peekText(o, "burst_unit")
			if bu == "" {
				bu = "packets"
			}
			s += " burst " + strconv.FormatUint(b, 10) + " " + bu
		}
		return s
	case "quota":
		if s, ok := v.str(); ok {
			return "quota name " + quote(s)
		}
		s := "quota "
		if over, _ := o.peek("inv").boolean(); over {
			s += "over "
		}
		return s + scalar(o.peek("val")) + " " + peekText(o, "val_unit")
	case "ct count":
		s := "ct count "
		if over, _ := o.peek("inv").boolean(); over {
			s += "over "
		}
		return s + scalar(o.peek("val"))
	case "reject":
		typ, code := peekText(o, "type"), peekText(o, "expr")
		own := map[string]string{"ip": "icmp", "ip6": "icmpv6", "inet": "icmpx"}[x.family]
		switch {
		case o == nil || typ == "" || (typ == own && code == "port-unreachable"):
			return "reject"
		case code == "":
			return "reject with " + typ
		}
		return "reject with " + typ + " " + code
	case "notrack":
		return "notrack"
	case "masquerade", "snat", "dnat", "redirect":
		return x.nat(name, o)
	case "mangle":
		left, ks := x.key(o.peek("key"))
		return left + " set " + texter{family: x.family, data: ks}.val(o.peek("value"), ks)
	case "set", "map":
		s := peekText(o, "op") + " " + peekText(o, name) + " { " + x.val(o.peek("elem"), nil)
		if d := o.peek("data"); d != nil {
			s += " : " + x.val(d, nil)
		}
		for _, in := range o.peek("stmt").arr() {
			s += " " + x.stmt(in)
		}
		return s + " }"
	case "meter":
		s := "meter " + peekText(o, "name") + " { " + x.val(o.peek("key"), nil)
		if in := o.peek("stmt"); in != nil {
			s += " " + x.stmt(in)
		}
		return s + " }"
	case "ct helper", "ct timeout", "ct expectation":
		return name + " set " + quote(scalar(v))
	case "queue":
		s := "queue"
		if fs := o.peek("flags").strs(); len(fs) > 0 {
			s += " flags " + strings.Join(fs, ",")
		}
		if num := o.peek("num"); num != nil {
			s += " to " + x.val(num, nil)
		}
		return s
	case "synproxy":
		s := "synproxy"
		for _, k := range []string{"mss", "wscale"} {
			if o.has(k) {
				s += " " + k + " " + scalar(o.peek(k))
			}
		}
		return s + strings.ReplaceAll(flagList(o.peek("flags")), ",", " ")
	case "tproxy":
		s := "tproxy"
		if f := peekText(o, "family"); f != "" {
			s += " " + f
		}
		s += " to "
		if a := o.peek("addr"); a != nil {
			s += x.val(a, nil)
		}
		if p := o.peek("port"); p != nil {
			s += ":" + x.val(p, nil)
		}
		return s
	case "flow":
		return "flow " + peekText(o, "op") + " " + peekText(o, "flowtable")
	case "dup", "fwd":
		s := name + " to " + x.val(o.peek("addr"), nil)
		if d := o.peek("dev"); d != nil {
			s += " device " + x.val(d, []kind{kIface})
		}
		return s
	case "xt":
		return "xt " + peekText(o, "type") + " " + quote(peekText(o, "name"))
	case "":
		return "<?>"
	}
	return "<" + clip(name) + ">"
}

// nat prints masquerade, snat, dnat and redirect.
func (x texter) nat(word string, o *object) string {
	s := word
	if f := peekText(o, "family"); f != "" {
		s += " " + f
	}
	// "snat ip prefix to": the map hands out whole networks. nft then leaves "netmap" unsaid.
	types := o.peek("type_flags").strs()
	if t, ok := o.peek("type_flags").str(); ok {
		types = []string{t}
	}
	prefix := false
	for _, t := range types {
		s += " " + t
		prefix = prefix || t == "prefix"
	}
	var flags []string
	for _, f := range o.peek("flags").strs() {
		if f != "netmap" || !prefix {
			flags = append(flags, f)
		}
	}
	addr, port := o.peek("addr"), o.peek("port")
	if addr != nil || port != nil {
		to := ""
		if addr != nil {
			to = x.val(addr, nil)
		}
		if port != nil {
			if strings.Contains(to, ":") && !strings.ContainsAny(to, " -/") {
				to = "[" + to + "]"
			}
			to += ":" + x.val(port, nil)
		}
		s += " to " + to
	}
	if len(flags) > 0 {
		s += " " + strings.Join(flags, ",")
	}
	return s
}
