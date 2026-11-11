package ipt

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// genericOpts are the options iptables itself owns, outside any extension.
var genericOpts = map[string]string{
	"-s": "s", "--source": "s", "--src": "s",
	"-d": "d", "--destination": "d", "--dst": "d",
	"-i": "i", "--in-interface": "i",
	"-o": "o", "--out-interface": "o",
	"-p": "p", "--protocol": "p",
	"-f": "f", "--fragment": "f",
	"-4": "4", "--ipv4": "4",
	"-6": "6", "--ipv6": "6",
	"-m": "m", "--match": "m",
	"-j": "j", "--jump": "j",
	"-g": "g", "--goto": "g",
	"-c": "c", "--set-counters": "c",
}

// moduleArity lists, for each match extension the parser understands, how many values each of
// its options takes. An extension missing here is Unknown as a whole.
var moduleArity = map[string]map[string]int{
	"tcp":       {"sport": 1, "source-port": 1, "dport": 1, "destination-port": 1, "tcp-flags": 2, "syn": 0, "tcp-option": 1},
	"udp":       {"sport": 1, "source-port": 1, "dport": 1, "destination-port": 1},
	"udplite":   {"sport": 1, "source-port": 1, "dport": 1, "destination-port": 1},
	"sctp":      {"sport": 1, "source-port": 1, "dport": 1, "destination-port": 1, "chunk-types": 2},
	"dccp":      {"sport": 1, "source-port": 1, "dport": 1, "destination-port": 1, "dccp-types": 1, "dccp-option": 1},
	"multiport": {"dports": 1, "destination-ports": 1, "sports": 1, "source-ports": 1, "ports": 1},
	"conntrack": {"ctstate": 1, "ctproto": 1, "ctorigsrc": 1, "ctorigdst": 1, "ctreplsrc": 1, "ctrepldst": 1,
		"ctorigsrcport": 1, "ctorigdstport": 1, "ctreplsrcport": 1, "ctrepldstport": 1, "ctstatus": 1,
		"ctexpire": 1, "ctdir": 1},
	"state":     {"state": 1},
	"addrtype":  {"src-type": 1, "dst-type": 1, "limit-iface-in": 0, "limit-iface-out": 0},
	"mark":      {"mark": 1},
	"connmark":  {"mark": 1},
	"set":       {"match-set": 2, "return-nomatch": 0, "update-counters": 0, "update-subcounters": 0, "packets-eq": 1, "packets-lt": 1, "packets-gt": 1, "bytes-eq": 1, "bytes-lt": 1, "bytes-gt": 1},
	"iprange":   {"src-range": 1, "dst-range": 1},
	"pkttype":   {"pkt-type": 1},
	"icmp":      {"icmp-type": 1},
	"icmp6":     {"icmpv6-type": 1},
	"ipv6-icmp": {"icmpv6-type": 1},
	"rpfilter":  {"loose": 0, "validmark": 0, "accept-local": 0, "invert": 0},
	"policy":    {"dir": 1, "pol": 1, "strict": 0, "reqid": 1, "spi": 1, "proto": 1, "mode": 1, "tunnel-src": 1, "tunnel-dst": 1, "next": 0},
	"limit":     {"limit": 1, "limit-burst": 1},
	"hashlimit": {"hashlimit": 1, "hashlimit-upto": 1, "hashlimit-above": 1, "hashlimit-burst": 1, "hashlimit-mode": 1,
		"hashlimit-srcmask": 1, "hashlimit-dstmask": 1, "hashlimit-name": 1, "hashlimit-htable-size": 1,
		"hashlimit-htable-max": 1, "hashlimit-htable-expire": 1, "hashlimit-htable-gcinterval": 1,
		"hashlimit-rate-match": 0, "hashlimit-rate-interval": 1},
	"comment":   {"comment": 1},
	"recent":    {"set": 0, "rcheck": 0, "update": 0, "remove": 0, "seconds": 1, "reap": 0, "hitcount": 1, "rttl": 0, "name": 1, "rsource": 0, "rdest": 0, "mask": 1},
	"connlimit": {"connlimit-upto": 1, "connlimit-above": 1, "connlimit-mask": 1, "connlimit-saddr": 0, "connlimit-daddr": 0},
}

// optWhat says what an option of a known extension looks at, when the model cannot follow it.
var optWhat = map[string]string{
	"tcp-option":     "looks at TCP options",
	"chunk-types":    "looks at SCTP chunk types",
	"dccp-types":     "looks at DCCP packet types",
	"dccp-option":    "looks at DCCP options",
	"ctorigsrc":      "looks at the connection's original source address",
	"ctreplsrc":      "looks at the source address of the connection's replies",
	"ctrepldst":      "looks at the destination address of the connection's replies",
	"ctorigsrcport":  "looks at the connection's original source port",
	"ctreplsrcport":  "looks at the source port of the connection's replies",
	"ctrepldstport":  "looks at the destination port of the connection's replies",
	"ctexpire":       "looks at how long the connection has left to live",
	"return-nomatch": "changes what an element marked nomatch means",
	"packets-eq":     "looks at the element's packet counter",
	"packets-lt":     "looks at the element's packet counter",
	"packets-gt":     "looks at the element's packet counter",
	"bytes-eq":       "looks at the element's byte counter",
	"bytes-lt":       "looks at the element's byte counter",
	"bytes-gt":       "looks at the element's byte counter",
}

// mopt is one option of an extension with its values.
type mopt struct {
	neg     bool
	name    string // without the leading dashes
	args    []string
	unknown bool // an option the arity table does not know; args holds whatever followed it
	short   bool // fewer values than the option needs
}

func (o mopt) flag() string { return "--" + o.name }

// splitOpts cuts an extension's words into options using its arity table.
func splitOpts(toks []token, arity map[string]int) []mopt {
	var out []mopt
	for i := 0; i < len(toks); {
		var o mopt
		if !toks[i].quoted && toks[i].s == "!" {
			o.neg = true
			i++
			if i == len(toks) {
				out = append(out, mopt{neg: true, unknown: true, name: "!"})
				break
			}
		}
		t := toks[i]
		i++
		if t.quoted || !strings.HasPrefix(t.s, "-") {
			o.name, o.unknown = t.s, true
			out = append(out, o)
			continue
		}
		o.name = strings.TrimLeft(t.s, "-")
		n, ok := arity[o.name]
		if !ok {
			o.unknown = true
			for i < len(toks) && !(!toks[i].quoted && (strings.HasPrefix(toks[i].s, "--") || toks[i].s == "!")) {
				o.args = append(o.args, toks[i].s)
				i++
			}
			out = append(out, o)
			continue
		}
		for k := 0; k < n; k++ {
			if i == len(toks) {
				o.short = true
				break
			}
			o.args = append(o.args, toks[i].s)
			i++
		}
		out = append(out, o)
	}
	return out
}

// ruleParser turns the words of one rule (after "-A CHAIN") into expressions.
type ruleParser struct {
	toks    []token
	i       int
	family  string
	table   *rules.Table
	chain   string
	setDims map[string][]string
	walk    walkFacts

	exprs     []rules.Expr
	target    []rules.Expr
	protos    map[uint32]bool // protocols a positive -p already requires
	lastProto uint32
	hasProto  bool
}

func (p *ruleParser) add(e rules.Expr) { p.exprs = append(p.exprs, e) }

func (p *ruleParser) unknown(format string, a ...any) {
	p.add(&rules.Unknown{Why: fmt.Sprintf(format, a...)})
}

func match(f rules.FieldName, neg bool, atoms ...rules.Atom) *rules.Match {
	m := rules.Eq(f, atoms...)
	m.Neg = neg
	return m
}

var anyAtom = rules.Atom{Kind: rules.AtomAny}

func (p *ruleParser) isStop(i int) bool {
	if i >= len(p.toks) {
		return true
	}
	t := p.toks[i]
	if t.quoted {
		return false
	}
	if _, ok := genericOpts[t.s]; ok {
		return true
	}
	return t.s == "!" && i+1 < len(p.toks) && !p.toks[i+1].quoted && genericOpts[p.toks[i+1].s] != ""
}

// collect takes the words up to the next option iptables itself owns.
// For a known extension the values of its options are skipped by count, so a value that looks
// like an option ("--comment -s") stays with its option.
func (p *ruleParser) collect(mod string) []token {
	start := p.i
	arity := moduleArity[mod]
	for !p.isStop(p.i) {
		t := p.toks[p.i]
		p.i++
		if n, ok := arity[strings.TrimLeft(t.s, "-")]; ok && !t.quoted && strings.HasPrefix(t.s, "--") {
			for k := 0; k < n && p.i < len(p.toks); k++ {
				p.i++
			}
		}
	}
	return p.toks[start:p.i]
}

func (p *ruleParser) arg() (string, bool) {
	if p.i >= len(p.toks) {
		return "", false
	}
	t := p.toks[p.i]
	p.i++
	return t.s, true
}

func (p *ruleParser) parse() []rules.Expr {
	p.protos = map[uint32]bool{}
	for p.i < len(p.toks) {
		start := p.i
		t := p.toks[p.i]
		neg := false
		if !t.quoted && t.s == "!" {
			neg = true
			p.i++
			if p.i == len(p.toks) {
				p.unknown("the rule ends with a lone \"!\"")
				break
			}
			t = p.toks[p.i]
		}
		kind := ""
		if !t.quoted {
			kind = genericOpts[t.s]
		}
		p.i++
		switch kind {
		case "s", "d", "i", "o", "p":
			v, ok := p.arg()
			if !ok {
				p.unknown("the option %s has no value", t.s)
				continue
			}
			p.generic(kind, v, neg)
		case "f":
			if neg {
				p.add(&rules.Always{What: "not a fragment: a first packet is never one"})
			} else {
				p.add(&rules.Never{What: "fragments only (-f): a first packet is never a later fragment"})
			}
		case "4", "6":
			if (kind == "4") == (p.family == "ip") {
				p.add(&rules.Always{What: "rule for this IP version (" + t.s + ")"})
			} else {
				p.add(&rules.Never{What: "rule for the other IP version (" + t.s + ")"})
			}
		case "c":
			p.arg()
			p.arg()
		case "m":
			name, ok := p.arg()
			opts := p.collect(name)
			if !ok || name == "" {
				p.unknown("the rule names a match (-m) without saying which")
				continue
			}
			if neg {
				p.unknown("the rule puts \"!\" in front of the %s match, which iptables does not allow", name)
				continue
			}
			p.module(name, opts)
		case "j", "g":
			name, ok := p.arg()
			opts := p.collect("")
			if !ok || neg {
				p.unknown("the rule has a target seaward cannot read")
				continue
			}
			p.target = append(p.target, p.parseTarget(kind, name, opts)...)
		default:
			// An option outside any -m: iptables loads the protocol's own extension after -p.
			p.i = start
			mod, ok := protoModule[p.lastProto]
			ok = ok && p.hasProto && !t.quoted && strings.HasPrefix(t.s, "--")
			if !ok {
				mod = ""
			}
			opts := p.collect(mod)
			if ok {
				p.module(mod, opts)
				continue
			}
			words := make([]string, len(opts))
			for k, o := range opts {
				words[k] = o.s
			}
			p.unknown("the rule has words seaward does not understand (%s)", clip(strings.Join(words, " ")))
		}
	}
	return append(p.exprs, p.target...)
}

func (p *ruleParser) generic(kind, v string, neg bool) {
	switch kind {
	case "s", "d":
		f, what := rules.FSaddr, "source"
		if kind == "d" {
			f, what = rules.FDaddr, "destination"
		}
		var atoms []rules.Atom
		for _, part := range strings.Split(v, ",") {
			pf, why := parsePrefix(part)
			if why != "" {
				p.unknown("the %s address %s %s", what, part, why)
				return
			}
			atoms = append(atoms, rules.Pfx(pf))
		}
		p.add(match(f, neg, atoms...))
	case "i", "o":
		f := rules.FIifName
		if kind == "o" {
			f = rules.FOifName
		}
		p.add(match(f, neg, ifaceAtom(v)))
	case "p":
		n, all, ok := parseProto(v)
		switch {
		case !ok:
			p.unknown("the protocol %s is not one seaward knows", v)
		case all && neg:
			p.add(&rules.Never{What: "no protocol at all (! -p all)"})
		case all:
			p.add(&rules.Always{What: "any protocol (-p all)"})
		default:
			p.add(match(rules.FL4Proto, neg, rules.Num(n)))
			if !neg {
				p.protos[n] = true
				p.lastProto, p.hasProto = n, true
			}
		}
	}
}

// ifaceAtom reads an interface name; a trailing "+" means every name that starts with the rest.
func ifaceAtom(v string) rules.Atom {
	if strings.HasSuffix(v, "+") {
		return rules.StrPfx(strings.TrimSuffix(v, "+"))
	}
	return rules.Str(v)
}

// parsePrefix reads an address, a CIDR network or an address with a dotted mask. A non-empty
// second result is the end of a sentence saying why it could not.
func parsePrefix(s string) (netip.Prefix, string) {
	addrS, maskS, hasMask := strings.Cut(s, "/")
	a, err := netip.ParseAddr(addrS)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, "is not an address seaward can read (a host name is looked up only when the rule is loaded)"
	}
	bits := a.BitLen()
	if hasMask {
		if n, err := strconv.Atoi(maskS); err == nil && !strings.HasPrefix(maskS, "+") && !strings.HasPrefix(maskS, "-") {
			if n < 0 || n > bits {
				return netip.Prefix{}, "has a prefix length out of range"
			}
			bits = n
		} else {
			m, err := netip.ParseAddr(maskS)
			if err != nil || m.BitLen() != a.BitLen() {
				return netip.Prefix{}, "has a mask seaward cannot read"
			}
			n, ok := maskLen(m.AsSlice())
			if !ok {
				return netip.Prefix{}, "has a mask with gaps in it, which seaward cannot represent"
			}
			bits = n
		}
	}
	return netip.PrefixFrom(a, bits).Masked(), ""
}

// maskLen counts the leading one bits of a mask and says whether the rest are all zero.
func maskLen(b []byte) (int, bool) {
	n, zero := 0, false
	for _, x := range b {
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<bit) != 0 {
				if zero {
					return 0, false
				}
				n++
			} else {
				zero = true
			}
		}
	}
	return n, true
}

func parseU32(s string) (uint32, bool) {
	v, err := strconv.ParseUint(s, 0, 32)
	return uint32(v), err == nil
}

// parseMarkMask reads "v" or "v/m".
func parseMarkMask(s string) (v, m uint32, hasMask, ok bool) {
	vs, ms, hasMask := strings.Cut(s, "/")
	if v, ok = parseU32(vs); !ok {
		return 0, 0, false, false
	}
	if !hasMask {
		return v, 0xffffffff, false, true
	}
	m, ok = parseU32(ms)
	return v, m, true, ok
}

// needProto adds the protocol condition a port or type extension carries with it, unless a
// positive -p already said the same.
func (p *ruleParser) needProto(n uint32) {
	if !p.protos[n] {
		p.add(rules.Eq(rules.FL4Proto, rules.Num(n)))
		p.protos[n] = true
	}
}

func (p *ruleParser) module(name string, toks []token) {
	arity, known := moduleArity[name]
	if !known {
		p.unknown("%s", unknownModule(name))
		return
	}
	if p.table.Name == "raw" && (name == "conntrack" || name == "state" || name == "connmark") {
		// The raw table runs before connection tracking has looked the packet up, so these see
		// no connection (or "untracked" after a NOTRACK rule), not the state the walk assumes.
		p.unknown("the %s match in the raw table runs before connection tracking, so its answer depends on earlier raw rules", name)
		return
	}
	opts := splitOpts(toks, arity)
	var rest []mopt
	for _, o := range opts {
		switch {
		case o.unknown:
			p.unknown("the %s match has an option seaward does not know (%s)", name, clip(strings.TrimSpace(o.flag()+" "+strings.Join(o.args, " "))))
		case o.short:
			p.unknown("the %s match option %s is missing its value", name, o.flag())
		default:
			rest = append(rest, o)
		}
	}
	switch name {
	case "tcp", "udp", "udplite", "sctp", "dccp":
		p.needProto(moduleProto[name])
		p.ports(name, rest)
	case "multiport":
		p.multiport(rest)
	case "conntrack":
		p.conntrack(rest)
	case "state":
		for _, o := range rest {
			p.ctstate("state", o)
		}
	case "addrtype":
		p.addrtype(rest)
	case "mark", "connmark":
		f := rules.FMark
		if name == "connmark" {
			f = rules.FCtMark
		}
		for _, o := range rest {
			v, m, hasMask, ok := parseMarkMask(o.args[0])
			if !ok {
				p.unknown("the %s match value %s is not a number", name, o.args[0])
				continue
			}
			key := rules.Field{Name: f}
			if hasMask {
				key.Mask, key.HasMask = m, true
			}
			p.add(&rules.Match{Key: []rules.Field{key}, Neg: o.neg, Values: rules.One(rules.Num(v))})
		}
	case "set":
		p.set(rest)
	case "iprange":
		for _, o := range rest {
			f := rules.FSaddr
			if o.name == "dst-range" {
				f = rules.FDaddr
			}
			a, ok := parseAddrRange(o.args[0])
			if !ok {
				p.unknown("the iprange match range %s is not one seaward can read", o.args[0])
				continue
			}
			p.add(match(f, o.neg, a))
		}
	case "pkttype":
		for _, o := range rest {
			v, ok := pktTypes[strings.ToLower(o.args[0])]
			if !ok {
				p.unknown("the pkttype match looks for %s packets, which seaward does not model", o.args[0])
				continue
			}
			p.add(match(rules.FPktType, o.neg, rules.Num(v)))
		}
	case "icmp":
		p.needProto(1)
		for _, o := range rest {
			p.icmp(o, rules.FICMPType, icmpNames, "icmp")
		}
	case "icmp6", "ipv6-icmp":
		p.needProto(58)
		for _, o := range rest {
			p.icmp(o, rules.FICMPv6Type, icmp6Names, name)
		}
	case "rpfilter":
		p.rpfilter(rest)
	case "policy":
		p.policy(rest)
	case "limit":
		p.add(&rules.Always{What: "rate limit (-m limit): its burst lets a first packet through"})
	case "hashlimit":
		above := false
		for _, o := range rest {
			if o.name == "hashlimit-above" {
				above = true
			}
		}
		if above {
			p.add(&rules.Never{What: "rate above a limit (-m hashlimit --hashlimit-above): a first packet is never over it"})
		} else {
			p.add(&rules.Always{What: "rate limit (-m hashlimit): its burst lets a first packet through"})
		}
	case "comment":
		text := ""
		for _, o := range rest {
			text = o.args[0]
		}
		p.add(&rules.Always{What: "comment: " + text})
	case "recent":
		p.recent(rest)
	case "connlimit":
		p.connlimit(rest)
	}
}

func (p *ruleParser) ports(name string, opts []mopt) {
	for _, o := range opts {
		switch o.name {
		case "sport", "source-port", "dport", "destination-port":
			f := rules.FSport
			if o.name == "dport" || o.name == "destination-port" {
				f = rules.FDport
			}
			a, ok := parsePortRange(o.args[0], ":")
			if !ok {
				p.unknown("the %s match port %s is not one seaward can read", name, o.args[0])
				continue
			}
			p.add(match(f, o.neg, a))
		case "tcp-flags", "syn":
			if name != "tcp" {
				p.unknown("the %s match has an option seaward does not know (%s)", name, o.flag())
				continue
			}
			mask, comp := uint32(0x17), uint32(0x02) // --syn is FIN,SYN,RST,ACK SYN
			if o.name == "tcp-flags" {
				var ok1, ok2 bool
				mask, ok1 = tcpFlags(o.args[0])
				comp, ok2 = tcpFlags(o.args[1])
				if !ok1 || !ok2 {
					p.unknown("the tcp match flags %s %s are not ones seaward can read", o.args[0], o.args[1])
					continue
				}
			}
			p.add(&rules.Match{Key: []rules.Field{{Name: rules.FTCPFlags, Mask: mask, HasMask: true}}, Neg: o.neg, Values: rules.One(rules.Num(comp))})
		default:
			p.unknown("the %s match option %s %s, which seaward does not model", name, o.flag(), optWhat[o.name])
		}
	}
}

var tcpFlagBits = map[string]uint32{"FIN": 1, "SYN": 2, "RST": 4, "PSH": 8, "ACK": 16, "URG": 32, "ALL": 0x3f, "NONE": 0}

func tcpFlags(s string) (uint32, bool) {
	var v uint32
	for _, f := range strings.Split(s, ",") {
		b, ok := tcpFlagBits[strings.ToUpper(f)]
		if !ok {
			return 0, false
		}
		v |= b
	}
	return v, true
}

func (p *ruleParser) multiport(opts []mopt) {
	for _, o := range opts {
		var atoms []rules.Atom
		ok := true
		for _, part := range strings.Split(o.args[0], ",") {
			a, good := parsePortRange(part, ":")
			if !good {
				ok = false
				break
			}
			atoms = append(atoms, a)
		}
		if !ok {
			p.unknown("the multiport match list %s is not one seaward can read", o.args[0])
			continue
		}
		switch o.name {
		case "sports", "source-ports":
			p.add(match(rules.FSport, o.neg, atoms...))
		case "dports", "destination-ports":
			p.add(match(rules.FDport, o.neg, atoms...))
		case "ports":
			// Either port may be in the list: a two-field key with a wildcard on the other side.
			m := &rules.Match{Key: []rules.Field{{Name: rules.FSport}, {Name: rules.FDport}}, Neg: o.neg, Values: &rules.Set{}}
			for _, a := range atoms {
				m.Values.Elems = append(m.Values.Elems, rules.Elem{a, anyAtom}, rules.Elem{anyAtom, a})
			}
			p.add(m)
		}
	}
}

// ctstate handles --ctstate and --state. SNAT and DNAT in a ctstate list are status bits, not
// states: the list passes when the state is one of the others or one of those bits is set. That
// "or" across fields is a multi-field key whose other fields are wildcards.
func (p *ruleParser) ctstate(mod string, o mopt) {
	var states []rules.Atom
	dnat, snat := false, false
	for _, s := range strings.Split(o.args[0], ",") {
		s = strings.ToUpper(s)
		if v, ok := ctStates[s]; ok {
			states = append(states, rules.Num(v))
			continue
		}
		if mod == "conntrack" && s == "DNAT" {
			dnat = true
			continue
		}
		if mod == "conntrack" && s == "SNAT" {
			snat = true
			continue
		}
		p.unknown("the %s match state %s is not one seaward knows", mod, s)
		return
	}
	if !dnat && !snat {
		p.add(match(rules.FCtState, o.neg, states...))
		return
	}
	var key []rules.Field
	if len(states) > 0 {
		key = append(key, rules.Field{Name: rules.FCtState})
	}
	if dnat {
		key = append(key, rules.Field{Name: rules.FCtStatusDNAT})
	}
	if snat {
		key = append(key, rules.Field{Name: rules.FCtStatusSNAT})
	}
	m := &rules.Match{Key: key, Neg: o.neg, Values: &rules.Set{}}
	elem := func(f rules.FieldName, a rules.Atom) rules.Elem {
		e := make(rules.Elem, len(key))
		for i, k := range key {
			if k.Name == f {
				e[i] = a
			} else {
				e[i] = anyAtom
			}
		}
		return e
	}
	for _, s := range states {
		m.Values.Elems = append(m.Values.Elems, elem(rules.FCtState, s))
	}
	if dnat {
		m.Values.Elems = append(m.Values.Elems, elem(rules.FCtStatusDNAT, rules.Num(1)))
	}
	if snat {
		m.Values.Elems = append(m.Values.Elems, elem(rules.FCtStatusSNAT, rules.Num(1)))
	}
	p.add(m)
}

// conntrack follows the kernel's order of tests. For a packet with no connection (invalid or
// untracked) the kernel stops after --ctstate: the match is then the state test alone if there is
// one, and false otherwise.
func (p *ruleParser) conntrack(opts []mopt) {
	var state *mopt
	var others []mopt
	for i := range opts {
		if opts[i].name == "ctstate" {
			state = &opts[i]
		} else {
			others = append(others, opts[i])
		}
	}
	if state != nil {
		p.ctstate("conntrack", *state)
	}
	if len(others) == 0 {
		return
	}
	if state != nil {
		mayBeNone := state.neg
		for _, s := range strings.Split(strings.ToUpper(state.args[0]), ",") {
			if s == "INVALID" || s == "UNTRACKED" {
				mayBeNone = true
			}
		}
		if mayBeNone {
			p.unknown("the conntrack match skips its other tests for packets without a connection, which seaward cannot express here")
			return
		}
	} else {
		// Without a state test, a packet without a connection fails every other test.
		p.add(rules.Eq(rules.FCtState, rules.Num(rules.CtNew), rules.Num(rules.CtEstablished), rules.Num(rules.CtRelated)))
	}
	for _, o := range others {
		switch o.name {
		case "ctproto":
			n, all, ok := parseProto(o.args[0])
			switch {
			case !ok:
				p.unknown("the conntrack match protocol %s is not one seaward knows", o.args[0])
			case all && o.neg:
				// The kernel compares with 0, which no real connection has.
				p.add(&rules.Always{What: "connection protocol is not 0"})
			case all:
				p.add(&rules.Never{What: "connection protocol 0, which no connection has"})
			default:
				// A new connection's original protocol is the packet's own.
				p.add(match(rules.FL4Proto, o.neg, rules.Num(n)))
			}
		case "ctorigdst":
			pf, why := parsePrefix(o.args[0])
			if why != "" {
				p.unknown("the conntrack match address %s %s", o.args[0], why)
				continue
			}
			p.add(match(rules.FCtOrigDaddr, o.neg, rules.Pfx(pf)))
		case "ctorigdstport":
			a, ok := parsePortRange(o.args[0], ":")
			if !ok {
				p.unknown("the conntrack match port %s is not one seaward can read", o.args[0])
				continue
			}
			p.add(match(rules.FCtOrigDport, o.neg, a))
		case "ctdir":
			switch strings.ToUpper(o.args[0]) {
			case "ORIGINAL":
				p.add(match(rules.FCtDirection, o.neg, rules.Num(0)))
			case "REPLY":
				p.add(match(rules.FCtDirection, o.neg, rules.Num(1)))
			default:
				p.unknown("the conntrack match direction %s is not one seaward knows", o.args[0])
			}
		case "ctstatus":
			bad := ""
			for _, s := range strings.Split(strings.ToUpper(o.args[0]), ",") {
				if !ctStatuses[s] {
					bad = s
				}
			}
			if bad != "" {
				p.unknown("the conntrack match status %s is not one seaward knows", bad)
				continue
			}
			// EXPECTED, SEEN_REPLY, ASSURED and CONFIRMED are all clear on the first packet of a
			// new connection, so the test is false, or true with "!" (the guard above already
			// covers packets without a connection).
			if o.neg {
				p.add(&rules.Always{What: "connection status not " + o.args[0] + ": none of these is set on a first packet"})
			} else {
				p.add(&rules.Never{What: "connection status " + o.args[0] + ": none of these is set on a first packet"})
			}
		default:
			what := optWhat[o.name]
			if what == "" {
				what = "is a test"
			}
			p.unknown("the conntrack match option %s %s, which seaward does not model", o.flag(), what)
		}
	}
}

func (p *ruleParser) addrtype(opts []mopt) {
	for _, o := range opts {
		if o.name == "limit-iface-in" || o.name == "limit-iface-out" {
			p.unknown("the addrtype match with %s only counts the addresses of one interface, which seaward does not model", o.flag())
			return
		}
	}
	for _, o := range opts {
		f := rules.FFibSaddrType
		if o.name == "dst-type" {
			f = rules.FFibDaddrType
		}
		var atoms []rules.Atom
		for _, s := range strings.Split(o.args[0], ",") {
			v, ok := addrTypes[strings.ToUpper(s)]
			if !ok {
				atoms = nil
				p.unknown("the addrtype match type %s is not one seaward knows", s)
				break
			}
			atoms = append(atoms, rules.Num(v))
		}
		if atoms != nil {
			p.add(match(f, o.neg, atoms...))
		}
	}
}

func (p *ruleParser) set(opts []mopt) {
	for _, o := range opts {
		switch o.name {
		case "match-set":
			p.setMatch(o.args[0], o.args[1], o.neg)
		case "update-counters", "update-subcounters":
			// Only says whether the element's counters are updated; the outcome is the same.
		default:
			p.unknown("the set match option %s %s, which seaward does not model", o.flag(), optWhat[o.name])
		}
	}
}

// setMatch builds the key of an ipset lookup from the set's dimensions and the direction flags.
func (p *ruleParser) setMatch(name, flagList string, neg bool) {
	if p.walk.setFilled[name] {
		p.unknown("the ipset %s is also filled by a rule (-j SET), so a first packet may put itself in it", name)
		return
	}
	dims, ok := p.setDims[name]
	if !ok {
		p.unknown("the ipset %s was not captured, so seaward cannot tell what is in it", name)
		return
	}
	if len(dims) == 0 {
		p.unknown("the ipset %s has a type seaward could not read", name)
		return
	}
	flags := strings.Split(flagList, ",")
	for _, f := range flags {
		if f != "src" && f != "dst" {
			p.unknown("the ipset %s is looked up with a direction seaward does not know (%s)", name, f)
			return
		}
	}
	if len(flags) < len(dims) {
		// The kernel answers "not in the set" when there are fewer directions than parts.
		if neg {
			p.add(&rules.Always{What: "ipset " + name + " given fewer directions than it has parts"})
		} else {
			p.add(&rules.Never{What: "ipset " + name + " given fewer directions than it has parts"})
		}
		return
	}
	var key []rules.Field
	for i, d := range dims {
		src := flags[i] == "src"
		base, maskS, hasMask := strings.Cut(d, "/")
		pick := func(s, dst rules.FieldName) rules.FieldName {
			if src {
				return s
			}
			return dst
		}
		switch base {
		case "ip", "net":
			key = append(key, rules.Field{Name: pick(rules.FSaddr, rules.FDaddr)})
		case "port":
			key = append(key, rules.Field{Name: rules.FL4Proto}, rules.Field{Name: pick(rules.FSport, rules.FDport)})
		case "port-only":
			key = append(key, rules.Field{Name: pick(rules.FSport, rules.FDport)})
		case "iface":
			key = append(key, rules.Field{Name: pick(rules.FIifName, rules.FOifName)})
		case "mark":
			f := rules.Field{Name: rules.FMark}
			if hasMask {
				m, ok := parseU32(maskS)
				if !ok {
					p.unknown("the ipset %s has a mark mask seaward cannot read", name)
					return
				}
				f.Mask, f.HasMask = m, true
			}
			key = append(key, f)
		case "mac":
			p.unknown("the ipset %s holds hardware (MAC) addresses, which seaward does not model", name)
			return
		default:
			p.unknown("the ipset %s has a part (%s) seaward does not understand", name, d)
			return
		}
	}
	p.add(&rules.Match{Key: key, Neg: neg, SetRef: rules.SetKey("", "", name)})
}

// parseAddrRange reads "a-b" or a single address.
func parseAddrRange(s string) (rules.Atom, bool) {
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := netip.ParseAddr(lo)
	if err != nil {
		return rules.Atom{}, false
	}
	if !isRange {
		return rules.Pfx(netip.PrefixFrom(a, a.BitLen())), true
	}
	b, err := netip.ParseAddr(hi)
	if err != nil || a.BitLen() != b.BitLen() {
		return rules.Atom{}, false
	}
	if b.Less(a) {
		a, b = b, a
	}
	return rules.Atom{Kind: rules.AtomRange, AddrLo: a, AddrHi: b}, true
}

func (p *ruleParser) icmp(o mopt, f rules.FieldName, names map[string]icmpType, mod string) {
	v := o.args[0]
	if strings.EqualFold(v, "any") {
		if o.neg {
			p.add(&rules.Never{What: "no " + mod + " type at all"})
		} else {
			p.add(&rules.Always{What: "any " + mod + " type"})
		}
		return
	}
	var t icmpType
	if ts, cs, hasCode := strings.Cut(v, "/"); isDigits(ts) {
		n, err := strconv.ParseUint(ts, 10, 8)
		if err != nil {
			p.unknown("the %s match type %s is not one seaward can read", mod, v)
			return
		}
		t.typ = uint32(n)
		if hasCode {
			c, err := strconv.ParseUint(cs, 10, 8)
			if err != nil {
				p.unknown("the %s match type %s is not one seaward can read", mod, v)
				return
			}
			t.code, t.hasCode = uint32(c), true
		}
	} else {
		var ok bool
		if t, ok = names[strings.ToLower(v)]; !ok {
			p.unknown("the %s match type %s is not one seaward knows", mod, v)
			return
		}
	}
	if t.hasCode {
		p.unknown("the %s match checks code %d of type %d, and seaward models only the type", mod, t.code, t.typ)
		return
	}
	p.add(match(f, o.neg, rules.Num(t.typ)))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (p *ruleParser) rpfilter(opts []mopt) {
	invert := false
	var odd []string
	for _, o := range opts {
		if o.name == "invert" {
			invert = true
		} else {
			odd = append(odd, o.flag())
		}
	}
	if len(odd) > 0 {
		p.unknown("the rpfilter match with %s checks the route back to the sender in a way seaward does not model", strings.Join(odd, " "))
		return
	}
	v := uint32(1)
	if invert {
		v = 0
	}
	p.add(rules.Eq(rules.FRpfOK, rules.Num(v)))
}

func (p *ruleParser) policy(opts []mopt) {
	dir, pol := "", ""
	var details []string
	for _, o := range opts {
		switch o.name {
		case "dir":
			dir = strings.ToLower(o.args[0])
		case "pol":
			pol = strings.ToLower(o.args[0])
		default:
			details = append(details, o.flag())
		}
	}
	if dir != "in" {
		p.unknown("the policy match looks at the IPsec policy for leaving packets (--dir %s), which seaward does not model", dir)
		return
	}
	switch pol {
	case "none":
		p.add(rules.Eq(rules.FIPSecIn, rules.Num(0)))
	case "ipsec":
		p.add(rules.Eq(rules.FIPSecIn, rules.Num(1)))
		if len(details) > 0 {
			p.unknown("the policy match checks details of the IPsec policy (%s), which seaward does not model", strings.Join(details, " "))
		}
	default:
		p.unknown("the policy match policy %q is not one seaward knows", pol)
	}
}

func (p *ruleParser) recent(opts []mopt) {
	check, set, neg, name, hits := "", false, false, "DEFAULT", uint32(0)
	for _, o := range opts {
		switch o.name {
		case "name":
			name = o.args[0]
		case "hitcount":
			hits, _ = parseU32(o.args[0])
		case "rcheck", "update", "remove":
			check, neg = o.name, o.neg
		case "set":
			set = true
			if o.neg {
				neg = true
			}
		}
	}
	// Each "--set" rule the packet passed earlier adds one hit to the list for this very packet.
	if check != "" && p.walk.recentSets[name] > 0 && int(hits) <= p.walk.recentSets[name] {
		p.unknown("the recent match checks the list %s, which other rules fill, so a first packet may already be on it", name)
		return
	}
	switch {
	case check != "" && neg:
		p.add(&rules.Always{What: "not seen recently (! -m recent --" + check + "): a first packet's sender was never seen"})
	case check != "":
		p.add(&rules.Never{What: "seen recently (-m recent --" + check + "): a first packet's sender was never seen"})
	case set && neg:
		p.add(&rules.Never{What: "! -m recent --set never matches"})
	default:
		p.add(&rules.Always{What: "remember the sender (-m recent --set)"})
	}
}

// connlimit counts the new connection too, so a first connection from a sender is a count of 1.
func (p *ruleParser) connlimit(opts []mopt) {
	full := uint32(32)
	if p.family == "ip6" {
		full = 128
	}
	for _, o := range opts {
		mask, ok := parseU32(strings.Join(o.args, ""))
		if o.name == "connlimit-daddr" || (o.name == "connlimit-mask" && (!ok || mask < full)) {
			p.unknown("the connlimit match counts connections from more than one sender (%s), which seaward cannot know", o.flag())
			return
		}
	}
	for _, o := range opts {
		if o.name != "connlimit-above" && o.name != "connlimit-upto" {
			continue
		}
		n, ok := parseU32(o.args[0])
		if !ok {
			p.unknown("the connlimit match limit %s is not a number", o.args[0])
			return
		}
		pass := 1 > n
		if o.name == "connlimit-upto" {
			pass = 1 <= n
		}
		if o.neg {
			pass = !pass
		}
		what := fmt.Sprintf("connection count %s%s %d (a first connection counts 1)", map[bool]string{true: "! ", false: ""}[o.neg], o.flag(), n)
		if pass {
			p.add(&rules.Always{What: what})
		} else {
			p.add(&rules.Never{What: what})
		}
		return
	}
	p.unknown("the connlimit match has no limit seaward can read")
}
