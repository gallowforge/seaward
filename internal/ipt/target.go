package ipt

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// topt is one target option with the values that follow it.
type topt struct {
	name string // without the leading dashes
	args []string
}

// targetOpts cuts a target's words into options: each "--name" takes the words after it.
func targetOpts(toks []token) (opts []topt, stray []string) {
	for _, t := range toks {
		if !t.quoted && strings.HasPrefix(t.s, "--") {
			opts = append(opts, topt{name: t.s[2:]})
			continue
		}
		if len(opts) == 0 {
			stray = append(stray, t.s)
			continue
		}
		opts[len(opts)-1].args = append(opts[len(opts)-1].args, t.s)
	}
	return opts, stray
}

func unknownStmt(format string, a ...any) []rules.Expr {
	return []rules.Expr{&rules.UnknownStmt{Why: fmt.Sprintf(format, a...)}}
}

func (p *ruleParser) parseTarget(kind, name string, toks []token) []rules.Expr {
	if ch, ok := p.table.Chains[name]; ok {
		if ch.Base {
			return unknownStmt("the rule jumps to the built-in chain %s, which iptables does not allow", name)
		}
		if len(toks) > 0 {
			p.unknown("the rule has words after its jump to %s that seaward does not understand", name)
		}
		if kind == "g" {
			return []rules.Expr{&rules.Verdict{Kind: rules.Goto, Chain: name}}
		}
		return []rules.Expr{&rules.Verdict{Kind: rules.Jump, Chain: name}}
	}
	if kind == "g" {
		return unknownStmt("the rule goes to %s, which is not a chain in the %s table", name, p.table.Name)
	}
	opts, stray := targetOpts(toks)
	if len(stray) > 0 {
		return unknownStmt("the %s target has words seaward does not understand (%s)", name, clip(strings.Join(stray, " ")))
	}
	get := func(n string) (string, bool) {
		for _, o := range opts {
			if o.name == n && len(o.args) > 0 {
				return o.args[0], true
			}
		}
		return "", false
	}
	has := func(n string) bool {
		for _, o := range opts {
			if o.name == n {
				return true
			}
		}
		return false
	}
	switch name {
	case "ACCEPT":
		return []rules.Expr{&rules.Verdict{Kind: rules.Accept}}
	case "DROP":
		return []rules.Expr{&rules.Verdict{Kind: rules.Drop}}
	case "RETURN":
		return []rules.Expr{&rules.Verdict{Kind: rules.Return}}
	case "REJECT":
		return []rules.Expr{&rules.Verdict{Kind: rules.Reject}}
	case "DNAT":
		var dests []string
		for _, o := range opts {
			if o.name == "to-destination" {
				dests = append(dests, o.args...)
			}
		}
		if len(dests) != 1 {
			return unknownStmt("the DNAT target has %d destinations, and seaward reads exactly one", len(dests))
		}
		d, ok := parseNATDest(dests[0])
		if !ok {
			return unknownStmt("the DNAT target destination %s is not one seaward can read", dests[0])
		}
		return []rules.Expr{d}
	case "REDIRECT":
		r := &rules.Redirect{}
		if v, ok := get("to-ports"); ok {
			lo, hi, ok := natPorts(v)
			if !ok {
				return unknownStmt("the REDIRECT target ports %s are not ones seaward can read", v)
			}
			r.Port, r.PortHi = lo, hi
		}
		return []rules.Expr{r}
	case "MARK", "CONNMARK":
		return p.markTarget(name, opts)
	case "NOTRACK":
		return []rules.Expr{&rules.Notrack{}}
	case "CT":
		if has("notrack") {
			return []rules.Expr{&rules.Notrack{}}
		}
		return []rules.Expr{&rules.Noop{What: "connection tracking settings (CT)"}}
	case "NETMAP", "SNAT", "MASQUERADE":
		// These rewrite the source when they run after routing; anywhere else they would change
		// the destination, which the model only follows for DNAT and REDIRECT.
		// SNAT and MASQUERADE are only allowed there; NETMAP is allowed before routing too.
		if name != "NETMAP" || p.chain == "POSTROUTING" || p.chain == "INPUT" {
			return []rules.Expr{&rules.Noop{What: noopTargets[name] + " (" + name + ")"}}
		}
		return unknownStmt("%s", targetWhy[name])
	}
	if what, ok := noopTargets[name]; ok {
		return []rules.Expr{&rules.Noop{What: what + " (" + name + ")"}}
	}
	if why, ok := targetWhy[name]; ok {
		return unknownStmt("%s", why)
	}
	return unknownStmt("the target %s (-j %s) is not one seaward understands", name, name)
}

// markTarget follows libxt_MARK and libxt_CONNMARK, which turn every form into
// "new = (old AND NOT mask) XOR value". SetMark stores And = NOT mask and Xor = value.
func (p *ruleParser) markTarget(name string, opts []topt) []rules.Expr {
	ct := name == "CONNMARK"
	nfmask, ctmask := uint32(0xffffffff), uint32(0xffffffff)
	var op string
	var val, mask uint32
	for _, o := range opts {
		arg := ""
		if len(o.args) > 0 {
			arg = o.args[0]
		}
		switch o.name {
		case "set-xmark", "set-mark":
			v, m, _, ok := parseMarkMask(arg)
			if !ok {
				return unknownStmt("the %s target value %s is not one seaward can read", name, arg)
			}
			if o.name == "set-mark" {
				// "--set-mark v/m" zeroes the bits of m and sets those of v.
				m |= v
			}
			op, val, mask = "set", v, m
		case "and-mark", "or-mark", "xor-mark":
			v, ok := parseU32(arg)
			if !ok {
				return unknownStmt("the %s target value %s is not a number", name, arg)
			}
			switch o.name {
			case "and-mark":
				op, val, mask = "set", 0, ^v
			case "or-mark":
				op, val, mask = "set", v, v
			case "xor-mark":
				op, val, mask = "set", v, 0
			}
		case "save-mark", "restore-mark":
			if !ct {
				return unknownStmt("the MARK target has an option seaward does not know (--%s)", o.name)
			}
			op = o.name
		case "nfmask", "ctmask", "mask":
			v, ok := parseU32(arg)
			if !ok {
				return unknownStmt("the %s target mask %s is not a number", name, arg)
			}
			if o.name != "ctmask" {
				nfmask = v
			}
			if o.name != "nfmask" {
				ctmask = v
			}
		default:
			return unknownStmt("the %s target option --%s changes marks in a way seaward does not follow", name, o.name)
		}
	}
	switch op {
	case "set":
		return []rules.Expr{&rules.SetMark{Ct: ct, And: ^mask, Xor: val}}
	case "save-mark", "restore-mark":
		if nfmask != ctmask {
			return unknownStmt("the CONNMARK target --%s uses two different masks, which seaward does not follow", op)
		}
		return []rules.Expr{&rules.CopyMark{ToCt: op == "save-mark", Mask: nfmask}}
	}
	return unknownStmt("the %s target does not say how to change the mark", name)
}

// parseNATDest reads every form of --to-destination: "a", "a:p", "a-b", "a-b:p-q", ":p",
// "[v6]:p", "[v6]-[v6]:p" and a bare IPv6 address.
func parseNATDest(s string) (*rules.DNAT, bool) {
	var addrPart, portPart string
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return nil, false
		}
		addrPart = s[1:end]
		rest := s[end+1:]
		if strings.HasPrefix(rest, "-[") {
			end2 := strings.Index(rest, "]")
			if end2 < 0 {
				return nil, false
			}
			addrPart += "-" + rest[2:end2]
			rest = rest[end2+1:]
		}
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return nil, false
			}
			portPart = rest[1:]
		}
	case strings.Count(s, ":") > 1:
		addrPart = s // an IPv6 address without brackets carries no port
	default:
		addrPart, portPart, _ = strings.Cut(s, ":")
	}
	d := &rules.DNAT{}
	if addrPart != "" {
		lo, hi, isRange := strings.Cut(addrPart, "-")
		a, err := netip.ParseAddr(lo)
		if err != nil {
			return nil, false
		}
		d.Addr = a
		if isRange {
			b, err := netip.ParseAddr(hi)
			if err != nil || b.BitLen() != a.BitLen() {
				return nil, false
			}
			d.AddrHi = b
		}
	}
	if portPart != "" {
		lo, hi, ok := natPorts(portPart)
		if !ok {
			return nil, false
		}
		d.Port, d.PortHi = lo, hi
	}
	if addrPart == "" && portPart == "" {
		return nil, false
	}
	return d, true
}

// natPorts reads "p" or "p-q". A base port ("p-q/b") shifts ports in a way the model cannot hold.
func natPorts(s string) (lo, hi uint16, ok bool) {
	if strings.Contains(s, "/") {
		return 0, 0, false
	}
	a, b, isRange := strings.Cut(s, "-")
	x, ok := parsePortNum(a)
	if !ok || x == 0 {
		return 0, 0, false
	}
	if !isRange {
		return uint16(x), 0, true
	}
	y, ok := parsePortNum(b)
	if !ok || y < x {
		return 0, 0, false
	}
	return uint16(x), uint16(y), true
}
