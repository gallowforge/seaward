package ipt

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// The dump is a stable, readable rendering of the model, used by the golden tests.

var fieldNames = map[rules.FieldName]string{
	rules.FSaddr: "saddr", rules.FDaddr: "daddr", rules.FSport: "sport", rules.FDport: "dport",
	rules.FL4Proto: "l4proto", rules.FNFProto: "nfproto", rules.FIifName: "iifname",
	rules.FOifName: "oifname", rules.FMark: "mark", rules.FCtMark: "ctmark", rules.FCtState: "ctstate",
	rules.FCtStatusDNAT: "ctstatus-dnat", rules.FCtStatusSNAT: "ctstatus-snat",
	rules.FCtOrigDaddr: "ct-orig-daddr", rules.FCtOrigDport: "ct-orig-dport", rules.FCtDirection: "ctdir",
	rules.FFibDaddrType: "daddr-type", rules.FFibSaddrType: "saddr-type", rules.FRpfOK: "rpf-ok",
	rules.FPktType: "pkttype", rules.FTCPFlags: "tcpflags", rules.FICMPType: "icmp-type",
	rules.FICMPv6Type: "icmpv6-type", rules.FIPSecIn: "ipsec-in",
	rules.FFibDaddrTypeIif: "daddr-type-on-iif", rules.FFibSaddrTypeIif: "saddr-type-on-iif",
}

func dumpField(f rules.Field) string {
	s := fieldNames[f.Name]
	if f.HasMask {
		s += fmt.Sprintf("&0x%x", f.Mask)
	}
	return s
}

func dumpAtom(a rules.Atom) string {
	switch a.Kind {
	case rules.AtomAny:
		return "*"
	case rules.AtomPrefix:
		return a.Prefix.String()
	case rules.AtomRange:
		return a.AddrLo.String() + "-" + a.AddrHi.String()
	case rules.AtomNum:
		if a.Lo == a.Hi {
			return fmt.Sprint(a.Lo)
		}
		return fmt.Sprintf("%d-%d", a.Lo, a.Hi)
	case rules.AtomStr:
		return fmt.Sprintf("%q", a.S)
	case rules.AtomStrPfx:
		return fmt.Sprintf("%q*", a.S)
	}
	return "?"
}

func dumpElems(es []rules.Elem) string {
	var parts []string
	for _, e := range es {
		var as []string
		for _, a := range e {
			as = append(as, dumpAtom(a))
		}
		if len(as) == 1 {
			parts = append(parts, as[0])
		} else {
			parts = append(parts, "("+strings.Join(as, " . ")+")")
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

var verdictNames = map[rules.VerdictKind]string{
	rules.Accept: "accept", rules.Drop: "drop", rules.Reject: "reject", rules.Return: "return",
	rules.Continue: "continue", rules.Jump: "jump", rules.Goto: "goto",
}

func dumpExpr(e rules.Expr) string {
	switch x := e.(type) {
	case *rules.Match:
		var ks []string
		for _, f := range x.Key {
			ks = append(ks, dumpField(f))
		}
		op := "in"
		if x.Neg {
			op = "not in"
		}
		val := ""
		if x.SetRef != "" {
			val = "@" + strings.ReplaceAll(x.SetRef, "\x00", "/")
		} else if x.Values != nil {
			val = dumpElems(x.Values.Elems)
		}
		return fmt.Sprintf("match %s %s %s", strings.Join(ks, " . "), op, val)
	case *rules.Unknown:
		return "unknown: " + x.Why
	case *rules.Always:
		return "always: " + x.What
	case *rules.Never:
		return "never: " + x.What
	case *rules.Notrack:
		return "notrack"
	case *rules.Verdict:
		if x.Chain != "" {
			return verdictNames[x.Kind] + " " + x.Chain
		}
		return verdictNames[x.Kind]
	case *rules.DNAT:
		s := "dnat"
		if x.Addr.IsValid() {
			s += " addr " + x.Addr.String()
			if x.AddrHi.IsValid() {
				s += "-" + x.AddrHi.String()
			}
		}
		if x.Port != 0 {
			s += fmt.Sprintf(" port %d", x.Port)
			if x.PortHi != 0 {
				s += fmt.Sprintf("-%d", x.PortHi)
			}
		}
		if x.Random {
			s += " random"
		}
		return s
	case *rules.Redirect:
		s := "redirect"
		if x.Port != 0 {
			s += fmt.Sprintf(" port %d", x.Port)
			if x.PortHi != 0 {
				s += fmt.Sprintf("-%d", x.PortHi)
			}
		}
		if x.Random {
			s += " random"
		}
		return s
	case *rules.SetMark:
		return fmt.Sprintf("setmark ct=%v and=0x%x xor=0x%x", x.Ct, x.And, x.Xor)
	case *rules.CopyMark:
		return fmt.Sprintf("copymark toct=%v mask=0x%x", x.ToCt, x.Mask)
	case *rules.Noop:
		return "noop: " + x.What
	case *rules.UnknownStmt:
		return "unknown statement: " + x.Why
	}
	return fmt.Sprintf("?%T", e)
}

func dumpTables(tables []*rules.Table, notes []string) string {
	var b strings.Builder
	for _, n := range notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	for _, t := range tables {
		fmt.Fprintf(&b, "table %s %s (%s)\n", t.Family, t.Name, t.Origin)
		for _, name := range t.Order {
			c := t.Chains[name]
			if c.Base {
				fmt.Fprintf(&b, "  chain %s: hook %s, type %s, priority %d, policy %s\n", c.Name, c.Hook, c.Type, c.Priority, verdictNames[c.Policy])
			} else {
				fmt.Fprintf(&b, "  chain %s\n", c.Name)
			}
			for _, r := range c.Rules {
				fmt.Fprintf(&b, "    %s\n", r.Text)
				for _, e := range r.Exprs {
					fmt.Fprintf(&b, "      %s\n", dumpExpr(e))
				}
			}
		}
	}
	return b.String()
}

func dumpSets(sets map[string]*rules.Set, dims map[string][]string, notes []string) string {
	var b strings.Builder
	for _, n := range notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	var names []string
	for k := range dims {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		s := sets[rules.SetKey("", "", n)]
		fmt.Fprintf(&b, "set %s dims %s dynamic=%v incomplete=%v", n, strings.Join(dims[n], ","), s.Dynamic, s.Incomplete)
		if s.Why != "" {
			fmt.Fprintf(&b, " why=%q", s.Why)
		}
		fmt.Fprintf(&b, "\n  %s\n", dumpElems(s.Elems))
	}
	return b.String()
}
