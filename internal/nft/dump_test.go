package nft

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/ipt"
	"github.com/gallowforge/seaward/internal/rules"
)

// The fixtures in testdata. Every .json but one is what nft 1.1.7 printed with "nft -j list
// ruleset" in a private network namespace, next to the same ruleset as text (.txt) and, for the
// tables iptables 1.8.13 (nf_tables) made, what iptables-save and ip6tables-save printed for it
// (.save, .save6).
//
//	native            an inet table made with nft: sets, maps, ct, fib, marks, nat (native.nft)
//	native-more       the rarer statements and matches, named objects, a dormant table, tables of
//	                  the families seaward leaves out
//	iptables          a wide spread of iptables and ip6tables rules: what comes out as xt
//	iptables-more     the rest of what iptables-nft writes natively
//	mixed             iptables rules, then nft rules added to the same "ip filter" table: an
//	                  anonymous set, a named set, a verdict map. mixed.save shows how iptables-save
//	                  misprints them.
//	firewalld-handwritten
//	                  NOT from a real tool: an "inet firewalld" table written by hand in the shape
//	                  firewalld gives its ruleset, since firewalld is not installed here.
var fixtures = []string{"native", "native-more", "iptables", "iptables-more", "mixed", "firewalld-handwritten"}

func readFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sharedOf parses the iptables-save text that goes with a fixture, if it has any.
func sharedOf(t testing.TB, name string) []*rules.Table {
	t.Helper()
	var shared []*rules.Table
	for ext, family := range map[string]string{".save": "ip", ".save6": "ip6"} {
		b, err := os.ReadFile(filepath.Join("testdata", name+ext))
		if err != nil {
			continue
		}
		ts, _, err := ipt.ParseSave(string(b), ipt.Options{Family: family})
		if err != nil {
			t.Fatalf("%s%s: %v", name, ext, err)
		}
		shared = append(shared, ts...)
	}
	sort.SliceStable(shared, func(i, j int) bool { return shared[i].Family < shared[j].Family })
	return shared
}

// load parses a fixture the way the snapshot does: with the iptables-save tables beside it.
func load(t testing.TB, name string) *rules.Ruleset {
	t.Helper()
	rs, err := ParseJSON(readFile(t, name+".json"), sharedOf(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return rs
}

var fieldNames = map[rules.FieldName]string{
	rules.FSaddr: "saddr", rules.FDaddr: "daddr", rules.FSport: "sport", rules.FDport: "dport",
	rules.FL4Proto: "l4proto", rules.FNFProto: "nfproto", rules.FIifName: "iif", rules.FOifName: "oif",
	rules.FMark: "mark", rules.FCtMark: "ctmark", rules.FCtState: "ctstate",
	rules.FCtStatusDNAT: "ct-dnat", rules.FCtStatusSNAT: "ct-snat", rules.FCtOrigDaddr: "ct-orig-daddr",
	rules.FCtOrigDport: "ct-orig-dport", rules.FCtDirection: "ct-dir", rules.FFibDaddrType: "daddr-type",
	rules.FFibSaddrType: "saddr-type", rules.FRpfOK: "rpf-ok", rules.FPktType: "pkttype",
	rules.FTCPFlags: "tcpflags", rules.FICMPType: "icmp-type", rules.FICMPv6Type: "icmpv6-type",
	rules.FIPSecIn: "ipsec-in", rules.FFibDaddrTypeIif: "daddr-type-iif", rules.FFibSaddrTypeIif: "saddr-type-iif",
}

var verdictNames = map[rules.VerdictKind]string{
	rules.Accept: "accept", rules.Drop: "drop", rules.Reject: "reject", rules.Return: "return",
	rules.Continue: "continue", rules.Jump: "jump", rules.Goto: "goto",
}

func dumpKey(fs []rules.Field) string {
	var parts []string
	for _, f := range fs {
		s := fieldNames[f.Name]
		if s == "" {
			s = fmt.Sprintf("field%d", f.Name)
		}
		if f.HasMask {
			s += fmt.Sprintf("&%#x", f.Mask)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " . ")
}

func dumpAtom(a rules.Atom) string {
	switch a.Kind {
	case rules.AtomAny:
		return "*"
	case rules.AtomPrefix:
		if a.Prefix.IsSingleIP() {
			return a.Prefix.Addr().String()
		}
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

func dumpElem(e rules.Elem) string {
	var parts []string
	for _, a := range e {
		parts = append(parts, dumpAtom(a))
	}
	return strings.Join(parts, " . ")
}

func dumpVerdict(v rules.Verdict) string {
	s := verdictNames[v.Kind]
	if v.Chain != "" {
		s += " " + v.Chain
	}
	return s
}

func dumpRef(ref string) string { return "@" + strings.ReplaceAll(ref, "\x00", "/") }

func dumpSet(s *rules.Set) string {
	if s == nil {
		return "{nil}"
	}
	var parts []string
	for i, e := range s.Elems {
		p := dumpElem(e)
		if i < len(s.Verdicts) {
			p += " : " + dumpVerdict(s.Verdicts[i])
		}
		parts = append(parts, p)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func dumpExpr(x rules.Expr) string {
	switch x := x.(type) {
	case *rules.Match:
		op := " in "
		if x.Neg {
			op = " not in "
		}
		if x.SetRef != "" {
			return "match " + dumpKey(x.Key) + op + dumpRef(x.SetRef)
		}
		return "match " + dumpKey(x.Key) + op + dumpSet(x.Values)
	case *rules.Unknown:
		return "UNKNOWN " + x.Why
	case *rules.Always:
		return "always (" + x.What + ")"
	case *rules.Never:
		return "never (" + x.What + ")"
	case *rules.Verdict:
		return dumpVerdict(*x)
	case *rules.VerdictMap:
		if x.SetRef != "" {
			return "vmap " + dumpKey(x.Key) + " " + dumpRef(x.SetRef)
		}
		var parts []string
		for _, e := range x.Entries {
			parts = append(parts, dumpElem(e.Key)+" : "+dumpVerdict(e.Verdict))
		}
		return "vmap " + dumpKey(x.Key) + " {" + strings.Join(parts, ", ") + "}"
	case *rules.DNAT:
		s := "dnat"
		if x.Addr.IsValid() {
			s += " " + x.Addr.String()
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
		return s
	case *rules.Redirect:
		s := "redirect"
		if x.Port != 0 {
			s += fmt.Sprintf(" port %d", x.Port)
			if x.PortHi != 0 {
				s += fmt.Sprintf("-%d", x.PortHi)
			}
		}
		return s
	case *rules.SetMark:
		which := "mark"
		if x.Ct {
			which = "ctmark"
		}
		return fmt.Sprintf("%s = (%s & %#x) ^ %#x", which, which, x.And, x.Xor)
	case *rules.CopyMark:
		if x.ToCt {
			return fmt.Sprintf("ctmark <- mark, mask %#x", x.Mask)
		}
		return fmt.Sprintf("mark <- ctmark, mask %#x", x.Mask)
	case *rules.Noop:
		return "noop (" + x.What + ")"
	case *rules.Notrack:
		return "notrack"
	case *rules.UnknownStmt:
		return "UNKNOWN-STMT " + x.Why
	}
	return fmt.Sprintf("%T", x)
}

// dump prints a ruleset in full, for the golden files.
func dump(rs *rules.Ruleset) string {
	var b strings.Builder
	for _, t := range rs.Tables {
		fmt.Fprintf(&b, "table %s %s (%s)\n", t.Family, t.Name, t.Origin)
		for _, name := range t.Order {
			c := t.Chains[name]
			fmt.Fprintf(&b, "  chain %s", c.Name)
			if c.Hook != "" {
				fmt.Fprintf(&b, ": %s hook %s priority %d policy %s", c.Type, c.Hook, c.Priority, verdictNames[c.Policy])
				if !c.Base {
					b.WriteString(" (not running)")
				}
			}
			b.WriteString("\n")
			for _, r := range c.Rules {
				fmt.Fprintf(&b, "    %s\n", r.Text)
				for _, x := range r.Exprs {
					fmt.Fprintf(&b, "        %s\n", dumpExpr(x))
				}
			}
		}
	}
	var keys []string
	for k := range rs.Sets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := rs.Sets[k]
		fmt.Fprintf(&b, "set %s", dumpRef(k))
		if s.Dynamic {
			b.WriteString(" dynamic")
		}
		if s.Incomplete {
			fmt.Fprintf(&b, " INCOMPLETE %s", s.Why)
		}
		fmt.Fprintf(&b, " %s\n", dumpSet(s))
	}
	for _, n := range rs.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}
