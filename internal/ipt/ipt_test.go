package ipt

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/rules"
)

// header declares the built-in chains of a table plus two user chains, web and logdrop.
func header(table string) string {
	var b strings.Builder
	b.WriteString("*" + table + "\n")
	for _, c := range []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"} {
		if _, ok := baseChains[table][c]; ok {
			b.WriteString(":" + c + " ACCEPT [0:0]\n")
		}
	}
	b.WriteString(":web - [0:0]\n:logdrop - [0:0]\n")
	return b.String()
}

func parseOne(t *testing.T, family, table, chain, rest string, dims map[string][]string) []rules.Expr {
	t.Helper()
	text := header(table) + "-A " + chain + " " + rest + "\nCOMMIT\n"
	tables, _, err := ParseSave(text, Options{Family: family, SetDims: dims})
	if err != nil {
		t.Fatalf("%s: %v", rest, err)
	}
	rs := tables[0].Chains[chain].Rules
	if len(rs) != 1 {
		t.Fatalf("%s: %d rules", rest, len(rs))
	}
	if want := "-A " + chain + " " + rest; rs[0].Text != want {
		t.Errorf("Text = %q, want %q", rs[0].Text, want)
	}
	checkRule(t, tables[0], rs[0])
	return rs[0].Exprs
}

// same compares expression lists exactly, except that the What of Always and Never is ignored
// and the Why of Unknown and UnknownStmt only has to contain the expected text.
func same(got, want []rules.Expr) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		switch w := want[i].(type) {
		case *rules.Always:
			if _, ok := got[i].(*rules.Always); !ok {
				return false
			}
		case *rules.Never:
			if _, ok := got[i].(*rules.Never); !ok {
				return false
			}
		case *rules.Noop:
			if _, ok := got[i].(*rules.Noop); !ok {
				return false
			}
		case *rules.Unknown:
			g, ok := got[i].(*rules.Unknown)
			if !ok || !strings.Contains(g.Why, w.Why) {
				return false
			}
		case *rules.UnknownStmt:
			g, ok := got[i].(*rules.UnknownStmt)
			if !ok || !strings.Contains(g.Why, w.Why) {
				return false
			}
		default:
			if !reflect.DeepEqual(got[i], want[i]) {
				return false
			}
		}
	}
	return true
}

func dumpList(es []rules.Expr) string {
	var s []string
	for _, e := range es {
		s = append(s, "    "+dumpExpr(e))
	}
	return strings.Join(s, "\n")
}

// Shorthands for expected expressions.
func eq(f rules.FieldName, a ...rules.Atom) rules.Expr { return rules.Eq(f, a...) }
func ne(f rules.FieldName, a ...rules.Atom) rules.Expr { return rules.Ne(f, a...) }
func pfx(s string) rules.Atom                          { return rules.Pfx(netip.MustParsePrefix(s)) }
func rng(a, b string) rules.Atom {
	return rules.Atom{Kind: rules.AtomRange, AddrLo: netip.MustParseAddr(a), AddrHi: netip.MustParseAddr(b)}
}
func num(v uint32) rules.Atom     { return rules.Num(v) }
func nr(a, b uint32) rules.Atom   { return rules.NumRange(a, b) }
func unk(s string) rules.Expr     { return &rules.Unknown{Why: s} }
func unkStmt(s string) rules.Expr { return &rules.UnknownStmt{Why: s} }
func always() rules.Expr          { return &rules.Always{} }
func never() rules.Expr           { return &rules.Never{} }
func noop() rules.Expr            { return &rules.Noop{} }
func verdict(k rules.VerdictKind) rules.Expr {
	return &rules.Verdict{Kind: k}
}
func masked(f rules.FieldName, mask, v uint32, neg bool) rules.Expr {
	return &rules.Match{Key: []rules.Field{{Name: f, Mask: mask, HasMask: true}}, Neg: neg, Values: rules.One(rules.Num(v))}
}
func multi(neg bool, key []rules.FieldName, elems ...rules.Elem) rules.Expr {
	m := &rules.Match{Neg: neg, Values: &rules.Set{Elems: elems}}
	for _, k := range key {
		m.Key = append(m.Key, rules.Field{Name: k})
	}
	return m
}
func setRef(name string, neg bool, key ...rules.Field) rules.Expr {
	return &rules.Match{Key: key, Neg: neg, SetRef: rules.SetKey("", "", name)}
}
func fld(f rules.FieldName) rules.Field { return rules.Field{Name: f} }

var any_ = rules.Atom{Kind: rules.AtomAny}

var tracked = eq(rules.FCtState, num(rules.CtNew), num(rules.CtEstablished), num(rules.CtRelated))

var testDims = map[string][]string{
	"blocklist": {"net"},
	"webports":  {"ip", "port"},
	"lowports":  {"port-only"},
	"ifnets":    {"net", "iface"},
	"marks":     {"ip", "mark/0xff"},
	"macs":      {"mac"},
	"triple":    {"ip", "port", "net"},
}

type ruleCase struct {
	rest string
	want []rules.Expr
}

func runCases(t *testing.T, family, table, chain string, cases []ruleCase) {
	t.Helper()
	for _, c := range cases {
		got := parseOne(t, family, table, chain, c.rest, testDims)
		if !same(got, c.want) {
			t.Errorf("%s\n  got:\n%s\n  want:\n%s", c.rest, dumpList(got), dumpList(c.want))
		}
	}
}

func TestMatches(t *testing.T) {
	runCases(t, "ip", "filter", "INPUT", []ruleCase{
		// Addresses.
		{"-s 203.0.113.7/32", []rules.Expr{eq(rules.FSaddr, pfx("203.0.113.7/32"))}},
		{"-s 203.0.113.7", []rules.Expr{eq(rules.FSaddr, pfx("203.0.113.7/32"))}},
		{"! -s 10.0.0.0/8", []rules.Expr{ne(rules.FSaddr, pfx("10.0.0.0/8"))}},
		{"-d 10.0.0.0/255.0.0.0", []rules.Expr{eq(rules.FDaddr, pfx("10.0.0.0/8"))}},
		{"-d 10.1.2.3/255.255.0.0", []rules.Expr{eq(rules.FDaddr, pfx("10.1.0.0/16"))}},
		{"-s 10.0.0.0/255.0.255.0", []rules.Expr{unk("mask with gaps")}},
		{"-s web.example", []rules.Expr{unk("not an address")}},
		{"--source 198.51.100.0/24 --destination 192.0.2.1", []rules.Expr{eq(rules.FSaddr, pfx("198.51.100.0/24")), eq(rules.FDaddr, pfx("192.0.2.1/32"))}},
		// Interfaces.
		{"-i eth0", []rules.Expr{eq(rules.FIifName, rules.Str("eth0"))}},
		{"! -i docker0", []rules.Expr{ne(rules.FIifName, rules.Str("docker0"))}},
		{"-i eth+", []rules.Expr{eq(rules.FIifName, rules.StrPfx("eth"))}},
		{"! -o br-+", []rules.Expr{ne(rules.FOifName, rules.StrPfx("br-"))}},
		// Protocols.
		{"-p tcp", []rules.Expr{eq(rules.FL4Proto, num(6))}},
		{"! -p udp", []rules.Expr{ne(rules.FL4Proto, num(17))}},
		{"-p 47", []rules.Expr{eq(rules.FL4Proto, num(47))}},
		{"-p esp", []rules.Expr{eq(rules.FL4Proto, num(50))}},
		{"-p udplite", []rules.Expr{eq(rules.FL4Proto, num(136))}},
		{"-p all", []rules.Expr{always()}},
		{"-p frobnicate", []rules.Expr{unk("protocol frobnicate")}},
		{"-4", []rules.Expr{always()}},
		{"-6", []rules.Expr{never()}},
		// Fragments.
		{"-f", []rules.Expr{never()}},
		{"! -f", []rules.Expr{always()}},
		// Ports.
		{"-p tcp -m tcp --dport 22", []rules.Expr{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(22))}},
		{"-p tcp -m tcp ! --dport 22", []rules.Expr{eq(rules.FL4Proto, num(6)), ne(rules.FDport, num(22))}},
		{"-p tcp -m tcp --sport 1024:65535 --dport 80:90", []rules.Expr{eq(rules.FL4Proto, num(6)), eq(rules.FSport, nr(1024, 65535)), eq(rules.FDport, nr(80, 90))}},
		{"-p udp -m udp --sport 0:100", []rules.Expr{eq(rules.FL4Proto, num(17)), eq(rules.FSport, nr(0, 100))}},
		{"-p tcp -m tcp --dport ssh", []rules.Expr{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(22))}},
		{"-p tcp --dport 443", []rules.Expr{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(443))}},
		{"-p sctp -m sctp --dport 5", []rules.Expr{eq(rules.FL4Proto, num(132)), eq(rules.FDport, num(5))}},
		{"-p dccp -m dccp --sport 7", []rules.Expr{eq(rules.FL4Proto, num(33)), eq(rules.FSport, num(7))}},
		{"-m udp --dport 53", []rules.Expr{eq(rules.FL4Proto, num(17)), eq(rules.FDport, num(53))}},
		{"-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN", []rules.Expr{eq(rules.FL4Proto, num(6)), masked(rules.FTCPFlags, 0x17, 0x02, false)}},
		{"-p tcp -m tcp ! --tcp-flags SYN,RST SYN", []rules.Expr{eq(rules.FL4Proto, num(6)), masked(rules.FTCPFlags, 0x06, 0x02, true)}},
		{"-p tcp -m tcp --tcp-flags ALL NONE", []rules.Expr{eq(rules.FL4Proto, num(6)), masked(rules.FTCPFlags, 0x3f, 0, false)}},
		{"-p tcp -m tcp --syn", []rules.Expr{eq(rules.FL4Proto, num(6)), masked(rules.FTCPFlags, 0x17, 0x02, false)}},
		{"-p tcp -m tcp ! --syn", []rules.Expr{eq(rules.FL4Proto, num(6)), masked(rules.FTCPFlags, 0x17, 0x02, true)}},
		{"-p tcp -m tcp --sport 1:65535 --tcp-option 2", []rules.Expr{eq(rules.FL4Proto, num(6)), eq(rules.FSport, nr(1, 65535)), unk("--tcp-option looks at TCP options")}},
		{"-p sctp -m sctp --chunk-types any INIT", []rules.Expr{eq(rules.FL4Proto, num(132)), unk("--chunk-types")}},
		// Multiport.
		{"-p tcp -m multiport --dports 80,443,8000:8010", []rules.Expr{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(80), num(443), nr(8000, 8010))}},
		{"-p udp -m multiport ! --sports 53,123", []rules.Expr{eq(rules.FL4Proto, num(17)), ne(rules.FSport, num(53), num(123))}},
		{"-p tcp -m multiport --ports 1,2:5", []rules.Expr{eq(rules.FL4Proto, num(6)),
			multi(false, []rules.FieldName{rules.FSport, rules.FDport}, rules.Elem{num(1), any_}, rules.Elem{any_, num(1)}, rules.Elem{nr(2, 5), any_}, rules.Elem{any_, nr(2, 5)})}},
		// Connection tracking.
		{"-m conntrack --ctstate RELATED,ESTABLISHED", []rules.Expr{eq(rules.FCtState, num(rules.CtRelated), num(rules.CtEstablished))}},
		{"-m conntrack ! --ctstate INVALID", []rules.Expr{ne(rules.FCtState, num(rules.CtInvalid))}},
		{"-m conntrack --ctstate NEW,UNTRACKED", []rules.Expr{eq(rules.FCtState, num(rules.CtNew), num(rules.CtUntracked))}},
		{"-m state --state NEW", []rules.Expr{eq(rules.FCtState, num(rules.CtNew))}},
		{"-m state ! --state ESTABLISHED,RELATED", []rules.Expr{ne(rules.FCtState, num(rules.CtEstablished), num(rules.CtRelated))}},
		{"-m state --state DNAT", []rules.Expr{unk("state DNAT")}},
		{"-m conntrack --ctstate DNAT", []rules.Expr{multi(false, []rules.FieldName{rules.FCtStatusDNAT}, rules.Elem{num(1)})}},
		{"-m conntrack --ctstate NEW,DNAT", []rules.Expr{multi(false, []rules.FieldName{rules.FCtState, rules.FCtStatusDNAT},
			rules.Elem{num(rules.CtNew), any_}, rules.Elem{any_, num(1)})}},
		{"-m conntrack ! --ctstate SNAT,DNAT", []rules.Expr{multi(true, []rules.FieldName{rules.FCtStatusDNAT, rules.FCtStatusSNAT},
			rules.Elem{num(1), any_}, rules.Elem{any_, num(1)})}},
		{"-m conntrack --ctstate BOGUS", []rules.Expr{unk("state BOGUS")}},
		{"-m conntrack --ctstate NEW --ctproto 6 --ctorigdst 192.0.2.1 --ctorigdstport 80", []rules.Expr{
			eq(rules.FCtState, num(rules.CtNew)), eq(rules.FL4Proto, num(6)), eq(rules.FCtOrigDaddr, pfx("192.0.2.1/32")), eq(rules.FCtOrigDport, num(80))}},
		{"-m conntrack ! --ctorigdst 192.0.2.0/24 --ctorigdstport 8000:8010", []rules.Expr{
			tracked, ne(rules.FCtOrigDaddr, pfx("192.0.2.0/24")), eq(rules.FCtOrigDport, nr(8000, 8010))}},
		{"-m conntrack --ctproto tcp ! --ctorigdstport 22", []rules.Expr{tracked, eq(rules.FL4Proto, num(6)), ne(rules.FCtOrigDport, num(22))}},
		{"-m conntrack --ctproto 0", []rules.Expr{tracked, never()}},
		{"-m conntrack ! --ctproto all", []rules.Expr{tracked, always()}},
		{"-m conntrack --ctstate NEW --ctstatus BOGUS --ctorigdstport 80", []rules.Expr{eq(rules.FCtState, num(rules.CtNew)), unk("status BOGUS"), eq(rules.FCtOrigDport, num(80))}},
		{"-m comment --comment -s -j DROP", []rules.Expr{always(), verdict(rules.Drop)}},
		{"-m conntrack --ctdir ORIGINAL", []rules.Expr{tracked, eq(rules.FCtDirection, num(0))}},
		{"-m conntrack --ctdir REPLY", []rules.Expr{tracked, eq(rules.FCtDirection, num(1))}},
		{"-m conntrack --ctstatus SEEN_REPLY,ASSURED", []rules.Expr{tracked, never()}},
		{"-m conntrack ! --ctstatus CONFIRMED", []rules.Expr{tracked, always()}},
		{"-m conntrack --ctstate NEW --ctstatus EXPECTED", []rules.Expr{eq(rules.FCtState, num(rules.CtNew)), never()}},
		{"-m conntrack ! --ctstate INVALID --ctorigdst 192.0.2.1", []rules.Expr{ne(rules.FCtState, num(rules.CtInvalid)), unk("skips its other tests")}},
		{"-m conntrack --ctstate UNTRACKED --ctdir REPLY", []rules.Expr{eq(rules.FCtState, num(rules.CtUntracked)), unk("skips its other tests")}},
		{"-m conntrack --ctorigsrc 192.0.2.1", []rules.Expr{tracked, unk("--ctorigsrc looks at the connection's original source address")}},
		{"-m conntrack --ctexpire 10:20", []rules.Expr{tracked, unk("--ctexpire")}},
		// Address types.
		{"-m addrtype --dst-type LOCAL", []rules.Expr{eq(rules.FFibDaddrType, num(rules.AddrLocal))}},
		{"-m addrtype ! --src-type UNICAST,BLACKHOLE --dst-type LOCAL", []rules.Expr{
			ne(rules.FFibSaddrType, num(rules.AddrUnicast), num(rules.AddrBlackhole)), eq(rules.FFibDaddrType, num(rules.AddrLocal))}},
		{"-m addrtype --dst-type BROADCAST,MULTICAST,ANYCAST,UNREACHABLE,PROHIBIT,UNSPEC", []rules.Expr{eq(rules.FFibDaddrType,
			num(rules.AddrBroadcast), num(rules.AddrMulticast), num(rules.AddrAnycast), num(rules.AddrUnreachable), num(rules.AddrProhibit), num(rules.AddrUnspec))}},
		{"-m addrtype --dst-type LOCAL --limit-iface-in", []rules.Expr{eq(rules.FFibDaddrTypeIif, num(rules.AddrLocal))}},
		{"-m addrtype --src-type LOCAL --limit-iface-out", []rules.Expr{unk("--limit-iface-out")}},
		{"-m addrtype --dst-type NAT", []rules.Expr{unk("type NAT")}},
		// Marks.
		{"-m mark --mark 0x1/0xff", []rules.Expr{masked(rules.FMark, 0xff, 1, false)}},
		{"-m mark ! --mark 0x1/0xff", []rules.Expr{masked(rules.FMark, 0xff, 1, true)}},
		{"-m mark --mark 0x4", []rules.Expr{eq(rules.FMark, num(4))}},
		{"-m connmark --mark 0x2", []rules.Expr{eq(rules.FCtMark, num(2))}},
		{"-m connmark ! --mark 0x10/0xf0", []rules.Expr{masked(rules.FCtMark, 0xf0, 0x10, true)}},
		// Address ranges.
		{"-m iprange --src-range 192.0.2.1-192.0.2.9", []rules.Expr{eq(rules.FSaddr, rng("192.0.2.1", "192.0.2.9"))}},
		{"-m iprange ! --src-range 192.0.2.1-192.0.2.9 --dst-range 192.0.2.10-192.0.2.20", []rules.Expr{
			ne(rules.FSaddr, rng("192.0.2.1", "192.0.2.9")), eq(rules.FDaddr, rng("192.0.2.10", "192.0.2.20"))}},
		// Packet type.
		{"-m pkttype --pkt-type broadcast", []rules.Expr{eq(rules.FPktType, num(rules.PktBroadcast))}},
		{"-m pkttype ! --pkt-type unicast", []rules.Expr{ne(rules.FPktType, num(rules.PktHost))}},
		{"-m pkttype --pkt-type multicast", []rules.Expr{eq(rules.FPktType, num(rules.PktMulticast))}},
		{"-m pkttype --pkt-type loopback", []rules.Expr{unk("loopback packets")}},
		// ICMP.
		{"-p icmp -m icmp --icmp-type 8", []rules.Expr{eq(rules.FL4Proto, num(1)), eq(rules.FICMPType, num(8))}},
		{"-p icmp -m icmp ! --icmp-type 8", []rules.Expr{eq(rules.FL4Proto, num(1)), ne(rules.FICMPType, num(8))}},
		{"-p icmp -m icmp --icmp-type echo-request", []rules.Expr{eq(rules.FL4Proto, num(1)), eq(rules.FICMPType, num(8))}},
		{"-p icmp -m icmp --icmp-type destination-unreachable", []rules.Expr{eq(rules.FL4Proto, num(1)), eq(rules.FICMPType, num(3))}},
		{"-p icmp -m icmp --icmp-type 3/4", []rules.Expr{eq(rules.FL4Proto, num(1)), unk("code 4 of type 3")}},
		{"-p icmp -m icmp --icmp-type port-unreachable", []rules.Expr{eq(rules.FL4Proto, num(1)), unk("code 3 of type 3")}},
		{"-p icmp -m icmp --icmp-type any", []rules.Expr{eq(rules.FL4Proto, num(1)), always()}},
		{"-p icmp --icmp-type 0", []rules.Expr{eq(rules.FL4Proto, num(1)), eq(rules.FICMPType, num(0))}},
		// Reverse path, IPsec.
		{"-m rpfilter", []rules.Expr{eq(rules.FRpfOK, num(1))}},
		{"-m rpfilter --invert", []rules.Expr{eq(rules.FRpfOK, num(0))}},
		{"-m rpfilter --loose --invert", []rules.Expr{unk("--loose")}},
		{"-m policy --dir in --pol none", []rules.Expr{eq(rules.FIPSecIn, num(0))}},
		{"-m policy --dir in --pol ipsec", []rules.Expr{eq(rules.FIPSecIn, num(1))}},
		{"-m policy --dir in --pol ipsec --strict --proto esp", []rules.Expr{eq(rules.FIPSecIn, num(1)), unk("--strict --proto")}},
		{"-m policy --dir out --pol none", []rules.Expr{unk("leaving packets")}},
		// First-packet answers.
		{"-m limit --limit 3/min --limit-burst 10", []rules.Expr{always()}},
		{"-m hashlimit --hashlimit-upto 5/sec --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name x", []rules.Expr{always()}},
		{"-m hashlimit --hashlimit-above 5/sec --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name x", []rules.Expr{never()}},
		{"-m comment --comment \"allow web \\\"prod\\\"\"", []rules.Expr{&rules.Always{What: "comment: allow web \"prod\""}}},
		{"-m recent --set --name x --mask 255.255.255.255 --rsource", []rules.Expr{always()}},
		{"-m recent --rcheck --seconds 60 --name x --mask 255.255.255.255 --rsource", []rules.Expr{never()}},
		{"-m recent --update --seconds 30 --hitcount 6 --name x --mask 255.255.255.255 --rsource", []rules.Expr{never()}},
		{"-m recent ! --update --seconds 30 --hitcount 6 --name x --mask 255.255.255.255 --rsource", []rules.Expr{always()}},
		{"-m recent --remove --name x --mask 255.255.255.255 --rsource", []rules.Expr{never()}},
		{"-m connlimit --connlimit-above 3 --connlimit-mask 32 --connlimit-saddr", []rules.Expr{never()}},
		{"-m connlimit --connlimit-above 0 --connlimit-mask 32 --connlimit-saddr", []rules.Expr{always()}},
		{"-m connlimit --connlimit-upto 3 --connlimit-mask 32 --connlimit-saddr", []rules.Expr{always()}},
		{"-m connlimit --connlimit-above 100 --connlimit-mask 0 --connlimit-saddr", []rules.Expr{unk("more than one sender (--connlimit-mask)")}},
		{"-m connlimit --connlimit-above 3 --connlimit-mask 32 --connlimit-daddr", []rules.Expr{unk("more than one sender (--connlimit-daddr)")}},
		{"-m connlimit --connlimit-upto 0 --connlimit-mask 32 --connlimit-saddr", []rules.Expr{never()}},
		{"-m connlimit ! --connlimit-above 3 --connlimit-mask 32 --connlimit-saddr", []rules.Expr{always()}},
		// ipsets.
		{"-m set --match-set blocklist src", []rules.Expr{setRef("blocklist", false, fld(rules.FSaddr))}},
		{"-m set ! --match-set blocklist dst", []rules.Expr{setRef("blocklist", true, fld(rules.FDaddr))}},
		{"-m set --match-set webports dst,dst", []rules.Expr{setRef("webports", false, fld(rules.FDaddr), fld(rules.FL4Proto), fld(rules.FDport))}},
		{"-m set --match-set webports src,src", []rules.Expr{setRef("webports", false, fld(rules.FSaddr), fld(rules.FL4Proto), fld(rules.FSport))}},
		{"-m set --match-set triple src,dst,dst", []rules.Expr{setRef("triple", false, fld(rules.FSaddr), fld(rules.FL4Proto), fld(rules.FDport), fld(rules.FDaddr))}},
		{"-m set --match-set lowports dst", []rules.Expr{setRef("lowports", false, fld(rules.FDport))}},
		{"-m set --match-set ifnets src,src", []rules.Expr{setRef("ifnets", false, fld(rules.FSaddr), fld(rules.FIifName))}},
		{"-m set --match-set ifnets dst,dst", []rules.Expr{setRef("ifnets", false, fld(rules.FDaddr), fld(rules.FOifName))}},
		{"-m set --match-set marks src,src", []rules.Expr{setRef("marks", false, fld(rules.FSaddr), rules.Field{Name: rules.FMark, Mask: 0xff, HasMask: true})}},
		{"-m set --match-set webports dst", []rules.Expr{never()}},
		{"-m set ! --match-set webports dst", []rules.Expr{always()}},
		{"-m set --match-set blocklist src,dst", []rules.Expr{setRef("blocklist", false, fld(rules.FSaddr))}},
		{"-m set --match-set macs src", []rules.Expr{unk("hardware (MAC)")}},
		{"-m set --match-set nosuch src", []rules.Expr{unk("the ipset nosuch was not captured")}},
		{"-m set --match-set blocklist src --return-nomatch", []rules.Expr{setRef("blocklist", false, fld(rules.FSaddr)), unk("--return-nomatch")}},
		{"-m set --match-set blocklist src --packets-gt 5", []rules.Expr{setRef("blocklist", false, fld(rules.FSaddr)), unk("--packets-gt")}},
		{"-m set --match-set blocklist src ! --update-counters", []rules.Expr{setRef("blocklist", false, fld(rules.FSaddr))}},
		// Counters given inline are not conditions.
		{"-c 10 2000 -p tcp", []rules.Expr{eq(rules.FL4Proto, num(6))}},
	})
}

func TestIP6Matches(t *testing.T) {
	runCases(t, "ip6", "filter", "INPUT", []ruleCase{
		{"-s 2001:db8::/32", []rules.Expr{eq(rules.FSaddr, pfx("2001:db8::/32"))}},
		{"! -d 2001:db8::1/128", []rules.Expr{ne(rules.FDaddr, pfx("2001:db8::1/128"))}},
		{"-d 2001:db8::/ffff:ffff::", []rules.Expr{eq(rules.FDaddr, pfx("2001:db8::/32"))}},
		{"-p ipv6-icmp -m icmp6 --icmpv6-type 128", []rules.Expr{eq(rules.FL4Proto, num(58)), eq(rules.FICMPv6Type, num(128))}},
		{"-p icmpv6 -m icmp6 ! --icmpv6-type neighbour-solicitation", []rules.Expr{eq(rules.FL4Proto, num(58)), ne(rules.FICMPv6Type, num(135))}},
		{"-p ipv6-icmp -m icmp6 --icmpv6-type 1/4", []rules.Expr{eq(rules.FL4Proto, num(58)), unk("code 4 of type 1")}},
		{"-p ipv6-icmp -m ipv6-icmp --icmpv6-type echo-reply", []rules.Expr{eq(rules.FL4Proto, num(58)), eq(rules.FICMPv6Type, num(129))}},
		{"-p ipv6-icmp --icmpv6-type 2", []rules.Expr{eq(rules.FL4Proto, num(58)), eq(rules.FICMPv6Type, num(2))}},
		{"-4", []rules.Expr{never()}},
		{"-6", []rules.Expr{always()}},
		{"-m rt --rt-type 0", []rules.Expr{never()}},
		{"-m frag --fragid 0:4294967295", []rules.Expr{never()}},
		{"-m hbh", []rules.Expr{never()}},
	})
}

func TestUnknownMatches(t *testing.T) {
	for _, c := range []struct{ rest, want string }{
		{"-m string --string \"GET /x\" --algo bm -j ACCEPT", "the string match (-m string) looks inside the packet's data"},
		{"-m u32 --u32 \"0x0>>0x16&0x3c@0xc>>0x1a&0x3c@0x0=0x504f5354\"", "the u32 match (-m u32) tests raw bytes"},
		{"-m bpf --bytecode \"4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0\"", "the bpf match"},
		{"-m time --timestart 09:00:00 --timestop 23:59:59 --datestop 2038-01-19T03:14:07", "time of day"},
		{"-m owner --uid-owner 0", "local program"},
		{"-m physdev --physdev-in eth0", "bridge port"},
		{"-m socket --transparent", "local socket"},
		{"-m length --length 10:20", "packet's length"},
		{"-m ttl --ttl-gt 3", "time-to-live"},
		{"-m hl --hl-eq 255", "hop limit"},
		{"-p tcp -m tcpmss --mss 1:500", "segment size"},
		{"-m mac --mac-source 00:11:22:33:44:55", "MAC"},
		{"-m geoip --src-cc XX", "country"},
		{"-m cgroup --path user.slice", "group of local programs"},
		{"-m dscp --dscp 0x01", "DSCP"},
		{"-m tos --tos 0x10/0x3f", "type-of-service"},
		{"-p tcp -m ecn --ecn-tcp-cwr", "ECN"},
		{"-m statistic --mode random --probability 0.50000000000", "at random"},
		{"-m nfacct --nfacct-name x", "accounting"},
		{"-m helper --helper ftp", "helper"},
		{"-m ipvs --ipvs", "IPVS"},
		{"-m cluster --cluster-total-nodes 2 --cluster-local-node 1 --cluster-hash-seed 0xdeadbeef", "cluster"},
		{"-m devgroup --src-group 0x1", "interface group"},
		{"-m realm --realm 0x1", "realm"},
		{"-m cpu --cpu 1", "processor"},
		{"-m quota --quota 1000", "bytes"},
		{"-m osf --genre Linux", "operating system"},
		{"-m frobnicate --level 11", "the frobnicate match (-m frobnicate) is not one seaward understands"},
	} {
		got := parseOne(t, "ip", "filter", "INPUT", c.rest, nil)
		found := false
		for _, e := range got {
			if u, ok := e.(*rules.Unknown); ok && strings.Contains(u.Why, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no Unknown containing %q:\n%s", c.rest, c.want, dumpList(got))
		}
	}
	// An unknown extension takes its own options, and what follows still parses.
	got := parseOne(t, "ip", "filter", "INPUT", "-m string --string \"-p udp\" --algo bm -p tcp -m tcp --dport 80 -m ttl --ttl-gt 3 -j ACCEPT", nil)
	want := []rules.Expr{unk("string"), eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(80)), unk("ttl"), verdict(rules.Accept)}
	if !same(got, want) {
		t.Errorf("rest of rule after an unknown match:\n%s", dumpList(got))
	}
	// An unknown option of a known extension is Unknown, and the others still count.
	got = parseOne(t, "ip", "filter", "INPUT", "-p tcp -m tcp --dport 80 --frob 3 --sport 9 -j DROP", nil)
	want = []rules.Expr{eq(rules.FL4Proto, num(6)), unk("--frob 3"), eq(rules.FDport, num(80)), eq(rules.FSport, num(9)), verdict(rules.Drop)}
	if !same(got, want) {
		t.Errorf("unknown option of a known match:\n%s", dumpList(got))
	}
	// Words outside any extension.
	got = parseOne(t, "ip", "filter", "INPUT", "--frob 3 -j ACCEPT", nil)
	if !same(got, []rules.Expr{unk("--frob 3"), verdict(rules.Accept)}) {
		t.Errorf("stray option:\n%s", dumpList(got))
	}
}

func TestTargets(t *testing.T) {
	jump := func(k rules.VerdictKind, c string) rules.Expr { return &rules.Verdict{Kind: k, Chain: c} }
	random := func(x rules.Expr) rules.Expr {
		x.(*rules.DNAT).Random = true
		return x
	}
	dnat := func(a, ahi string, p, phi uint16) rules.Expr {
		d := &rules.DNAT{Port: p, PortHi: phi}
		if a != "" {
			d.Addr = netip.MustParseAddr(a)
		}
		if ahi != "" {
			d.AddrHi = netip.MustParseAddr(ahi)
		}
		return d
	}
	setmark := func(ct bool, and, xor uint32) rules.Expr { return &rules.SetMark{Ct: ct, And: and, Xor: xor} }
	runCases(t, "ip", "filter", "INPUT", []ruleCase{
		{"-j ACCEPT", []rules.Expr{verdict(rules.Accept)}},
		{"-j DROP", []rules.Expr{verdict(rules.Drop)}},
		{"-j RETURN", []rules.Expr{verdict(rules.Return)}},
		{"-j REJECT --reject-with icmp-port-unreachable", []rules.Expr{verdict(rules.Reject)}},
		{"-p tcp -j REJECT --reject-with tcp-reset", []rules.Expr{eq(rules.FL4Proto, num(6)), verdict(rules.Reject)}},
		{"-j web", []rules.Expr{jump(rules.Jump, "web")}},
		{"-g web", []rules.Expr{jump(rules.Goto, "web")}},
		{"-j nowhere", []rules.Expr{unkStmt("the target nowhere (-j nowhere) is not one seaward understands")}},
		{"-g nowhere", []rules.Expr{unkStmt("not a chain")}},
		{"-j INPUT", []rules.Expr{unkStmt("built-in chain")}},
		{"-p tcp", []rules.Expr{eq(rules.FL4Proto, num(6))}},
		{"-j LOG --log-prefix \"[UFW BLOCK] \" --log-level 4", []rules.Expr{noop()}},
		{"-j NFLOG --nflog-group 1", []rules.Expr{noop()}},
		{"-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", []rules.Expr{eq(rules.FL4Proto, num(6)), masked(rules.FTCPFlags, 0x06, 0x02, false), noop()}},
		{"-j TRACE", []rules.Expr{noop()}},
		{"-j SET --add-set blocklist src", []rules.Expr{noop()}},
		{"-j CLASSIFY --set-class 1:1", []rules.Expr{noop()}},
		{"-j AUDIT --type drop", []rules.Expr{noop()}},
		{"-j NFQUEUE --queue-num 3", []rules.Expr{unkStmt("NFQUEUE")}},
		{"-j QUEUE", []rules.Expr{unkStmt("QUEUE")}},
		{"-p tcp -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460", []rules.Expr{eq(rules.FL4Proto, num(6)), unkStmt("SYNPROXY")}},
		{"-p tcp -j TARPIT", []rules.Expr{eq(rules.FL4Proto, num(6)), unkStmt("TARPIT")}},
		{"-j DELUDE", []rules.Expr{unkStmt("DELUDE")}},
		{"-j CHAOS", []rules.Expr{unkStmt("CHAOS")}},
		// Matches written after the target still come before it.
		{"-j ACCEPT -p udp", []rules.Expr{eq(rules.FL4Proto, num(17)), verdict(rules.Accept)}},
		// Marks: new = (old AND And) XOR Xor.
		{"-j MARK --set-xmark 0x1/0xff", []rules.Expr{setmark(false, ^uint32(0xff), 1)}},
		{"-j MARK --set-xmark 0x5/0xffffffff", []rules.Expr{setmark(false, 0, 5)}},
		{"-j MARK --set-mark 5", []rules.Expr{setmark(false, 0, 5)}},
		{"-j MARK --set-mark 0x10/0x1", []rules.Expr{setmark(false, ^uint32(0x11), 0x10)}},
		{"-j MARK --and-mark 0x4", []rules.Expr{setmark(false, 4, 0)}},
		{"-j MARK --or-mark 0x4", []rules.Expr{setmark(false, ^uint32(4), 4)}},
		{"-j MARK --xor-mark 0x4", []rules.Expr{setmark(false, 0xffffffff, 4)}},
		{"-j CONNMARK --set-xmark 0x3/0x7", []rules.Expr{setmark(true, ^uint32(7), 3)}},
		{"-j CONNMARK --set-mark 0x3/0x4", []rules.Expr{setmark(true, ^uint32(7), 3)}},
		{"-j CONNMARK --or-mark 0x8", []rules.Expr{setmark(true, ^uint32(8), 8)}},
		{"-j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff", []rules.Expr{&rules.CopyMark{ToCt: true, Mask: 0xffffffff}}},
		{"-j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff", []rules.Expr{&rules.CopyMark{ToCt: false, Mask: 0xff}}},
		{"-j CONNMARK --restore-mark --mask 0xf0", []rules.Expr{&rules.CopyMark{ToCt: false, Mask: 0xf0}}},
		{"-j CONNMARK --save-mark --nfmask 0xff --ctmask 0xf", []rules.Expr{unkStmt("two different masks")}},
		{"-j CONNMARK --set-xmark 0x1/0x1 --left-shift-mark 8", []rules.Expr{unkStmt("--left-shift-mark")}},
		{"-j MARK --restore-mark", []rules.Expr{unkStmt("--restore-mark")}},
	})
	runCases(t, "ip", "raw", "PREROUTING", []ruleCase{
		{"-j NOTRACK", []rules.Expr{&rules.Notrack{}}},
		{"-j CT --notrack", []rules.Expr{&rules.Notrack{}}},
		{"-j CT --helper ftp", []rules.Expr{noop()}},
		{"-j CT --zone 1", []rules.Expr{noop()}},
	})
	runCases(t, "ip", "mangle", "PREROUTING", []ruleCase{
		{"-p tcp -j TPROXY --on-port 1 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1", []rules.Expr{eq(rules.FL4Proto, num(6)), unkStmt("TPROXY")}},
		{"-j TTL --ttl-set 64", []rules.Expr{noop()}},
	})
	runCases(t, "ip", "nat", "PREROUTING", []ruleCase{
		{"-j DNAT --to-destination 10.0.0.2", []rules.Expr{dnat("10.0.0.2", "", 0, 0)}},
		{"-j DNAT --to-destination 10.0.0.2:80", []rules.Expr{dnat("10.0.0.2", "", 80, 0)}},
		{"-j DNAT --to-destination 10.0.0.2-10.0.0.9", []rules.Expr{dnat("10.0.0.2", "10.0.0.9", 0, 0)}},
		{"-j DNAT --to-destination 10.0.0.2:8000-8010", []rules.Expr{dnat("10.0.0.2", "", 8000, 8010)}},
		{"-j DNAT --to-destination 192.0.2.2-192.0.2.9:8000-8010 --random --persistent", []rules.Expr{random(dnat("192.0.2.2", "192.0.2.9", 8000, 8010))}},
		{"-j DNAT --to-destination 192.0.2.2:8000-8010 --persistent", []rules.Expr{dnat("192.0.2.2", "", 8000, 8010)}},
		{"-j DNAT --to-destination :8080", []rules.Expr{dnat("", "", 8080, 0)}},
		{"-j DNAT --to-destination 192.0.2.2:80-90/85", []rules.Expr{unkStmt("destination 192.0.2.2:80-90/85")}},
		{"-j DNAT --to-destination bogus", []rules.Expr{unkStmt("bogus")}},
		{"-j DNAT", []rules.Expr{unkStmt("0 destinations")}},
		{"-j REDIRECT --to-ports 8080", []rules.Expr{&rules.Redirect{Port: 8080}}},
		{"-j REDIRECT --to-ports 8000-8010 --random", []rules.Expr{&rules.Redirect{Port: 8000, PortHi: 8010, Random: true}}},
		{"-j REDIRECT --to-ports 8000-8010", []rules.Expr{&rules.Redirect{Port: 8000, PortHi: 8010}}},
		{"-j REDIRECT", []rules.Expr{&rules.Redirect{}}},
		{"-j NETMAP --to 10.0.0.0/8", []rules.Expr{unkStmt("NETMAP")}},
	})
	runCases(t, "ip", "nat", "POSTROUTING", []ruleCase{
		{"-s 172.17.0.0/16 ! -o docker0 -j MASQUERADE", []rules.Expr{eq(rules.FSaddr, pfx("172.17.0.0/16")), ne(rules.FOifName, rules.Str("docker0")), noop()}},
		{"-j SNAT --to-source 192.0.2.1", []rules.Expr{noop()}},
		{"-j NETMAP --to 10.0.0.0/8", []rules.Expr{noop()}},
	})
	runCases(t, "ip6", "nat", "PREROUTING", []ruleCase{
		{"-j DNAT --to-destination [2001:db8::2]:80", []rules.Expr{dnat("2001:db8::2", "", 80, 0)}},
		{"-j DNAT --to-destination 2001:db8::2", []rules.Expr{dnat("2001:db8::2", "", 0, 0)}},
		{"-j DNAT --to-destination [2001:db8::2]-[2001:db8::9]:80-90", []rules.Expr{dnat("2001:db8::2", "2001:db8::9", 80, 90)}},
		{"-j DNAT --to-destination [2001:db8::2]", []rules.Expr{dnat("2001:db8::2", "", 0, 0)}},
	})
}

// The mark arithmetic must agree with what the kernel does for each option, checked on random
// marks against the meaning the iptables manual gives.
func TestMarkArithmetic(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	apply := func(e rules.Expr, old uint32) uint32 {
		s := e.(*rules.SetMark)
		return (old & s.And) ^ s.Xor
	}
	for i := 0; i < 200; i++ {
		v, m, old := r.Uint32(), r.Uint32(), r.Uint32()
		cases := []struct {
			opt  string
			want uint32
		}{
			{"--set-xmark " + hex(v) + "/" + hex(m), (old &^ m) ^ v},
			{"--set-mark " + hex(v) + "/" + hex(m), (old &^ m) | v},
			{"--set-mark " + hex(v), v},
			{"--and-mark " + hex(v), old & v},
			{"--or-mark " + hex(v), old | v},
			{"--xor-mark " + hex(v), old ^ v},
		}
		for _, c := range cases {
			for _, target := range []string{"MARK", "CONNMARK"} {
				got := parseOne(t, "ip", "mangle", "PREROUTING", "-j "+target+" "+c.opt, nil)
				if len(got) != 1 {
					t.Fatalf("%s %s: %s", target, c.opt, dumpList(got))
				}
				if res := apply(got[0], old); res != c.want {
					t.Fatalf("%s %s on 0x%x: got 0x%x, want 0x%x", target, c.opt, old, res, c.want)
				}
				if got[0].(*rules.SetMark).Ct != (target == "CONNMARK") {
					t.Fatalf("%s %s: wrong Ct", target, c.opt)
				}
			}
		}
		// save-mark with equal masks: ct = (ct AND NOT m) OR (nf AND m), as CopyMark says.
		got := parseOne(t, "ip", "mangle", "PREROUTING", "-j CONNMARK --save-mark --nfmask "+hex(m)+" --ctmask "+hex(m), nil)
		if cm, ok := got[0].(*rules.CopyMark); !ok || !cm.ToCt || cm.Mask != m {
			t.Fatalf("save-mark: %s", dumpList(got))
		}
	}
}

func hex(v uint32) string { return fmt.Sprintf("0x%x", v) }

func TestTokenize(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`-A T -m comment --comment "allow web \"prod\" it\'s" -j LOG --log-prefix "[UFW BLOCK] "`,
			[]string{"-A", "T", "-m", "comment", "--comment", `allow web "prod" it's`, "-j", "LOG", "--log-prefix", "[UFW BLOCK] "}},
		{`a  "" b`, []string{"a", "", "b"}},
		{"a\tb", []string{"a", "b"}},
		{`x"y z"w`, []string{"xy zw"}},
		{`"back\\slash"`, []string{`back\slash`}},
	} {
		toks, err := tokenize(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		var got []string
		for _, tk := range toks {
			got = append(got, tk.s)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := tokenize(`-m comment --comment "open`); err == nil {
		t.Error("an open quote should be an error")
	}
}

func TestStructure(t *testing.T) {
	text := `# Generated by iptables-save
*mangle
:PREROUTING ACCEPT [10:2000]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
[12:3456] -A PREROUTING -p tcp -j ACCEPT
COMMIT
*security
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:INPUT2 - [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
`
	tables, notes, err := ParseSave(text, Options{Family: "ip", Legacy: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Errorf("notes: %v", notes)
	}
	if len(tables) != 3 {
		t.Fatalf("%d tables", len(tables))
	}
	m := tables[0]
	if m.Origin != "iptables-legacy" || m.Family != "ip" || m.Name != "mangle" {
		t.Errorf("table: %+v", m)
	}
	want := map[string]baseChain{
		"PREROUTING": {"prerouting", "filter", -150}, "INPUT": {"input", "filter", -150}, "FORWARD": {"forward", "filter", -150},
		"OUTPUT": {"output", "route", -150}, "POSTROUTING": {"postrouting", "filter", -150},
	}
	for name, w := range want {
		c := m.Chains[name]
		if !c.Base || c.Hook != w.hook || c.Type != w.typ || c.Priority != w.prio || c.Policy != rules.Accept {
			t.Errorf("%s: %+v", name, c)
		}
	}
	if r := m.Chains["PREROUTING"].Rules[0]; r.Text != "-A PREROUTING -p tcp -j ACCEPT" || len(r.Exprs) != 2 {
		t.Errorf("counter prefix: %q %s", r.Text, dumpList(r.Exprs))
	}
	s := tables[1]
	if c := s.Chains["FORWARD"]; !c.Base || c.Priority != 50 || c.Policy != rules.Drop {
		t.Errorf("security FORWARD: %+v", c)
	}
	if c := s.Chains["INPUT2"]; c.Base {
		t.Errorf("INPUT2 should be a user chain")
	}
	if !reflect.DeepEqual(s.Order, []string{"INPUT", "FORWARD", "OUTPUT", "INPUT2"}) {
		t.Errorf("order %v", s.Order)
	}
	n := tables[2]
	for name, prio := range map[string]int{"PREROUTING": -100, "OUTPUT": -100, "INPUT": 100, "POSTROUTING": 100} {
		if c := n.Chains[name]; c.Type != "nat" || c.Priority != prio {
			t.Errorf("nat %s: %+v", name, c)
		}
	}
	// raw.
	tables, _, err = ParseSave("*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", Options{Family: "ip6"})
	if err != nil {
		t.Fatal(err)
	}
	if c := tables[0].Chains["OUTPUT"]; c.Hook != "output" || c.Priority != -300 || tables[0].Family != "ip6" || tables[0].Origin != "iptables" {
		t.Errorf("raw: %+v %+v", tables[0], c)
	}
}

func TestIncompatibleTable(t *testing.T) {
	text := "# Table `filter' is incompatible, use 'nft' tool.\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n"
	tables, notes, err := ParseSave(text, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 1 || tables[0].Name != "nat" || len(notes) != 1 || !strings.Contains(notes[0], "filter") {
		t.Errorf("tables %d, notes %q", len(tables), notes)
	}
	// If the tool ever prints the table anyway, it is still left out.
	text = "# Table `filter' is incompatible, use 'nft' tool.\n*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j DROP\nCOMMIT\n"
	tables, _, err = ParseSave(text, Options{})
	if err != nil || len(tables) != 0 {
		t.Errorf("tables %d, err %v", len(tables), err)
	}
}

func TestErrors(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -j ACCEPT\n", "no COMMIT"},
		{"-A INPUT -j ACCEPT\n", "outside any table"},
		{"*filter\n:INPUT ACCEPT [0:0]\n-A NOPE -j ACCEPT\nCOMMIT\n", "does not declare"},
		{"*filter\n:INPUT ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\nCOMMIT\n", "declared twice"},
		{"*filter\n:INPUT\nCOMMIT\n", "no policy"},
		{"*filter\n*nat\nCOMMIT\n", "before table"},
		{"*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m comment --comment \"x\nCOMMIT\n", "not closed"},
		{"*filter\n:INPUT ACCEPT [0:0]\nbogus line\nCOMMIT\n", "not a rule"},
	} {
		_, _, err := ParseSave(c.text, Options{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err %v, want %q", c.text, err, c.want)
		}
	}
	if _, _, err := ParseSave("", Options{Family: "inet"}); err == nil {
		t.Error("family inet should be refused")
	}
	if tables, _, err := ParseSave("", Options{}); err != nil || len(tables) != 0 {
		t.Errorf("empty text: %v %v", tables, err)
	}
}

func TestOddPolicyAndTable(t *testing.T) {
	tables, notes, err := ParseSave("*filter\n:INPUT QUEUE [0:0]\nCOMMIT\n*broute\n:BROUTING ACCEPT [0:0]\nCOMMIT\n", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 2 || tables[0].Chains["INPUT"].Policy != rules.Accept || tables[1].Chains["BROUTING"].Base {
		t.Errorf("notes %q", notes)
	}
}

func TestRawTableConntrack(t *testing.T) {
	runCases(t, "ip", "raw", "PREROUTING", []ruleCase{
		{"-m conntrack --ctstate NEW -j DROP", []rules.Expr{unk("runs before connection tracking"), verdict(rules.Drop)}},
		{"-m state --state INVALID -j DROP", []rules.Expr{unk("runs before connection tracking"), verdict(rules.Drop)}},
		{"-m connmark ! --mark 0x1 -j DROP", []rules.Expr{unk("runs before connection tracking"), verdict(rules.Drop)}},
	})
	// mangle runs after connection tracking, so the same test is a plain state match there.
	runCases(t, "ip", "mangle", "PREROUTING", []ruleCase{
		{"-m conntrack --ctstate NEW -j DROP", []rules.Expr{eq(rules.FCtState, num(rules.CtNew)), verdict(rules.Drop)}},
	})
}

// A rule that puts the sender on a list, or into an ipset, changes what a later check on that
// list or set means for the same first packet.
func TestFilledByOtherRules(t *testing.T) {
	text := header("filter") + `-A INPUT -p tcp -m tcp --dport 22 -m recent --set --name SSH --mask 255.255.255.255 --rsource
-A INPUT -p tcp -m tcp --dport 22 -m recent --update --seconds 60 --name SSH --mask 255.255.255.255 --rsource -j DROP
-A INPUT -p tcp -m tcp --dport 22 -m recent --update --seconds 60 --hitcount 2 --name SSH --mask 255.255.255.255 --rsource -j DROP
-A INPUT -m recent --rcheck --seconds 60 --name OTHER --mask 255.255.255.255 --rsource -j DROP
-A INPUT -m set --match-set scanners src -j DROP
-A INPUT -p tcp -m tcp --dport 23 -j SET --add-set scanners src
COMMIT
`
	tables, _, err := ParseSave(text, Options{SetDims: map[string][]string{"scanners": {"ip"}}})
	if err != nil {
		t.Fatal(err)
	}
	rs := tables[0].Chains["INPUT"].Rules
	want := [][]rules.Expr{
		{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(22)), always()},
		{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(22)), unk("list SSH, which other rules fill"), verdict(rules.Drop)},
		{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(22)), never(), verdict(rules.Drop)},
		{never(), verdict(rules.Drop)},
		{unk("ipset scanners is also filled by a rule"), verdict(rules.Drop)},
		{eq(rules.FL4Proto, num(6)), eq(rules.FDport, num(23)), noop()},
	}
	for i, w := range want {
		if !same(rs[i].Exprs, w) {
			t.Errorf("%s\n%s", rs[i].Text, dumpList(rs[i].Exprs))
		}
	}
}
