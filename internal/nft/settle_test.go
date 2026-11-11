package nft

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/ipt"
	"github.com/gallowforge/seaward/internal/rules"
)

// doc wraps listing items into an "nft -j list ruleset" document.
func doc(items ...string) []byte {
	head := `{"metainfo": {"version": "1.1.7", "release_name": "a test", "json_schema_version": 1}}`
	return []byte(`{"nftables": [` + strings.Join(append([]string{head}, items...), ",\n") + `]}`)
}

// saved parses iptables-save text the way the snapshot does before it calls ParseJSON.
func saved(t *testing.T, family, text string) []*rules.Table {
	t.Helper()
	ts, _, err := ipt.ParseSave(text, ipt.Options{Family: family})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func tableOf(t *testing.T, rs *rules.Ruleset, family, name string) *rules.Table {
	t.Helper()
	for _, tb := range rs.Tables {
		if tb.Family == family && tb.Name == name {
			return tb
		}
	}
	t.Fatalf("no table %s %s in the result", family, name)
	return nil
}

func texts(c *rules.Chain) []string {
	var out []string
	for _, r := range c.Rules {
		out = append(out, r.Text)
	}
	return out
}

func noteWith(rs *rules.Ruleset, words ...string) bool {
next:
	for _, n := range rs.Notes {
		for _, w := range words {
			if !strings.Contains(n, w) {
				continue next
			}
		}
		return true
	}
	return false
}

// TestSettleReadsWhatIptablesSaveMisprints is the reason the settle step exists. In the mixed
// fixture the nft tool added rules to a table iptables made, and iptables-save 1.8.13 printed
// three of them as something else:
//
//	tcp dport { 25, 587 } accept              as  -A INPUT -p tcp -j ACCEPT
//	ip saddr @trusted tcp dport 3306 accept   as  -A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT
//	tcp dport vmap @svc                       as  -A INPUT -p tcp
//
// Read from iptables-save alone the machine looks wide open on every TCP port. The settled table
// has to say what the kernel does.
func TestSettleReadsWhatIptablesSaveMisprints(t *testing.T) {
	shared := sharedOf(t, "mixed")
	settled := load(t, "mixed")
	alone := &rules.Ruleset{Tables: shared, Sets: map[string]*rules.Set{}}

	tb := tableOf(t, settled, "ip", "filter")
	if tb.Origin != "iptables" {
		t.Errorf("the settled table's origin is %q, want the shared table's (iptables)", tb.Origin)
	}
	in := texts(tb.Chains["INPUT"])
	for _, want := range []string{
		"tcp dport { 25, 587 } accept",
		"ip saddr @trusted tcp dport 3306 accept",
		"tcp dport vmap @svc",
		"udp dport vmap { 161 : accept, 162 : drop }",
		// and the iptables rules beside them still come from iptables-save, with their details
		"-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"-A INPUT -s 198.51.100.0/24 -p tcp -m multiport --dports 80,443 -j web",
		"-A INPUT -p tcp -m tcp --dport 9100 -j REJECT --reject-with tcp-reset",
	} {
		found := false
		for _, got := range in {
			found = found || got == want
		}
		if !found {
			t.Errorf("the settled INPUT chain has no rule %q", want)
		}
	}
	for _, got := range in {
		if got == "-A INPUT -p tcp -j ACCEPT" || got == "-A INPUT -p tcp" || got == "-A INPUT -p udp" {
			t.Errorf("the settled INPUT chain kept a misprint of iptables-save: %q", got)
		}
	}
	if want := []string{"INPUT", "FORWARD", "OUTPUT", "web", "guard", "extra"}; !reflect.DeepEqual(tb.Order, want) {
		t.Errorf("chains in the order %v, want the nft listing's %v", tb.Order, want)
	}
	if len(settled.Notes) != 0 {
		t.Errorf("unexpected notes: %q", settled.Notes)
	}

	h := labHost()
	for _, c := range []struct {
		src, proto string
		port       uint16
		want       engine.Class
		by         string // the rule or chain that decides, when it matters
	}{
		{"198.51.100.7", "tcp", 22, engine.Open, "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"},
		{"198.51.100.7", "tcp", 25, engine.Closed, "tcp dport { 25, 587 } accept"},
		{"198.51.100.7", "tcp", 587, engine.Closed, "tcp dport { 25, 587 } accept"},
		{"198.51.100.7", "tcp", 26, engine.Filtered, ""},
		{"198.51.100.7", "tcp", 5000, engine.Filtered, ""},
		{"198.51.100.7", "tcp", 3306, engine.Closed, "ip saddr @trusted tcp dport 3306 accept"},
		{"192.0.2.200", "tcp", 3306, engine.Closed, "ip saddr @trusted tcp dport 3306 accept"},
		{"203.0.113.50", "tcp", 3306, engine.Filtered, ""},
		{"203.0.113.50", "tcp", 5432, engine.Closed, "tcp dport vmap @svc"},
		{"203.0.113.50", "tcp", 6379, engine.Filtered, "tcp dport vmap @svc"},
		{"203.0.113.50", "tcp", 7000, engine.Filtered, "-A guard -j DROP"},
		{"198.51.100.7", "tcp", 9000, engine.Closed, "ip saddr . tcp dport { 198.51.100.7 . 9000, 192.0.2.0/24 . 9001-9010 } accept"},
		{"198.51.100.8", "tcp", 9000, engine.Filtered, ""},
		{"192.0.2.9", "tcp", 9005, engine.Closed, ""},
		{"203.0.113.50", "udp", 161, engine.Closed, "udp dport vmap { 161 : accept, 162 : drop }"},
		{"203.0.113.50", "udp", 162, engine.Filtered, "udp dport vmap { 161 : accept, 162 : drop }"},
		{"203.0.113.50", "udp", 163, engine.Filtered, ""},
		{"198.51.100.9", "tcp", 4000, engine.Filtered, ""}, // ip saddr .8 ip saddr .9: never both
		{"198.51.100.7", "tcp", 9100, engine.Rejected, "-A INPUT -p tcp -m tcp --dport 9100 -j REJECT --reject-with tcp-reset"},
	} {
		pr := engine.Probe{Iif: "eth0", Src: addr(c.src), Dst: addr("203.0.113.10"), Proto: c.proto, Dport: c.port}
		r := engine.Run(settled, h, pr)
		if r.Class != c.want {
			t.Errorf("%s port %d from %s: the settled rules say %s, want %s (%v)", c.proto, c.port, c.src, r.Class, c.want, r.Unknowns)
			continue
		}
		if d := r.Deciding(); c.by != "" && (d == nil || d.Rule != c.by) {
			t.Errorf("%s port %d from %s: decided by %+v, want the rule %q", c.proto, c.port, c.src, d, c.by)
		}
	}

	// The same question put to iptables-save alone: the misprinted "-p tcp -j ACCEPT" lets
	// everything in.
	pr := engine.Probe{Iif: "eth0", Src: addr("198.51.100.7"), Dst: addr("203.0.113.10"), Proto: "tcp", Dport: 5000}
	if r := engine.Run(alone, h, pr); r.Class != engine.Closed {
		t.Errorf("iptables-save alone says %s for tcp port 5000; the fixture no longer shows the misprint", r.Class)
	}
}

// TestSettleLeavesSharedAlone: the caller's tables are never changed, and the settled table shares
// no rule or chain with them that a later change could reach.
func TestSettleLeavesSharedAlone(t *testing.T) {
	for _, name := range []string{"mixed", "iptables", "iptables-more"} {
		shared, fresh := sharedOf(t, name), sharedOf(t, name)
		rs, err := ParseJSON(readFile(t, name+".json"), shared)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(shared, fresh) {
			t.Fatalf("%s: ParseJSON changed the shared tables", name)
		}
		for _, tb := range rs.Tables {
			for _, sh := range shared {
				if tb == sh {
					t.Fatalf("%s: the result holds the caller's own table %s %s", name, sh.Family, sh.Name)
				}
			}
			// Scribble over everything the result holds.
			tb.Name, tb.Origin = "scribbled", "scribbled"
			tb.Order = append(tb.Order[:0], "scribbled")
			for _, c := range tb.Chains {
				c.Name, c.Policy, c.Base = "scribbled", rules.Reject, !c.Base
				for _, r := range c.Rules {
					r.Text = "scribbled"
					for i := range r.Exprs {
						r.Exprs[i] = &rules.Never{What: "scribbled"}
					}
					r.Exprs = append(r.Exprs, &rules.Never{What: "scribbled"})
				}
				c.Rules = append(c.Rules, &rules.Rule{Text: "scribbled"})
			}
			tb.Chains["scribbled"] = &rules.Chain{Name: "scribbled"}
		}
		if !reflect.DeepEqual(shared, fresh) {
			t.Fatalf("%s: changing the result changed the shared tables", name)
		}
	}
}

// TestSettleEveryIptablesRuleKeepsItsDetails: in the fixtures made with iptables alone, every
// rule of the settled tables is the one iptables-save printed, in the same place.
func TestSettleEveryIptablesRuleKeepsItsDetails(t *testing.T) {
	for _, name := range []string{"iptables", "iptables-more"} {
		shared := sharedOf(t, name)
		rs := load(t, name)
		if len(rs.Tables) != len(shared) {
			t.Errorf("%s: %d tables in the result, %d from iptables-save", name, len(rs.Tables), len(shared))
		}
		for _, sh := range shared {
			tb := tableOf(t, rs, sh.Family, sh.Name)
			for cname, c := range tb.Chains {
				sc := sh.Chains[cname]
				if sc == nil {
					t.Errorf("%s: chain %s of %s %s is not in iptables-save", name, cname, sh.Family, sh.Name)
					continue
				}
				if !reflect.DeepEqual(texts(c), texts(sc)) {
					t.Errorf("%s: chain %s of %s %s:\n  settled:       %q\n  iptables-save: %q", name, cname, sh.Family, sh.Name, texts(c), texts(sc))
				}
				for i, r := range c.Rules {
					if i < len(sc.Rules) && !reflect.DeepEqual(r.Exprs, sc.Rules[i].Exprs) {
						t.Errorf("%s: %s reads differently after settling", name, r.Text)
					}
				}
			}
		}
		if len(rs.Notes) != 0 {
			t.Errorf("%s: unexpected notes: %q", name, rs.Notes)
		}
	}
}

const (
	tblFilter  = `{"table": {"family": "ip", "name": "filter", "handle": 1}}`
	chInput    = `{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}`
	ruleCt     = `{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 4, "expr": [{"xt": {"type": "match", "name": "conntrack"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}`
	ruleSSH    = `{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 5, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}`
	ruleRange  = `{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 6, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"range": ["198.51.100.1", "198.51.100.9"]}}}, {"accept": null}]}}`
	ruleReject = `{"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 7, "expr": [{"xt": {"type": "target", "name": "REJECT"}}]}}`
)

// TestSettleCountsDiffer: iptables-save gives up in the middle of a table when it meets certain
// nft-made rules (an address range is one), so its listing of the chain is short. The positions
// no longer line up; the chain is read from the nft listing alone and a note says what that costs.
func TestSettleCountsDiffer(t *testing.T) {
	shared := saved(t, "ip", "*filter\n:INPUT DROP [0:0]\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n")
	rs, err := ParseJSON(doc(tblFilter, chInput, ruleCt, ruleSSH, ruleRange, ruleReject), shared)
	if err != nil {
		t.Fatal(err)
	}
	tb := tableOf(t, rs, "ip", "filter")
	if tb.Origin != "iptables" {
		t.Errorf("origin %q, want iptables", tb.Origin)
	}
	c := tb.Chains["INPUT"]
	if c == nil || !c.Base || c.Hook != "input" || c.Policy != rules.Drop {
		t.Fatalf("the INPUT chain was not read from the nft listing: %+v", c)
	}
	got := dump(rs)
	want := `table ip filter (iptables)
  chain INPUT: filter hook input priority 0 policy drop
    xt match "conntrack" counter packets 0 bytes 0 accept
        UNKNOWN this condition was written by iptables (the conntrack match) and the nft listing does not say what it checks
        noop (counter)
        accept
    tcp dport 22 counter packets 0 bytes 0 accept
        match l4proto in {6}
        match dport in {22}
        noop (counter)
        accept
    ip saddr 198.51.100.1-198.51.100.9 accept
        match saddr in {198.51.100.1-198.51.100.9}
        accept
    xt target "REJECT"
        reject
note: iptables-save printed 2 rules for the chain INPUT of table ip filter and the nft listing has 4; seaward read it from the nft listing, where conditions written by iptables show only their names
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestSettleChainInOneListingOnly: a chain only the nft listing has is read from it, with a note.
// A chain only iptables-save has is left out: silently when it is empty (iptables-save prints the
// built-in chains of a table whether or not the kernel has them), with a note when it has rules.
func TestSettleChainInOneListingOnly(t *testing.T) {
	shared := saved(t, "ip", "*filter\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:ghost - [0:0]\n"+
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A ghost -j DROP\nCOMMIT\n")
	extra := `{"chain": {"family": "ip", "table": "filter", "name": "extra", "handle": 9}}`
	ruleExtra := `{"rule": {"family": "ip", "table": "filter", "chain": "extra", "handle": 10, "expr": [{"xt": {"type": "match", "name": "recent"}}, {"drop": null}]}}`
	empty := `{"chain": {"family": "ip", "table": "filter", "name": "empty", "handle": 11}}`
	rs, err := ParseJSON(doc(tblFilter, chInput, ruleSSH, extra, ruleExtra, empty), shared)
	if err != nil {
		t.Fatal(err)
	}
	tb := tableOf(t, rs, "ip", "filter")
	if want := []string{"INPUT", "extra", "empty"}; !reflect.DeepEqual(tb.Order, want) {
		t.Errorf("chains %v, want %v", tb.Order, want)
	}
	if got := texts(tb.Chains["INPUT"]); !reflect.DeepEqual(got, []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"}) {
		t.Errorf("INPUT: %q", got)
	}
	if c := tb.Chains["extra"]; c == nil || len(c.Rules) != 1 || !hasUnknown(c.Rules[0].Exprs) {
		t.Errorf("the chain extra should hold its one rule with the iptables condition as an unknown")
	}
	if !noteWith(rs, "chain extra", "is in the nft listing and not in what iptables-save printed") {
		t.Errorf("no note about the chain extra: %q", rs.Notes)
	}
	if !noteWith(rs, "iptables-save printed a chain ghost with 1 rule in table ip filter") {
		t.Errorf("no note about the chain ghost: %q", rs.Notes)
	}
	if len(rs.Notes) != 2 {
		t.Errorf("want two notes (extra, ghost) and none about empty chains, got %q", rs.Notes)
	}
}

// TestSharedTableNotInTheListing: a shared table the document does not have is not this
// package's business, and a table of another family with the same name is not the same table.
func TestSharedTableNotInTheListing(t *testing.T) {
	shared := saved(t, "ip6", "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n")
	shared = append(shared, nil) // a careless caller
	rs, err := ParseJSON(doc(tblFilter, chInput, ruleSSH), shared)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Tables) != 1 || rs.Tables[0].Family != "ip" || rs.Tables[0].Origin != "nft" {
		t.Fatalf("want the one ip table, read as an nft table; got %s", dump(rs))
	}
	if got := texts(rs.Tables[0].Chains["INPUT"]); !reflect.DeepEqual(got, []string{"tcp dport 22 counter packets 0 bytes 0 accept"}) {
		t.Errorf("INPUT: %q", got)
	}
}

// TestDocumentOrder: tables come back in the order of the document, and so do the chains of a
// table, whatever their names.
func TestDocumentOrder(t *testing.T) {
	rs, err := ParseJSON(doc(
		`{"table": {"family": "inet", "name": "zeta", "handle": 1}}`,
		`{"table": {"family": "ip6", "name": "alpha", "handle": 2}}`,
		`{"table": {"family": "ip", "name": "mid", "handle": 3}}`,
		`{"chain": {"family": "inet", "table": "zeta", "name": "c9", "handle": 1}}`,
		`{"chain": {"family": "inet", "table": "zeta", "name": "c1", "handle": 2, "type": "filter", "hook": "input", "prio": -5, "policy": "accept"}}`,
		`{"chain": {"family": "inet", "table": "zeta", "name": "c5", "handle": 3}}`,
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tb := range rs.Tables {
		got = append(got, tb.Family+" "+tb.Name+" "+tb.Origin)
	}
	if want := []string{"inet zeta nft", "ip6 alpha nft", "ip mid nft"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tables %q, want %q", got, want)
	}
	if want := []string{"c9", "c1", "c5"}; !reflect.DeepEqual(rs.Tables[0].Order, want) {
		t.Errorf("chains %q, want %q", rs.Tables[0].Order, want)
	}
	if c := rs.Tables[0].Chains["c1"]; !c.Base || c.Hook != "input" || c.Priority != -5 || c.Policy != rules.Accept || c.Type != "filter" {
		t.Errorf("chain c1: %+v", c)
	}
}
