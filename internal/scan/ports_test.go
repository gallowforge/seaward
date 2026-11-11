package scan_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

// The tests of this file are about which ports a scan asks about. A port a rule sends somewhere
// else answers without anything listening here, so every port such a rule names has to be asked:
// however many rules there are, however many ports one rule names, and whether they stand in
// the rule or in a set it looks up. A long range is asked about in part, and the report says so.

const (
	natHead     = ":PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"
	forwardAll  = ":INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
	other       = "203.0.113.50" // another machine on eth0's network, where the rules send packets
	rangeNote   = "A long range of ports is asked about at its two ends and at every port inside it that a rule, a listener or the target of a rewrite sets apart; the ports between fare like the nearest one below them that was asked: "
	ceilingNote = "The rules name more than 4096 ports; the scan asked about the first 4096 and stopped."
)

// router writes a snapshot of the small machine with forwarding on and a nat table before its
// filter table.
func router(nat, filter string, listeners []string, ufw string) string {
	text := machine(true, filter, listeners, ufw)
	text = strings.Replace(text, "*filter\n", "*nat\n"+natHead+nat+"COMMIT\n*filter\n", 1)
	return strings.Replace(text, "net.ipv4.ip_forward = 0", "net.ipv4.ip_forward = 1", 1)
}

// nftRouter is the same machine with its rules as nft prints them: the objects given, in a
// ruleset of their own.
func nftRouter(objects ...string) string {
	text := machine(true, "", nil, "")
	text = strings.Replace(text, "### ss\n", `### nft-json`+"\n"+`{"nftables": [{"metainfo": {"version": "1.1.7", "release_name": "Commodore Bullmoose #8", "json_schema_version": 1}}, `+
		strings.Join(objects, ", ")+"]}\n### ss\n", 1)
	return strings.Replace(text, "net.ipv4.ip_forward = 0", "net.ipv4.ip_forward = 1", 1)
}

// asked lists the ports of a report by number, whatever was found out about them.
func asked(r *scan.Report) string {
	var tcp, udp []string
	for _, p := range r.Ports {
		if p.Proto == "udp" {
			udp = append(udp, fmt.Sprintf("udp %d", p.Port))
		} else {
			tcp = append(tcp, fmt.Sprint(p.Port))
		}
	}
	sortNumbers(tcp)
	return strings.TrimSpace(strings.Join(tcp, " ") + " " + strings.Join(udp, " "))
}

func sortNumbers(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && (len(s[j]) < len(s[j-1]) || (len(s[j]) == len(s[j-1]) && s[j] < s[j-1])); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// notesWith picks the notes of a report that hold a text.
func notesWith(r *scan.Report, text string) []string {
	var out []string
	for _, n := range r.Notes {
		if strings.Contains(n, text) {
			out = append(out, n)
		}
	}
	return out
}

// noPortNotes fails when a report says it asked about only part of a range or stopped early.
func noPortNotes(t *testing.T, r *scan.Report) {
	t.Helper()
	if n := append(notesWith(r, "long range"), r.Partial...); len(n) != 0 {
		t.Errorf("a note about ports nobody left out: %q", n)
	}
}

// Sixty rules that each send one port on are sixty ports: there is no count past which a rule
// is no longer looked at.
func TestSixtyRewriteRulesAreSixtyPorts(t *testing.T) {
	var nat strings.Builder
	var want []string
	for port := 9000; port < 9060; port++ {
		fmt.Fprintf(&nat, "-A PREROUTING -i eth0 -p tcp -m tcp --dport %d -j DNAT --to-destination %s:%d\n", port, other, port)
		want = append(want, fmt.Sprint(port))
	}
	r := report(t, router(nat.String(), forwardAll, nil, ""))
	eq(t, "headline", r.Headline, "60 ports can be reached from outside.")
	eq(t, "ports asked", asked(r), strings.Join(want, " "))
	for _, p := range r.Ports {
		if p.Finding != scan.Open || p.Service != fmt.Sprintf("another machine, %s:%d", other, p.Port) {
			t.Errorf("tcp %d: %s, %q", p.Port, p.Finding, p.Service)
		}
	}
	noPortNotes(t, r)
}

// One rule that names eight ports is eight ports, each sent on to the port it came for.
func TestOneRuleWithEightPorts(t *testing.T) {
	r := report(t, router("-A PREROUTING -i eth0 -p tcp -m multiport --dports 7001,7002,7003,7004,7005,7006,7007,7008 -j DNAT --to-destination "+other+"\n",
		forwardAll, nil, ""))
	eq(t, "headline", r.Headline, "8 ports can be reached from outside.")
	eq(t, "ports asked", asked(r), "7001 7002 7003 7004 7005 7006 7007 7008")
	p := port(t, r, "tcp", 7008)
	eq(t, "the last of them", p.Service, "another machine, "+other+":7008")
	if p.Rewrite == nil || !strings.Contains(p.Rewrite.Rule, "--dports 7001,7002") {
		t.Errorf("rewrite: %+v", p.Rewrite)
	}
	noPortNotes(t, r)
	// A list with a short range in it, and udp: the same.
	r = report(t, router("-A PREROUTING -p udp -m multiport --dports 5000:5003,5060 -j DNAT --to-destination "+other+"\n", forwardAll, nil, ""))
	eq(t, "udp ports asked", asked(r), "udp 5000 udp 5001 udp 5002 udp 5003 udp 5060")
	noPortNotes(t, r)
}

// A range of twelve ports is asked about port by port, and nothing is said about it: nothing
// was left out. Sixteen is the longest range asked in full.
func TestShortRangeIsAskedInFull(t *testing.T) {
	r := report(t, router("-A PREROUTING -p tcp -m tcp --dport 7000:7011 -j DNAT --to-destination "+other+"\n", forwardAll, nil, ""))
	eq(t, "headline", r.Headline, "12 ports can be reached from outside.")
	eq(t, "ports asked", asked(r), "7000 7001 7002 7003 7004 7005 7006 7007 7008 7009 7010 7011")
	noPortNotes(t, r)

	for _, c := range []struct {
		last  int
		ports int
		note  bool
	}{{7015, 16, false}, {7016, 4, true}} {
		// 7005 is singled out by a rule, so a range asked in part has four ports to ask: its two
		// ends, the port the rule names and the one after it.
		r = report(t, router(fmt.Sprintf("-A PREROUTING -p tcp -m tcp --dport 7000:%d -j DNAT --to-destination %s\n", c.last, other),
			":INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A FORWARD -p tcp -m tcp --dport 7005 -j DROP\n", nil, ""))
		if len(r.Ports) != c.ports {
			t.Errorf("a range of %d ports: %d asked (%s), want %d", c.last-6999, len(r.Ports), asked(r), c.ports)
		}
		if got := len(notesWith(r, "long range")) == 1; got != c.note {
			t.Errorf("a range of %d ports: notes %q", c.last-6999, r.Notes)
		}
		eq(t, "the port a rule stops", port(t, r, "tcp", 7005).Finding, scan.Blocked)
	}
}

// A range of two thousand ports is asked about at its two ends and at every port something sets
// apart: here a listener of this machine and a rule that lets one port through. The report says
// which range it asked in part, once, and every port between the ones asked fares like the
// nearest one below it.
func TestLongRangeIsAskedWhereSomethingChanges(t *testing.T) {
	text := router("-A PREROUTING -p tcp -m tcp --dport 20000:21999 -j DNAT --to-destination "+other+"\n",
		":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A FORWARD -p tcp -m tcp --dport 20700 -j ACCEPT\n",
		[]string{`tcp LISTEN 0 128 0.0.0.0:20500 0.0.0.0:* users:(("game",pid=7,fd=3))`}, "")
	r := report(t, text)
	eq(t, "headline", r.Headline, "1 port can be reached from outside.")
	// The two ends; the listener's port and the one after it; the rule's port and the one after it.
	eq(t, "ports asked", asked(r), "20000 20500 20501 20700 20701 21999")
	eq(t, "findings", findings(r), "open tcp 20700, blocked tcp 20000, blocked tcp 20500, blocked tcp 20501, blocked tcp 20701, blocked tcp 21999")
	eq(t, "the port let through", port(t, r, "tcp", 20700).Service, "another machine, "+other+":20700")
	// The listener never gets its packet: the rule sends it on before this machine would take it.
	if p := port(t, r, "tcp", 20500); p.Rewrite == nil || p.Deciding == nil || !strings.Contains(p.Deciding.Effect, "policy drop") {
		t.Errorf("20500: rewrite %+v, deciding %+v", p.Rewrite, p.Deciding)
	}
	if len(r.Notes) != 1 {
		t.Fatalf("notes: %q", r.Notes)
	}
	eq(t, "the note", r.Notes[0], rangeNote+"tcp 20000 to 21999.")
	if out := scan.Text(r, scan.TextOptions{}); strings.Count(out, "tcp 20000 to 21999") != 1 || !strings.Contains(out, "note        A long range of ports") {
		t.Errorf("the range is not named once in the text:\n%s", out)
	}

	// What the note promises, held against packets of their own to ports that were not asked.
	b, err := snapshot.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	class := func(n uint16) string {
		cells := scan.Trace(rs, h, "tcp", n, netip.MustParseAddr("198.51.100.7"))
		if len(cells) != 1 {
			t.Fatalf("port %d: %d cells", n, len(cells))
		}
		return cells[0].Class
	}
	for _, c := range []struct{ between, below uint16 }{{20001, 20000}, {20499, 20000}, {20600, 20501}, {20699, 20501}, {20702, 20701}, {21998, 20701}} {
		if got, want := class(c.between), class(c.below); got != want {
			t.Errorf("port %d is %s, the nearest port asked below it (%d) %s", c.between, got, c.below, want)
		}
	}
	eq(t, "the port let through, followed", class(20700), "forwarded")

	// Two rules on the same range are one range; a second range is named beside the first.
	r = report(t, router("-A PREROUTING -p tcp -m tcp --dport 20000:21999 -j DNAT --to-destination "+other+"\n"+
		"-A PREROUTING -p tcp -m tcp --dport 20000:21999 -j DNAT --to-destination 203.0.113.51\n"+
		"-A PREROUTING -p udp -m udp --dport 30000:30999 -j DNAT --to-destination "+other+"\n", forwardAll, nil, ""))
	if len(r.Notes) != 1 {
		t.Fatalf("notes: %q", r.Notes)
	}
	eq(t, "two ranges", r.Notes[0], rangeNote+"tcp 20000 to 21999 and udp 30000 to 30999.")
	eq(t, "ports asked", asked(r), "20000 21999 udp 30000 udp 30999")
}

// A rule that looks its ports up in a named set sends every port of the set on, so every one of
// them is asked about: single ports and a short range, and the same for a set that holds ports
// beside another field.
func TestPortsInANamedSetAreAsked(t *testing.T) {
	const (
		table = `{"table": {"family": "ip", "name": "nat", "handle": 1}}`
		chain = `{"chain": {"family": "ip", "table": "nat", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}`
		dport = `{"payload": {"protocol": "tcp", "field": "dport"}}`
	)
	r := report(t, nftRouter(table, chain,
		`{"set": {"family": "ip", "name": "web", "table": "nat", "type": "inet_service", "handle": 2, "flags": ["interval"], "elem": [8080, 8443, {"range": [9000, 9002]}]}}`,
		`{"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 3, "expr": [{"match": {"op": "==", "left": `+dport+`, "right": "@web"}}, {"dnat": {"addr": "`+other+`"}}]}}`))
	eq(t, "headline", r.Headline, "5 ports can be reached from outside.")
	eq(t, "ports asked", asked(r), "8080 8443 9000 9001 9002")
	p := port(t, r, "tcp", 9001)
	eq(t, "inside the range", p.Service, "another machine, "+other+":9001")
	if p.Rewrite == nil || !strings.Contains(p.Rewrite.Rule, "@web") {
		t.Errorf("rewrite: %+v", p.Rewrite)
	}
	noPortNotes(t, r)

	// An address and a port side by side: the ports of the set are asked, and only the address
	// the set pairs each with is sent on.
	r = report(t, nftRouter(table, chain,
		`{"set": {"family": "ip", "name": "pairs", "table": "nat", "type": ["ipv4_addr", "inet_service"], "handle": 2, "elem": [{"concat": ["203.0.113.10", 7000]}, {"concat": ["203.0.113.10", 7001]}, {"concat": ["192.0.2.99", 7002]}]}}`,
		`{"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 3, "expr": [{"match": {"op": "==", "left": {"concat": [{"payload": {"protocol": "ip", "field": "daddr"}}, `+dport+`]}, "right": "@pairs"}}, {"dnat": {"addr": "`+other+`"}}]}}`))
	eq(t, "ports asked, pairs", asked(r), "7000 7001 7002")
	eq(t, "findings, pairs", findings(r), "open tcp 7000, open tcp 7001, closed tcp 7002")

	// A set with a long range in it is asked like a long range in a rule.
	r = report(t, nftRouter(table, chain,
		`{"set": {"family": "ip", "name": "many", "table": "nat", "type": "inet_service", "handle": 2, "flags": ["interval"], "elem": [443, {"range": [20000, 21999]}]}}`,
		`{"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 3, "expr": [{"match": {"op": "==", "left": `+dport+`, "right": "@many"}}, {"dnat": {"addr": "`+other+`"}}]}}`))
	eq(t, "ports asked, long range in a set", asked(r), "443 20000 21999")
	if len(r.Notes) != 1 || r.Notes[0] != rangeNote+"tcp 20000 to 21999." {
		t.Errorf("notes: %q", r.Notes)
	}
}

// A long range the firewall manager was told to open is asked the same way: its ends, and the
// ports inside it something sets apart.
func TestLongRangeInTheManagersList(t *testing.T) {
	filter := dropAll + ":ufw-user-input - [0:0]\n-A INPUT -j ufw-user-input\n" +
		"-A ufw-user-input -p tcp -m multiport --dports 20000:21999 -j ACCEPT\n"
	game := `tcp LISTEN 0 128 0.0.0.0:20500 0.0.0.0:* users:(("game",pid=7,fd=3))`
	r := report(t, machine(true, filter, []string{game}, ufwStatus("20000:21999/tcp            ALLOW IN    Anywhere")))
	eq(t, "headline", r.Headline, "1 port can be reached from outside, and ufw allows it.")
	eq(t, "ports asked", asked(r), "20000 20500 20501 21999")
	eq(t, "findings", findings(r), "open tcp 20500, dead tcp 20000, dead tcp 20501, dead tcp 21999")
	eq(t, "stated", port(t, r, "tcp", 20501).Stated, "allowed")
	if len(r.Notes) != 1 || r.Notes[0] != rangeNote+"tcp 20000 to 21999." {
		t.Errorf("notes: %q", r.Notes)
	}
	if r.Frontend == nil || strings.Join(r.Frontend.Allows, "; ") != "20000-21999/tcp" {
		t.Errorf("ufw's list: %+v", r.Frontend)
	}

	// A short range in the list is asked in full, without a word.
	r = report(t, machine(true, dropAll, []string{sshd}, ufwStatus("6000:6007/udp              ALLOW IN    Anywhere")))
	eq(t, "ports asked, short", asked(r), "22 udp 6000 udp 6001 udp 6002 udp 6003 udp 6004 udp 6005 udp 6006 udp 6007")
	noPortNotes(t, r)
	// A range without a protocol is asked as tcp, as a single port without one is.
	r = report(t, machine(true, dropAll, nil, ufwStatus("30000:39999                ALLOW IN    Anywhere")))
	eq(t, "ports asked, no protocol", asked(r), "30000 39999")
	if len(r.Notes) != 1 || r.Notes[0] != rangeNote+"tcp 30000 to 39999." {
		t.Errorf("notes: %q", r.Notes)
	}
}

// The list of ports has a ceiling no ordinary machine comes near. A ruleset that names more
// ports than that is asked about up to the ceiling, and the report says it stopped.
func TestPortCeilingIsSaid(t *testing.T) {
	// A set of 4,200 single ports, every third one from 10000 on, sent to another machine.
	set := func(n int) string {
		var elems []string
		for i := 0; i < n; i++ {
			elems = append(elems, fmt.Sprint(10000+3*i))
		}
		return `{"set": {"family": "ip", "name": "many", "table": "nat", "type": "inet_service", "handle": 2, "elem": [` + strings.Join(elems, ", ") + `]}}`
	}
	ruleset := func(n int) string {
		return nftRouter(`{"table": {"family": "ip", "name": "nat", "handle": 1}}`,
			`{"chain": {"family": "ip", "table": "nat", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}`,
			set(n),
			`{"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 3, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "@many"}}, {"dnat": {"addr": "`+other+`"}}]}}`)
	}
	r := report(t, ruleset(4200))
	if len(r.Ports) != 4096 {
		t.Errorf("%d ports asked, want the ceiling of 4096", len(r.Ports))
	}
	// What was found is the least of it, and the headline says so.
	eq(t, "headline", r.Headline, "At least 4096 ports can be reached from outside.")
	eq(t, "detail", r.Detail, "Not every port was asked.")
	if len(r.Partial) != 1 || r.Partial[0] != ceilingNote || len(r.Notes) != 0 {
		t.Errorf("partial %q, notes %q", r.Partial, r.Notes)
	}
	out := scan.Text(r, scan.TextOptions{})
	if strings.Count(out, "asked about the first 4096 and stopped") != 1 || !strings.Contains(out, "\nnot asked  The rules name more than 4096 ports;") {
		t.Error("the ceiling is not said once, under the headline")
	}
	// The ports that were asked were asked from everyone: what is said of them stands.
	eq(t, "a port that was asked", port(t, r, "tcp", 10000).Finding, scan.Open)
	// Exactly at the ceiling nothing was left out, and nothing is said.
	r = report(t, ruleset(4096))
	if len(r.Ports) != 4096 || len(r.Notes) != 0 || len(r.Partial) != 0 {
		t.Errorf("at the ceiling: %d ports, notes %q, partial %q", len(r.Ports), r.Notes, r.Partial)
	}
	eq(t, "headline at the ceiling", r.Headline, "4096 ports can be reached from outside.")

	// A port the scan did not come to is still answered for when it is asked about by itself
	// ("seaward why"): it is sent on like the rest, and "no rule sends it anywhere" would be false.
	b, err := snapshot.Parse(ruleset(4200))
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	last := uint16(10000 + 3*4199)
	one := scan.One(rs, h, "", last)
	if len(one) != 1 || one[0].Proto != "tcp" || one[0].Port != last || one[0].Finding != scan.Open {
		t.Errorf("the last port of the set, asked by itself: %+v", one)
	}
	if got := scan.One(rs, h, "", last+1); len(got) != 0 {
		t.Errorf("a port between two of the set: %+v", got)
	}
	if got := scan.One(rs, h, "udp", last); len(got) != 0 {
		t.Errorf("the same port of udp: %+v", got)
	}

	// Nothing reachable among the ports that were asked is not "nothing can be reached".
	closed := strings.Replace(ruleset(4200), `{"dnat": {"addr": "`+other+`"}}`, `{"redirect": {"port": 9}}`, 1)
	r = report(t, closed)
	eq(t, "headline, nothing found", r.Headline, "Nothing was found reachable from outside, but not every port was asked.")
	eq(t, "a port that was asked, nothing found", port(t, r, "tcp", 10000).Finding, scan.Closed)
}

// The rule that names a port and the rule that rewrites are often not the same rule: the first
// jumps, and the chain it jumps to, or one further on, sends the packet somewhere else. Every
// port that can come as far as a rewrite is asked about. 0.1.0, and the first take at 0.1.1,
// looked for both in one rule and said "Nothing can be reached from outside." of a machine that
// passed eleven ports on.
func TestRewriteBehindAJump(t *testing.T) {
	const chains = ":FWD - [0:0]\n:DEEP - [0:0]\n"
	nat := func(rules string) string { return router(chains+rules, forwardAll, nil, "") }
	for _, c := range []struct {
		name, rules, asked, headline string
	}{
		{"the port in the calling rule",
			"-A PREROUTING -p tcp --dport 8000:8010 -j FWD\n-A FWD -j DNAT --to-destination " + other + "\n",
			"8000 8001 8002 8003 8004 8005 8006 8007 8008 8009 8010", "11 ports can be reached from outside."},
		{"the port in the chain jumped to",
			"-A PREROUTING -i eth0 -j FWD\n-A FWD -p tcp -m tcp --dport 7001 -j DNAT --to-destination " + other + "\n" +
				"-A FWD -p udp -m multiport --dports 5000,5060 -j DNAT --to-destination " + other + "\n",
			"7001 udp 5000 udp 5060", "3 ports can be reached from outside."},
		// Only what passes both is rewritten. 9000 is asked all the same, because a rule that
		// rewrites names it: a port too many costs a line, and a port missed is the worst this
		// tool can do. The answer for it is the true one: nothing there.
		{"a port in both",
			"-A PREROUTING -p tcp -m tcp --dport 8000:8010 -j FWD\n-A FWD -p tcp -m tcp --dport 8005 -j DNAT --to-destination " + other + "\n" +
				"-A FWD -p tcp -m tcp --dport 9000 -j DNAT --to-destination " + other + "\n",
			"8005 9000", "1 port can be reached from outside."},
		{"two chains deep, by goto",
			"-A PREROUTING -p tcp -m multiport --dports 2201,2202 -g FWD\n-A FWD -m comment --comment \"to the inner network\" -j DEEP\n" +
				"-A DEEP -p tcp -j DNAT --to-destination " + other + ":22\n",
			"2201 2202", "2 ports can be reached from outside."},
		{"past a condition nobody can decide",
			"-A PREROUTING -p tcp -m tcp --dport 443 -j FWD\n-A FWD -m statistic --mode random --probability 0.5 -j DEEP\n" +
				"-A DEEP -p tcp -j DNAT --to-destination " + other + ":8443\n",
			"443", "1 port could not be decided."},
		{"a redirect to a port of this machine",
			"-A PREROUTING -p tcp -m tcp --dport 80 -j FWD\n-A FWD -p tcp -j REDIRECT --to-ports 9\n",
			"80", "Nothing can be reached from outside."},
		// What the rules send packets to is no port to ask about: 8443 is where they go, not
		// where they come in.
		{"a rule that never runs for a packet from outside",
			"-A OUTPUT -p tcp -m tcp --dport 7000 -j FWD\n-A FWD -j DNAT --to-destination " + other + "\n",
			"", "Nothing can be reached from outside."},
	} {
		r := report(t, nat(c.rules))
		eq(t, c.name+": ports asked", asked(r), c.asked)
		eq(t, c.name+": headline", r.Headline, c.headline)
		noPortNotes(t, r)
	}
	// The report of a port behind a jump names the rule that rewrites, in its own chain.
	r := report(t, nat("-A PREROUTING -p tcp --dport 8000:8010 -j FWD\n-A FWD -j DNAT --to-destination "+other+"\n"))
	p := port(t, r, "tcp", 8010)
	eq(t, "service", p.Service, "another machine, "+other+":8010")
	if p.Rewrite == nil || p.Rewrite.Chain != "FWD" || p.Rewrite.Rule != "-A FWD -j DNAT --to-destination "+other {
		t.Errorf("rewrite: %+v", p.Rewrite)
	}
}

// A rewrite that no rule on the way narrows to a port takes every port: of tcp and of udp when no
// protocol is named either. That is a long range like any other. It is asked at its ends and
// wherever something sets a port apart, the report says so, and it does not count the few ports
// it asked as all there are.
func TestRewriteOfEveryPort(t *testing.T) {
	r := report(t, router("-A PREROUTING -i eth0 -j DNAT --to-destination "+other+"\n", forwardAll, []string{sshd}, ""))
	eq(t, "ports asked", asked(r), "1 22 23 65535 udp 1 udp 22 udp 23 udp 65535")
	eq(t, "headline", r.Headline, "At least 8 ports can be reached from outside.")
	eq(t, "detail", r.Detail, "A long range of ports was asked about in part: a port in it stands for the ports up to the next one asked.")
	if len(r.Notes) != 1 || r.Notes[0] != rangeNote+"tcp 1 to 65535 and udp 1 to 65535." {
		t.Errorf("notes: %q", r.Notes)
	}
	// sshd never gets its packet: it is sent on like every other.
	eq(t, "ssh", port(t, r, "tcp", 22).Service, "another machine, "+other+":22")
	if len(r.Partial) != 0 {
		t.Errorf("a long range is no ceiling: partial %q", r.Partial)
	}

	// With a protocol named, that protocol's ports.
	r = report(t, router("-A PREROUTING -i eth0 -p udp -j DNAT --to-destination "+other+"\n", forwardAll, nil, ""))
	eq(t, "udp alone", asked(r), "udp 1 udp 65535")
	// A range asked in part whose reachable port stands alone is counted as it is.
	r = report(t, router("-A PREROUTING -p tcp -m tcp --dport 20000:21999 -j DNAT --to-destination "+other+"\n",
		":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A FORWARD -p tcp -m tcp --dport 20700 -j ACCEPT\n", nil, ""))
	eq(t, "one port of a long range", r.Headline, "1 port can be reached from outside.")
	eq(t, "one port of a long range, detail", r.Detail, "")
}

// A statement the engine cannot follow may send a packet elsewhere too, when it stands where a
// packet passes before routing. Its ports are asked about, and are undecided, with the reason:
// a proxy that takes port 3128 by TPROXY is not passed over because nothing listens on 3128.
func TestStatementThatCannotBeFollowed(t *testing.T) {
	text := machine(true, dropAll, []string{sshd}, "")
	text = strings.Replace(text, "*filter\n", "*mangle\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"+
		"-A PREROUTING -p tcp -m tcp --dport 3128 -j TPROXY --on-port 3129 --on-ip 127.0.0.1 --tproxy-mark 0x1/0x1\nCOMMIT\n*filter\n", 1)
	r := report(t, text)
	eq(t, "findings", findings(r), "undecided tcp 3128, blocked tcp 22")
	p := port(t, r, "tcp", 3128)
	if !strings.Contains(p.Why, "TPROXY") {
		t.Errorf("why: %q", p.Why)
	}
	eq(t, "headline", r.Headline, "1 port could not be decided.")
	eq(t, "detail", r.Detail, "No other port can be reached from outside.")
	// The same statement in a chain a packet passes after routing sends nothing elsewhere.
	r = report(t, machine(true, dropAll+"-A INPUT -p tcp -m tcp --dport 3128 -j NFQUEUE --queue-num 0\n", []string{sshd}, ""))
	eq(t, "after routing", findings(r), "blocked tcp 22")

	// Over a long range, the two ports asked stand for a thousand: the count is the least there are.
	r = report(t, strings.Replace(text, "--dport 3128 ", "--dport 3000:3999 ", 1))
	eq(t, "a long range", findings(r), "undecided tcp 3000, undecided tcp 3999, blocked tcp 22")
	eq(t, "a long range, headline", r.Headline, "At least 2 ports could not be decided.")
	eq(t, "a long range, detail", r.Detail, "No other port can be reached from outside. A long range of ports was asked about in part: a port in it stands for the ports up to the next one asked.")
}

// The same in nftables: a jump, a goto and a verdict map each lead to a chain that rewrites, and
// a port matched without a protocol is a port of tcp and of udp.
func TestRewriteBehindAJumpNft(t *testing.T) {
	const (
		table = `{"table": {"family": "ip", "name": "nat", "handle": 1}}`
		pre   = `{"chain": {"family": "ip", "table": "nat", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}`
		fwd   = `{"chain": {"family": "ip", "table": "nat", "name": "fwd", "handle": 2}}`
		deep  = `{"chain": {"family": "ip", "table": "nat", "name": "deep", "handle": 3}}`
		dport = `{"payload": {"protocol": "tcp", "field": "dport"}}`
		toFwd = `{"rule": {"family": "ip", "table": "nat", "chain": "fwd", "handle": 10, "expr": [{"dnat": {"addr": "` + other + `"}}]}}`
	)
	in := func(chain string, handle int, exprs ...string) string {
		return fmt.Sprintf(`{"rule": {"family": "ip", "table": "nat", "chain": "%s", "handle": %d, "expr": [%s]}}`, chain, handle, strings.Join(exprs, ", "))
	}
	match := func(right string) string {
		return `{"match": {"op": "==", "left": ` + dport + `, "right": ` + right + `}}`
	}
	for _, c := range []struct {
		name  string
		rules []string
		asked string
	}{
		{"jump", []string{in("prerouting", 4, match(`{"range": [8000, 8010]}`), `{"jump": {"target": "fwd"}}`), toFwd},
			"8000 8001 8002 8003 8004 8005 8006 8007 8008 8009 8010"},
		{"goto, and the port in the chain it goes to",
			[]string{in("prerouting", 4, `{"goto": {"target": "fwd"}}`), in("fwd", 10, match(`{"set": [7001, 7003]}`), `{"dnat": {"addr": "`+other+`"}}`)},
			"7001 7003"},
		{"a verdict map: only the entries that lead to a rewrite",
			[]string{in("prerouting", 4, `{"vmap": {"key": `+dport+`, "data": {"set": [[8200, {"jump": {"target": "fwd"}}], [8201, {"goto": {"target": "deep"}}], [8202, {"accept": null}], [8203, {"jump": {"target": "idle"}}]]}}}`),
				toFwd, in("deep", 11, `{"redirect": {"port": 9}}`), `{"chain": {"family": "ip", "table": "nat", "name": "idle", "handle": 5}}`},
			"8200 8201"},
		{"a named verdict map",
			[]string{`{"map": {"family": "ip", "name": "byport", "table": "nat", "type": "inet_service", "handle": 6, "map": "verdict", "elem": [[8300, {"jump": {"target": "fwd"}}], [8301, {"drop": null}]]}}`,
				in("prerouting", 4, `{"vmap": {"key": `+dport+`, "data": "@byport"}}`), toFwd},
			"8300"},
		{"a jump under a jump, the port named twice",
			[]string{in("prerouting", 4, match(`{"range": [8400, 8410]}`), `{"jump": {"target": "deep"}}`),
				in("deep", 11, match(`{"set": [8404, 8405, 9999]}`), `{"jump": {"target": "fwd"}}`), toFwd},
			"8404 8405"},
		{"a port without a protocol",
			[]string{in("prerouting", 4, `{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}}`,
				`{"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": 5353}}`, `{"jump": {"target": "fwd"}}`), toFwd},
			"5353 udp 5353"},
	} {
		r := report(t, nftRouter(append([]string{table, pre, fwd, deep}, c.rules...)...))
		eq(t, c.name+": ports asked", asked(r), c.asked)
		noPortNotes(t, r)
		for _, p := range r.Ports {
			if p.Rewrite == nil {
				t.Errorf("%s: %s %d is asked and not rewritten: %s", c.name, p.Proto, p.Port, p.Why)
			}
		}
	}
}

// A rewrite to a range of ports cuts a long range it is taken from in two more places. The
// kernel keeps a packet's own port when that lies in the target range and uses the first port
// of the range when it does not: the ports just below the target range, the ports in it and the
// ports just above it fare three ways, and each is asked about.
func TestTargetRangeCutsALongRange(t *testing.T) {
	text := router("-A PREROUTING -p tcp -m tcp --dport 8000:9500 -j DNAT --to-destination "+other+":9000-9100\n",
		":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A FORWARD -p tcp -m tcp --dport 9000 -j ACCEPT\n", nil, "")
	text = strings.Replace(text, "*filter\n", "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A PREROUTING -p tcp -m tcp --dport 9400:9500 -j DROP\nCOMMIT\n*filter\n", 1)
	r := report(t, text)
	// 9000 and 9101 are the ends of the target range; 9001 is where the accept rule ends.
	eq(t, "ports asked", asked(r), "8000 9000 9001 9101 9400 9500")
	eq(t, "findings", findings(r), "open tcp 8000, open tcp 9000, open tcp 9101, blocked tcp 9001, blocked tcp 9400, blocked tcp 9500")
	eq(t, "above the target range", port(t, r, "tcp", 9101).Service, "another machine, "+other+":9000")
	eq(t, "headline", r.Headline, "At least 3 ports can be reached from outside.")
	if len(r.Notes) != 1 || r.Notes[0] != rangeNote+"tcp 8000 to 9500." {
		t.Errorf("notes: %q", r.Notes)
	}
	// What the note promises, held against a packet of its own to every port of the range.
	b, err := snapshot.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	class := func(n int) string {
		cells := scan.Trace(rs, h, "tcp", uint16(n), netip.MustParseAddr("198.51.100.7"))
		if len(cells) != 1 {
			t.Fatalf("port %d: %d cells", n, len(cells))
		}
		return cells[0].Class
	}
	scanned := map[int]bool{8000: true, 9000: true, 9001: true, 9101: true, 9400: true, 9500: true}
	last := ""
	for n := 8000; n <= 9500; n++ {
		got := class(n)
		if scanned[n] {
			last = got
		} else if got != last {
			t.Fatalf("port %d is %s, the nearest port asked below it %s", n, got, last)
		}
	}
	eq(t, "below the target range", class(8500), "forwarded")
	eq(t, "inside it", class(9050), "filtered")
	eq(t, "above it", class(9300), "forwarded")

	// The same for a redirect to ports of this machine, where what listens decides.
	listen := func(n int) string {
		return fmt.Sprintf(`tcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:(("app",pid=%d,fd=3))`, n, n)
	}
	r = report(t, router("-A PREROUTING -p tcp -m tcp --dport 8000:9500 -j REDIRECT --to-ports 9000-9100\n",
		":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n", []string{listen(9000), listen(9050)}, ""))
	eq(t, "redirect, ports asked", asked(r), "8000 9000 9001 9050 9051 9101 9500")
	eq(t, "redirect, findings", findings(r), "open tcp 8000, open tcp 9000, open tcp 9050, open tcp 9101, open tcp 9500, closed tcp 9001, closed tcp 9051")

	// And as nftables writes both.
	const (
		table = `{"table": {"family": "ip", "name": "nat", "handle": 1}}`
		pre   = `{"chain": {"family": "ip", "table": "nat", "name": "prerouting", "handle": 1, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}`
		from  = `{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"range": [8000, 9500]}}}`
	)
	for name, target := range map[string]string{
		"dnat to addr:lo-hi": `{"dnat": {"addr": "` + other + `", "port": {"range": [9000, 9100]}}}`,
		"redirect to :lo-hi": `{"redirect": {"port": {"range": [9000, 9100]}}}`,
	} {
		r = report(t, nftRouter(table, pre, `{"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "handle": 3, "expr": [`+from+`, `+target+`]}}`))
		eq(t, name+": ports asked", asked(r), "8000 9000 9101 9500")
	}
}
