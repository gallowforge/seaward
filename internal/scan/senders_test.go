package scan_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

// The tests of this file are about who is asked. The rules tell senders apart by address, and
// the scan follows one packet for every group they single out: however many rules name a sender,
// however long a set is, and whichever of its elements can arrive from where.

const ceilingOfSenders = "The rules tell more groups of senders apart than the scan asks about from one place: it asked about 1024 of them, and the senders beyond those were not asked."

// lets writes n rules that each let one sender in to port 22, and names the senders.
func lets(n int, addr func(i int) string) (rules string, names []string) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		a := addr(i)
		fmt.Fprintf(&b, "-A INPUT -s %s/32 -p tcp -m tcp --dport 22 -j ACCEPT\n", a)
		names = append(names, a)
	}
	return b.String(), names
}

// eighth is the i-th of the senders 198.51.100.8, .16, .24 and so on.
func eighth(i int) string { return fmt.Sprintf("198.51.100.%d", 8*(i+1)) }

// spread is the i-th of a long row of senders that never stand side by side.
func spread(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>12&255, i>>4&255, i&15<<4|1) }

// through lists who got a packet through to a port from one place, in the order of the report.
func through(p *scan.Port, vantage string) []string {
	var out []string
	for _, c := range p.Cells {
		if c.Vantage == vantage && c.Class == "open" {
			out = append(out, c.From)
		}
	}
	return out
}

// nftInput is the small machine with an nft input chain that drops by default and holds the
// objects given.
func nftInput(listeners []string, objects ...string) string {
	text := machine(true, "", listeners, "")
	all := append([]string{
		`{"metainfo": {"version": "1.1.7", "release_name": "Commodore Bullmoose #8", "json_schema_version": 1}}`,
		`{"table": {"family": "inet", "name": "filter", "handle": 1}}`,
		`{"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}`,
	}, objects...)
	return strings.Replace(text, "### ss\n", "### nft-json\n"+`{"nftables": [`+strings.Join(all, ", ")+"]}\n### ss\n", 1)
}

const (
	nftSaddr = `{"payload": {"protocol": "ip", "field": "saddr"}}`
	nftDport = `{"payload": {"protocol": "tcp", "field": "dport"}}`
	ssh22    = `{"match": {"op": "==", "left": ` + nftDport + `, "right": 22}}`
)

func nftRule(handle int, exprs ...string) string {
	return fmt.Sprintf(`{"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": %d, "expr": [%s]}}`, handle, strings.Join(exprs, ", "))
}

// Sixteen rules that each let one address in are sixteen senders. Every one of them is asked
// about and gets a packet of its own in the report; 0.1.0 found eleven.
func TestEverySenderARuleNamesIsAsked(t *testing.T) {
	for _, n := range []int{16, 30} {
		rules, names := lets(n, eighth)
		r := report(t, machine(true, dropAll+rules, []string{sshd}, ""))
		eq(t, "headline", r.Headline, "1 port can be reached from outside.")
		p := port(t, r, "tcp", 22)
		eq(t, "finding", p.Finding, scan.Limited)
		got := through(p, "internet")
		if strings.Join(got, " ") != strings.Join(names, " ") {
			t.Errorf("%d rules: %d senders got through from the internet: %q", n, len(got), got)
		}
		// Each is shown with the rule that lets it in, not with a neighbour's.
		for _, c := range p.Cells {
			if c.Class == "open" && (c.Deciding == nil || !strings.Contains(c.Deciding.Rule, "-s "+c.Src+"/32 ")) {
				t.Errorf("%s: decided by %+v", c.From, c.Deciding)
			}
		}
		if len(r.Notes) != 0 {
			t.Errorf("notes: %q", r.Notes)
		}
		// In a line, three of them and how many more.
		short := fmt.Sprintf("198.51.100.8, 198.51.100.16, 198.51.100.24 and %d more only", n-3)
		eq(t, "reach", p.Reach, short)
		eq(t, "title", p.Title, "Reachable from "+short+".")
		if len(p.Views) != 2 || p.Views[0].State != scan.ViewSome || p.Views[0].Note != short || p.Views[1].State != scan.ViewStopped {
			t.Errorf("views: %+v", p.Views)
		}
		// The JSON keeps every one.
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			if !strings.Contains(string(data), `"from":"`+name+`"`) {
				t.Errorf("%s is not in the JSON report", name)
			}
		}
	}
}

// Up to four names are all said; of more, the first three and how many others.
func TestManySendersAreSaidShortly(t *testing.T) {
	for _, c := range []struct {
		n     int
		reach string
	}{
		{1, "198.51.100.8 only"},
		{2, "198.51.100.8 and 198.51.100.16 only"},
		{3, "198.51.100.8, 198.51.100.16 and 198.51.100.24 only"},
		{4, "198.51.100.8, 198.51.100.16, 198.51.100.24 and 198.51.100.32 only"},
		{5, "198.51.100.8, 198.51.100.16, 198.51.100.24 and 2 more only"},
		{12, "198.51.100.8, 198.51.100.16, 198.51.100.24 and 9 more only"},
	} {
		rules, _ := lets(c.n, eighth)
		r := report(t, machine(true, dropAll+rules, []string{sshd}, ""))
		p := port(t, r, "tcp", 22)
		eq(t, fmt.Sprint(c.n, " senders, reach"), p.Reach, c.reach)
		eq(t, fmt.Sprint(c.n, " senders, title"), p.Title, "Reachable from "+c.reach+".")
		eq(t, fmt.Sprint(c.n, " senders, view"), p.Views[0].Note, c.reach)
		if got := len(through(p, "internet")); got != c.n {
			t.Errorf("%d senders: %d packets got through", c.n, got)
		}
	}
	// The local network is named before them, and counts as no sender of the list.
	rules, _ := lets(6, eighth)
	r := report(t, machine(true, dropAll+"-A INPUT -s 203.0.113.0/24 -p tcp -m tcp --dport 22 -j ACCEPT\n"+rules, []string{sshd}, ""))
	eq(t, "with the local network", port(t, r, "tcp", 22).Reach, "the local network, 198.51.100.8, 198.51.100.16, 198.51.100.24 and 3 more only")

	// What the firewall manager says is kept as short: its own list, further down, has them all.
	var status []string
	_, names := lets(16, eighth)
	for _, a := range names {
		status = append(status, "22/tcp                     ALLOW IN    "+a)
	}
	chain := ":ufw-user-input - [0:0]\n-A INPUT -j ufw-user-input\n" + strings.ReplaceAll(func() string { s, _ := lets(16, eighth); return s }(), "-A INPUT", "-A ufw-user-input")
	r = report(t, machine(true, dropAll+chain, []string{sshd}, ufwStatus(status...)))
	p := port(t, r, "tcp", 22)
	eq(t, "finding", p.Finding, scan.Open)
	eq(t, "title", p.Title, "Reachable from 198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only, as ufw allows.")
	eq(t, "stated", p.Stated, "allowed only from 198.51.100.8, from 198.51.100.16, from 198.51.100.24 and 13 more")
	if r.Frontend == nil || len(r.Frontend.Allows) != 16 {
		t.Errorf("ufw's list: %+v", r.Frontend)
	}
	// ufw allows two of them and the rules let all sixteen in: the other fourteen are the finding.
	r = report(t, machine(true, dropAll+chain, []string{sshd}, ufwStatus(status[:2]...)))
	p = port(t, r, "tcp", 22)
	eq(t, "finding, two allowed", p.Finding, scan.Exposed)
	eq(t, "title, two allowed", p.Title, "Reachable from 198.51.100.24. ufw allows it only from 198.51.100.8 and from 198.51.100.16.")
	eq(t, "reach, two allowed", p.Reach, "198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only")
}

// A long list of senders is set out so that it can be read at every width: no line runs past
// the edge, nothing is cut off, and a name or the count at the end is never broken in two.
func TestManySendersInTheTerminal(t *testing.T) {
	rules, names := lets(16, eighth)
	var status []string
	for _, a := range names {
		status = append(status, "22/tcp                     ALLOW IN    "+a)
	}
	chain := ":ufw-user-input - [0:0]\n-A INPUT -j ufw-user-input\n" + strings.ReplaceAll(rules, "-A INPUT", "-A ufw-user-input")
	plain := report(t, machine(true, dropAll+rules, []string{sshd, nginx}, ""))
	listed := report(t, machine(true, dropAll+chain, []string{sshd}, ufwStatus(status...)))
	breach := report(t, machine(true, dropAll+chain, []string{sshd}, ufwStatus(status[:2]...)))

	for _, c := range []struct {
		name  string
		r     *scan.Report
		width int
		want  string
	}{
		{"no manager", plain, 100, "" +
			"           PORT    SERVICE  REACHED BY\n" +
			"  limited  tcp 22  sshd     198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only\n" +
			"  blocked  tcp 80  nginx    nobody\n"},
		{"no manager", plain, 80, "" +
			"  limited  tcp 22  sshd     198.51.100.8, 198.51.100.16, 198.51.100.24\n" +
			"                            and 13 more only\n" +
			"  blocked  tcp 80  nginx    nobody\n"},
		{"no manager", plain, 60, "" +
			"  limited  tcp 22  sshd     198.51.100.8, 198.51.100.16,\n" +
			"                            198.51.100.24 and 13 more only\n" +
			"  blocked  tcp 80  nginx    nobody\n"},
		{"ufw allows them", listed, 100, "" +
			"  open  tcp 22  sshd     198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only\n" +
			"                ufw: allowed only from 198.51.100.8, from 198.51.100.16, from 198.51.100.24\n" +
			"                     and 13 more\n"},
		{"ufw allows them", listed, 80, "" +
			"  open  tcp 22  sshd     198.51.100.8, 198.51.100.16, 198.51.100.24\n" +
			"                         and 13 more only\n" +
			"                ufw: allowed only from 198.51.100.8, from 198.51.100.16,\n" +
			"                     from 198.51.100.24 and 13 more\n"},
		{"ufw allows them", listed, 60, "" +
			"  open  tcp 22  sshd     198.51.100.8, 198.51.100.16,\n" +
			"                         198.51.100.24 and 13 more only\n" +
			"                ufw: allowed only from 198.51.100.8,\n" +
			"                     from 198.51.100.16, from 198.51.100.24\n" +
			"                     and 13 more\n"},
		{"ufw allows two", breach, 80, "" +
			"EXPOSED  tcp 22  sshd\n" +
			"  Reachable from 198.51.100.24. ufw allows it only from 198.51.100.8 and\n" +
			"  from 198.51.100.16.\n" +
			"  reached by  198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only\n"},
		{"ufw allows two", breach, 60, "" +
			"  reached by  198.51.100.8, 198.51.100.16, 198.51.100.24\n" +
			"              and 13 more only\n"},
	} {
		out := scan.Text(c.r, scan.TextOptions{Width: c.width})
		if !strings.Contains(out, c.want) {
			t.Errorf("%s at %d columns: want\n%s\nin\n%s", c.name, c.width, c.want, out)
		}
	}
	for name, r := range map[string]*scan.Report{"no manager": plain, "ufw allows them": listed, "ufw allows two": breach} {
		for _, width := range []int{60, 64, 72, 80, 100, 110} {
			o := scan.TextOptions{Width: width, Hint: "seaward why PORT"}
			out := scan.Text(r, o)
			if strings.Contains(out, "...") {
				t.Errorf("%s at %d columns: something was cut off:\n%s", name, width, out)
			}
			if n := strings.Count(out, "13 more"); n == 0 {
				t.Errorf("%s at %d columns: the count was broken in two:\n%s", name, width, out)
			}
			for i := range r.Ports {
				out += scan.WhyText(&r.Ports[i], o)
			}
			for _, ln := range strings.Split(out, "\n") {
				if n := utf8.RuneCountInString(ln); n > width {
					t.Errorf("%s at %d columns: a line of %d: %q", name, width, n, ln)
				}
				if strings.TrimRight(ln, " ") != ln {
					t.Errorf("%s at %d columns: trailing space in %q", name, width, ln)
				}
			}
			if got := ansi.ReplaceAllString(scan.Text(r, scan.TextOptions{Width: width, Hint: "seaward why PORT", Color: true}), ""); got != scan.Text(r, o) {
				t.Errorf("%s at %d columns: the coloured text reads differently", name, width)
			}
		}
	}
}

// A whole IPv6 address is longer than the column a narrow terminal leaves for who reaches a port.
// It is broken after one of its colons: no line runs past the edge, and nothing is cut off.
func TestLongAddressesInTheTerminal(t *testing.T) {
	const (
		addrs6 = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","addr_info":[{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},` +
			`{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","addr_info":[{"family":"inet6","local":"2001:db8:1:2:3:4:5:10","prefixlen":64,"scope":"global"}]}]`
		routes6 = `[{"dst":"2001:db8:1:2::/64","dev":"eth0"},{"dst":"default","gateway":"2001:db8:1:2::1","dev":"eth0"}]`
		long    = "2001:db8:1234:5678:9abc:def0:1234:"
	)
	var rules strings.Builder
	rules.WriteString(":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n")
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&rules, "-A INPUT -s %s56%02d/128 -p tcp -m tcp --dport 22 -j ACCEPT\n", long, i)
	}
	text := "# seaward snapshot 1\n### meta\nhost box\nseaward test\ncollector cli\nroot yes\n" +
		"### ip6tables-save\n*filter\n" + rules.String() + "COMMIT\n" +
		"### ss\n" + `tcp LISTEN 0 128 [::]:22 [::]:* users:(("a-service-with-a-long-name",pid=830,fd=3))` + "\n" +
		"### ip-addr\n" + addrs6 + "\n### ip-route-6\n" + routes6 + "\n### sysctl\nnet.ipv6.conf.all.forwarding = 0\n"
	r := report(t, text)
	p := port(t, r, "tcp", 22)
	eq(t, "reach", p.Reach, long+"5601, "+long+"5602, "+long+"5603 and 3 more only")
	if got := through(p, "internet"); len(got) != 6 {
		t.Fatalf("%d senders got through: %q", len(got), got)
	}
	for _, width := range []int{60, 64, 72, 80, 100, 110} {
		o := scan.TextOptions{Width: width, Hint: "seaward why PORT"}
		out := scan.Text(r, o)
		// Every address is whole again once the lines of its column are put back together.
		joined := strings.Join(strings.Fields(out), "")
		for i := 1; i <= 3; i++ {
			if want := fmt.Sprintf("%s56%02d", long, i); !strings.Contains(joined, want) {
				t.Errorf("at %d columns %s is not all there:\n%s", width, want, out)
			}
		}
		if !strings.Contains(joined, "and3moreonly") {
			t.Errorf("at %d columns the count is missing:\n%s", width, out)
		}
		out += scan.WhyText(p, o)
		for _, ln := range strings.Split(out, "\n") {
			if n := utf8.RuneCountInString(ln); n > width {
				t.Errorf("at %d columns: a line of %d: %q", width, n, ln)
			}
		}
	}
	// At sixty columns the address is cut after a colon, under its own column.
	if out := scan.Text(r, scan.TextOptions{Width: 60}); !strings.Contains(out, "  2001:db8:1234:5678:9abc:\n") || !strings.Contains(out, "  def0:1234:5603\n") {
		t.Errorf("at 60 columns:\n%s", out)
	}
}

// Every range of a set is looked at, not the first few, in whichever order they are taken. Here
// sixteen addresses of a set cannot send from the internet: eight sit on the machine's own
// network and eight are loopback addresses. The seventeenth is out there, listed last and
// neither the lowest nor the highest of them, and it is the one sender that reaches the port
// from the internet.
func TestEveryRangeOfASetIsLookedAt(t *testing.T) {
	var elems []string
	for i := 20; i < 28; i++ {
		elems = append(elems, fmt.Sprintf(`"203.0.113.%d"`, i))
	}
	for i := 2; i < 10; i++ {
		elems = append(elems, fmt.Sprintf(`"127.0.0.%d"`, i))
	}
	elems = append(elems, `"198.51.100.50"`)
	r := report(t, nftInput([]string{sshd},
		`{"set": {"family": "inet", "name": "admins", "table": "filter", "type": "ipv4_addr", "handle": 2, "elem": [`+strings.Join(elems, ", ")+`]}}`,
		nftRule(3, ssh22, `{"match": {"op": "==", "left": `+nftSaddr+`, "right": "@admins"}}`, `{"accept": null}`)))
	p := port(t, r, "tcp", 22)
	eq(t, "reach", p.Reach, "the set admins only")
	if len(p.Views) != 2 || p.Views[0].State != scan.ViewSome || p.Views[0].Note != "the set admins only" || p.Views[1].State != scan.ViewSome {
		t.Errorf("views: %+v", p.Views)
	}
	var far *scan.Cell
	for i := range p.Cells {
		if c := &p.Cells[i]; c.Vantage == "internet" && c.Class == "open" {
			far = c
		}
	}
	if far == nil || far.Src != "198.51.100.50" || far.From != "the set admins" {
		t.Errorf("from the internet: %+v", far)
	}
}

// A verdict map, and a set that holds an address beside a port, may treat each of their elements
// differently, so each is a sender of its own: all twenty of them, not the first sixteen.
func TestEveryElementIsToldApart(t *testing.T) {
	var entries, pairs, want []string
	for i := 0; i < 20; i++ {
		verdict := `{"accept": null}`
		if i%10 == 9 {
			verdict = `{"drop": null}`
		} else {
			want = append(want, eighth(i))
		}
		entries = append(entries, fmt.Sprintf(`["%s", %s]`, eighth(i), verdict))
		pairs = append(pairs, fmt.Sprintf(`{"concat": ["%s", %d]}`, eighth(i), 22+80*(i%10/9)))
	}
	short := "198.51.100.8, 198.51.100.16, 198.51.100.24 and 15 more only"
	for name, rule := range map[string]string{
		"a verdict map": nftRule(3, ssh22, `{"vmap": {"key": `+nftSaddr+`, "data": {"set": [`+strings.Join(entries, ", ")+`]}}}`),
		"an address beside a port": nftRule(3, `{"match": {"op": "==", "left": {"concat": [`+nftSaddr+`, `+nftDport+`]}, "right": {"set": [`+
			strings.Join(pairs, ", ")+`]}}}`, `{"accept": null}`),
	} {
		r := report(t, nftInput([]string{sshd}, rule))
		p := port(t, r, "tcp", 22)
		if got := through(p, "internet"); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: %d senders got through: %q", name, len(got), got)
		}
		eq(t, name+", reach", p.Reach, short)
		if len(r.Notes) != 0 {
			t.Errorf("%s: notes %q", name, r.Notes)
		}
	}
}

// The groups of senders asked about from one place have a ceiling no ordinary ruleset comes
// near. Up to it every claim is firm and nothing is said. Past it senders were left out, and the
// report stops ruling things out: the headline says what was found and that not everyone was
// asked, a port that gets through says "at least", a port nobody asked gets through to is not
// decided, and the report carries the reason for programs to read.
func TestSenderCeilingIsSaid(t *testing.T) {
	// 1,023 named senders and "everyone else" are 1,024 groups: the ceiling, and all are asked.
	rules, names := lets(1023, spread)
	r := report(t, machine(true, dropAll+rules, []string{sshd, nginx}, ""))
	p := port(t, r, "tcp", 22)
	if got := through(p, "internet"); len(got) != 1023 || got[0] != names[0] || got[1022] != names[1022] {
		t.Errorf("at the ceiling: %d senders got through", len(got))
	}
	eq(t, "headline at the ceiling", r.Headline, "1 port can be reached from outside.")
	eq(t, "findings at the ceiling", findings(r), "limited tcp 22, blocked tcp 80")
	eq(t, "reach at the ceiling", p.Reach, "10.0.0.1, 10.0.0.17, 10.0.0.33 and 1020 more only")
	eq(t, "the other port at the ceiling", port(t, r, "tcp", 80).Reach, "nobody")
	if len(r.Notes) != 0 || len(r.Partial) != 0 {
		t.Errorf("at the ceiling: notes %q, partial %q", r.Notes, r.Partial)
	}

	// One more, and one is left out.
	rules, _ = lets(1024, spread)
	r = report(t, machine(true, dropAll+rules, []string{sshd, nginx}, ""))
	if len(r.Partial) != 1 || r.Partial[0] != ceilingOfSenders || len(r.Notes) != 0 {
		t.Fatalf("past the ceiling: partial %q, notes %q", r.Partial, r.Notes)
	}
	eq(t, "headline", r.Headline, "At least 1 port can be reached from outside.")
	eq(t, "detail", r.Detail, "Not every sender was asked. 1 more port could not be decided.")
	eq(t, "findings", findings(r), "undecided tcp 80, limited tcp 22")
	if r.Counts != (scan.Counts{Reachable: 1, Undecided: 1}) {
		t.Errorf("counts: %+v", r.Counts)
	}
	// What was found stands, as the least of it.
	p = port(t, r, "tcp", 22)
	if got := through(p, "internet"); len(got) != 1023 {
		t.Errorf("past the ceiling: %d senders got through", len(got))
	}
	const least = "at least 10.0.0.1, 10.0.0.17, 10.0.0.33 and 1020 more"
	eq(t, "reach", p.Reach, least)
	eq(t, "title", p.Title, "Reachable from "+least+".")
	if len(p.Views) != 2 || p.Views[0].State != scan.ViewSome || p.Views[0].Note != least || p.Views[1].State != scan.ViewStopped {
		t.Errorf("views: %+v", p.Views)
	}
	// What would have been ruled out is not: nobody that was asked gets through to nginx, and a
	// sender that was not asked may. From the local network everyone was asked, and is stopped.
	p = port(t, r, "tcp", 80)
	eq(t, "nginx, finding", p.Finding, scan.Undecided)
	eq(t, "nginx, severity", p.Severity, "unknown")
	eq(t, "nginx, title", p.Title, "No sender that was asked gets through, and not every sender was asked.")
	eq(t, "nginx, reach", p.Reach, "nobody that was asked")
	eq(t, "nginx, why", p.Why, ceilingOfSenders)
	if p.Deciding != nil || len(p.Views) != 2 || p.Views[0].State != scan.ViewUndecided || p.Views[1].State != scan.ViewStopped {
		t.Errorf("nginx: deciding %+v, views %+v", p.Deciding, p.Views)
	}
	// The reason is said once, under the headline, and the ports follow as a plain list.
	out := scan.Text(r, scan.TextOptions{})
	for _, want := range []string{
		"At least 1 port can be reached from outside.\nNot every sender was asked. 1 more port could not be decided.\n",
		"\nnot asked  The rules tell more groups of senders apart than the scan asks about from one place: it\n",
		"  undecided  tcp 80  nginx    nobody that was asked\n",
		"  limited    tcp 22  sshd     " + least + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("past the ceiling, missing %q in the text:\n%s", want, out)
		}
	}
	if strings.Count(out, "the senders beyond those were not asked") != 1 || strings.Contains(out, "UNDECIDED") || strings.Contains(out, " only\n") {
		t.Errorf("past the ceiling, the text:\n%s", out)
	}
	for _, width := range []int{60, 80, 100} {
		for _, ln := range strings.Split(scan.Text(r, scan.TextOptions{Width: width})+scan.WhyText(p, scan.TextOptions{Width: width}), "\n") {
			if n := utf8.RuneCountInString(ln); n > width {
				t.Errorf("at %d columns: a line of %d: %q", width, n, ln)
			}
		}
	}
	// And in the report as programs read it.
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"partial":["The rules tell more groups of senders apart`) {
		t.Error("the JSON report does not say it is partial")
	}
}

// The case that must never read as "nothing can be reached": far more senders than the ceiling
// are let in to one port, and one more sender, the last the rules name, to another. The scan
// does not get as far as that sender. It says what it found and that it did not ask everyone.
func TestNothingFoundIsNotNothingThere(t *testing.T) {
	var rules strings.Builder
	rules.WriteString(dropAll)
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&rules, "-A INPUT -s %s/32 -p tcp -m tcp --dport 8080 -j ACCEPT\n", spread(i))
	}
	rules.WriteString("-A INPUT -s 10.19.0.1/32 -p tcp -m tcp --dport 22 -j ACCEPT\n")
	text := machine(true, rules.String(), []string{sshd, redis}, "")
	r := report(t, text)
	eq(t, "headline", r.Headline, "Nothing was found reachable from outside, but not every sender was asked.")
	eq(t, "detail", r.Detail, "2 ports could not be decided.")
	eq(t, "findings", findings(r), "undecided tcp 22, undecided tcp 6379")
	if len(r.Partial) != 1 || r.Partial[0] != ceilingOfSenders {
		t.Errorf("partial: %q", r.Partial)
	}
	for _, p := range r.Ports {
		eq(t, fmt.Sprint(p.Port, " reach"), p.Reach, "nobody that was asked")
		if p.Finding == scan.Blocked || p.Finding == scan.Closed || strings.Contains(p.Title, "Stopped") {
			t.Errorf("tcp %d is ruled out: %s, %q", p.Port, p.Finding, p.Title)
		}
	}
	out := scan.Text(r, scan.TextOptions{})
	if strings.Contains(out, "Nothing can be reached") || strings.Contains(out, "blocked") || strings.Contains(out, " nobody\n") {
		t.Errorf("the text rules out what was not asked:\n%s", out)
	}
	// A port that listens on the loopback only is no open question: the kernel drops a packet
	// for the loopback that comes from outside, whoever sent it. It stays "this machine only",
	// from every place.
	const metrics = `tcp LISTEN 0 128 127.0.0.1:9093 0.0.0.0:* users:(("alertmanager",pid=91,fd=7))`
	r = report(t, machine(true, rules.String(), []string{sshd, metrics}, ""))
	eq(t, "with a loopback listener", findings(r), "undecided tcp 22, local tcp 9093")
	local := port(t, r, "tcp", 9093)
	eq(t, "the loopback listener's reach", local.Reach, "this machine only")
	for _, v := range local.Views {
		if v.State == scan.ViewUndecided {
			t.Errorf("the loopback listener seen from %s: %s", v.Vantage, v.State)
		}
	}
	// Unless the kernel is told to let such packets in (route_localnet): then a rule can send
	// one sender's packets to the loopback, and that sender may be one that was not asked.
	r = report(t, strings.Replace(machine(true, rules.String(), []string{sshd, metrics}, ""),
		"net.ipv4.ip_forward = 0\n", "net.ipv4.ip_forward = 0\nnet.ipv4.conf.all.route_localnet = 1\n", 1))
	eq(t, "with route_localnet", findings(r), "undecided tcp 22, undecided tcp 9093")
	eq(t, "with route_localnet, reach", port(t, r, "tcp", 9093).Reach, "nobody that was asked")

	// The sender the scan did not get to does reach ssh, as a packet of its own shows.
	b, err := snapshot.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	if cells := scan.Trace(rs, h, "tcp", 22, netip.MustParseAddr("10.19.0.1")); len(cells) != 1 || cells[0].Class != "open" {
		t.Errorf("from 10.19.0.1: %+v", cells)
	}
}

// within runs f and fails when it takes longer than limit. A machine under load gets two more
// tries: the guard is against work that grows with the square of a set's size, which takes many
// times the limit every time.
func within(t *testing.T, what string, limit time.Duration, f func()) {
	t.Helper()
	var took time.Duration
	for try := 0; try < 3; try++ {
		start := time.Now()
		f()
		if took = time.Since(start); took <= limit {
			return
		}
	}
	t.Errorf("%s took %v, longer than %v", what, took.Round(time.Millisecond), limit)
}

// A set of five thousand addresses is read once and searched by halving, so a scan of it takes
// no longer than a blink: as one group when being in the set is all that counts, and element by
// element, up to the ceiling, when it is a verdict map.
func TestFiveThousandElements(t *testing.T) {
	const limit = 3 * time.Second
	var all, entries []string
	for i := 0; i < 5000; i++ {
		all = append(all, `"`+spread(i)+`"`)
		entries = append(entries, `["`+spread(i)+`", {"accept": null}]`)
	}
	set := nftInput([]string{sshd, nginx},
		`{"set": {"family": "inet", "name": "admins", "table": "filter", "type": "ipv4_addr", "handle": 2, "elem": [`+strings.Join(all, ", ")+`]}}`,
		nftRule(3, ssh22, `{"match": {"op": "==", "left": `+nftSaddr+`, "right": "@admins"}}`, `{"accept": null}`))
	within(t, "a set of 5,000 addresses", limit, func() {
		r := report(t, set)
		eq(t, "findings", findings(r), "limited tcp 22, blocked tcp 80")
		p := port(t, r, "tcp", 22)
		eq(t, "reach", p.Reach, "the set admins only")
		if got := through(p, "internet"); len(got) != 1 {
			t.Errorf("a set is one group of senders: %d packets got through", len(got))
		}
		if len(r.Notes) != 0 {
			t.Errorf("notes: %q", r.Notes)
		}
	})

	// The only element that can send from the internet is the last of the five thousand: the
	// others are loopback addresses, which no packet from outside carries.
	var mostly []string
	for i := 0; i < 4999; i++ {
		mostly = append(mostly, fmt.Sprintf(`"127.%d.%d.%d"`, 1+i>>12, i>>4&255, i&15<<4|1))
	}
	mostly = append(mostly, `"198.51.100.50"`)
	last := nftInput([]string{sshd},
		`{"set": {"family": "inet", "name": "admins", "table": "filter", "type": "ipv4_addr", "handle": 2, "elem": [`+strings.Join(mostly, ", ")+`]}}`,
		nftRule(3, ssh22, `{"match": {"op": "==", "left": `+nftSaddr+`, "right": "@admins"}}`, `{"accept": null}`))
	within(t, "a set whose last element is the one sender", limit, func() {
		p := port(t, report(t, last), "tcp", 22)
		eq(t, "reach", p.Reach, "the set admins only")
		for _, c := range p.Cells {
			if c.Class == "open" && c.Src != "198.51.100.50" {
				t.Errorf("a packet from %s got through", c.Src)
			}
		}
	})

	vmap := nftInput([]string{sshd, nginx},
		`{"map": {"family": "inet", "name": "policy", "table": "filter", "type": "ipv4_addr", "handle": 2, "map": "verdict", "elem": [`+strings.Join(entries, ", ")+`]}}`,
		nftRule(3, ssh22, `{"vmap": {"key": `+nftSaddr+`, "data": "@policy"}}`))
	within(t, "a verdict map of 5,000 addresses", limit, func() {
		r := report(t, vmap)
		p := port(t, r, "tcp", 22)
		eq(t, "reach", p.Reach, "at least the set policy")
		if got := through(p, "internet"); len(got) != 1023 {
			t.Errorf("%d senders got through, want the ceiling less everyone else", len(got))
		}
		if len(r.Partial) != 1 || r.Partial[0] != ceilingOfSenders {
			t.Errorf("partial: %q", r.Partial)
		}
	})
}
