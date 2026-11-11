package scan_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// report reads a snapshot and scans it.
func report(t *testing.T, text string) *scan.Report {
	t.Helper()
	b, err := snapshot.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	return scan.Run(rs, h)
}

func sample(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "samples", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// One machine, eth0 at 203.0.113.10 with a default route, used by the small cases below.
const (
	addrs = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},` +
		`{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global"}]}]`
	route4 = `[{"dst":"default","gateway":"203.0.113.1","dev":"eth0"},{"dst":"203.0.113.0/24","dev":"eth0","scope":"link","prefsrc":"203.0.113.10"}]`
	sshd   = `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=830,fd=3))`
	nginx  = `tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1012,fd=6))`
	redis  = `tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=77,fd=6))`
)

// machine writes a snapshot of that machine: its filter table, its listeners and, when ufw is
// not empty, what ufw says about itself.
func machine(root bool, filter string, listeners []string, ufw string) string {
	var b strings.Builder
	b.WriteString("# seaward snapshot 1\n### meta\nhost box\nseaward test\ncollector cli\n")
	if root {
		b.WriteString("root yes\n")
	} else {
		b.WriteString("root no\n")
	}
	if filter != "" {
		b.WriteString("### iptables-version\niptables v1.8.10 (nf_tables)\n### iptables-save\n*filter\n" + filter + "COMMIT\n")
	}
	b.WriteString("### ss\n" + strings.Join(listeners, "\n") + "\n")
	b.WriteString("### ip-addr\n" + addrs + "\n### ip-route-4\n" + route4 + "\n")
	b.WriteString("### sysctl\nnet.ipv4.ip_forward = 0\n")
	if ufw != "" {
		b.WriteString("### ufw-status\n" + ufw)
	}
	return b.String()
}

const dropAll = ":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"

func ufwStatus(lines ...string) string {
	return "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\nNew profiles: skip\n\n" +
		"To                         Action      From\n--                         ------      ----\n" + strings.Join(lines, "\n") + "\n"
}

func findings(r *scan.Report) string {
	var out []string
	for _, p := range r.Ports {
		out = append(out, fmt.Sprintf("%s %s %d", p.Finding, p.Proto, p.Port))
	}
	return strings.Join(out, ", ")
}

func port(t *testing.T, r *scan.Report, proto string, n uint16) *scan.Port {
	t.Helper()
	for i := range r.Ports {
		if r.Ports[i].Proto == proto && r.Ports[i].Port == n {
			return &r.Ports[i]
		}
	}
	t.Fatalf("no %s port %d in the report: %s", proto, n, findings(r))
	return nil
}

func eq(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s:\n got  %q\n want %q", what, got, want)
	}
}

// The headline case: ufw is on and denies by default, Docker publishes three ports past it.
func TestShop(t *testing.T) {
	r := report(t, sample(t, "shop-1.snapshot"))
	eq(t, "headline", r.Headline, "7 ports can be reached from outside. ufw allows only 4 of them.")
	eq(t, "detail", r.Detail, "Docker publishes the other 3 with rules of its own, which never pass ufw's list.")
	eq(t, "findings", findings(r), "exposed tcp 5432, exposed tcp 6379, exposed tcp 8081, open tcp 22, open tcp 80, "+
		"open tcp 443, open tcp 9100, dead tcp 8443, blocked tcp 111, blocked udp 111, local tcp 53, local udp 53, local tcp 8125")
	if r.Counts != (scan.Counts{Reachable: 7, Exposed: 3, Stopped: 2, Quiet: 4}) {
		t.Errorf("counts: %+v", r.Counts)
	}
	if len(r.Unread) != 0 || len(r.Notes) != 0 {
		t.Errorf("unread %q, notes %q", r.Unread, r.Notes)
	}
	eq(t, "caveat", r.Caveat, scan.Caveat)

	db := port(t, r, "tcp", 5432)
	eq(t, "severity", db.Severity, "high")
	eq(t, "service", db.Service, "postgres in container db (postgres:16)")
	eq(t, "title", db.Title, "Reachable from the internet. ufw does not allow it.")
	eq(t, "reach", db.Reach, "the internet (IPv4 only)")
	eq(t, "stated", db.Stated, "not allowed")
	if db.Rewrite == nil || db.Deciding == nil {
		t.Fatalf("5432: rewrite %v, deciding %v", db.Rewrite, db.Deciding)
	}
	eq(t, "rewrite", db.Rewrite.Rule, "-A DOCKER ! -i br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.18.0.2:5432")
	eq(t, "deciding", db.Deciding.Rule, "-A DOCKER -d 172.18.0.2/32 ! -i br-4c2f9a71d0e3 -o br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j ACCEPT")
	if !strings.Contains(db.Why, "never sees it") {
		t.Errorf("why: %q", db.Why)
	}
	if len(db.Views) != 2 || db.Views[0].State != scan.ViewOpen || db.Views[0].Note != "IPv4 only" {
		t.Errorf("views: %+v", db.Views)
	}
	// The admin page is published on another port than the one its container listens on.
	adm := port(t, r, "tcp", 8081)
	if !strings.Contains(adm.Why, "172.18.0.4:8080") {
		t.Errorf("8081 why: %q", adm.Why)
	}

	ssh := port(t, r, "tcp", 22)
	eq(t, "ssh stated", ssh.Stated, "allowed, with a rate limit")
	eq(t, "ssh title", ssh.Title, "Reachable from the internet, as ufw allows.")
	mon := port(t, r, "tcp", 9100)
	eq(t, "9100 reach", mon.Reach, "198.51.100.0/24 only")
	if len(mon.Views) == 0 || mon.Views[0].State != scan.ViewSome || mon.Views[0].Note != "198.51.100.0/24 only" {
		t.Errorf("9100 views: %+v", mon.Views)
	}
	eq(t, "8443", port(t, r, "tcp", 8443).Title, "ufw allows it, and nothing is listening.")
	eq(t, "53", port(t, r, "tcp", 53).Why, "It is bound to 127.0.0.53, which only this machine can reach.")

	// Every cell tells its story from the first hop to the last.
	for _, p := range r.Ports {
		for _, c := range p.Cells {
			if len(c.Steps) == 0 || c.Why == "" || c.Src == "" || c.Dst == "" {
				t.Errorf("%s %d: thin cell %+v", p.Proto, p.Port, c)
			}
		}
	}
	// The report is what the page and --json show: it has to survive the trip.
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back scan.Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Headline != r.Headline || len(back.Ports) != len(r.Ports) || len(back.Ports[0].Cells) != len(r.Ports[0].Cells) {
		t.Error("the report does not survive JSON")
	}
}

func TestHeadlines(t *testing.T) {
	ufwRules := dropAll + ":ufw-user-input - [0:0]\n-A INPUT -j ufw-user-input\n" +
		"-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT\n"
	cases := []struct {
		name, snap, headline, detail, findings string
	}{
		{
			"everything allowed",
			machine(true, ufwRules, []string{sshd, nginx}, ufwStatus("22/tcp    ALLOW IN    Anywhere", "80/tcp    ALLOW IN    Anywhere")),
			"2 ports can be reached from outside, all allowed by ufw.", "",
			"open tcp 22, open tcp 80",
		},
		{
			"one, allowed",
			machine(true, ufwRules, []string{sshd}, ufwStatus("22/tcp    ALLOW IN    Anywhere", "80/tcp    ALLOW IN    Anywhere")),
			"1 port can be reached from outside, and ufw allows it.", "",
			"open tcp 22, dead tcp 80",
		},
		{
			"no firewall tool, open policy",
			machine(true, ":INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n", []string{sshd, redis}, ""),
			"2 ports can be reached from outside.", "",
			"open tcp 22, open tcp 6379",
		},
		{
			"nothing gets in",
			machine(true, dropAll, []string{sshd}, ""),
			"Nothing can be reached from outside.", "",
			"blocked tcp 22",
		},
		{
			"ufw allows it, an earlier rule stops it",
			machine(true, dropAll+":ufw-user-input - [0:0]\n-A INPUT -p tcp -m tcp --dport 80 -j DROP\n-A INPUT -j ufw-user-input\n"+
				"-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT\n",
				[]string{sshd, nginx}, ufwStatus("22/tcp    ALLOW IN    Anywhere", "80/tcp    ALLOW IN    Anywhere")),
			"1 port can be reached from outside, and ufw allows it.", "",
			"open tcp 22, shadowed tcp 80",
		},
		{
			"a rule the model cannot decide",
			machine(true, dropAll+"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 80 -m frobnicate --level 3 -j ACCEPT\n",
				[]string{sshd, nginx}, ""),
			"1 port can be reached from outside.", "1 more port could not be decided.",
			"undecided tcp 80, open tcp 22",
		},
		{
			"allowed by hand, not by ufw",
			machine(true, dropAll+":ufw-user-input - [0:0]\n-A INPUT -p tcp -m tcp --dport 6379 -j ACCEPT\n-A INPUT -j ufw-user-input\n"+
				"-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n",
				[]string{sshd, redis}, ufwStatus("22/tcp    ALLOW IN    Anywhere")),
			"2 ports can be reached from outside. ufw allows only 1 of them.", "",
			"exposed tcp 6379, open tcp 22",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := report(t, c.snap)
			eq(t, "headline", r.Headline, c.headline)
			eq(t, "detail", r.Detail, c.detail)
			eq(t, "findings", findings(r), c.findings)
			if len(r.Unread) != 0 {
				t.Errorf("unread: %q", r.Unread)
			}
		})
	}
}

// Rules nobody could read may stop or open anything: nothing is called open or closed then.
func TestUnread(t *testing.T) {
	r := report(t, machine(false, "", []string{sshd, nginx}, ""))
	eq(t, "headline", r.Headline, "The firewall rules could not be read, so nothing is decided.")
	if len(r.Unread) == 0 {
		t.Fatal("nothing listed as unread")
	}
	eq(t, "findings", findings(r), "undecided tcp 22, undecided tcp 80")
	if r.Counts.Undecided != 2 || r.Counts.Reachable != 0 {
		t.Errorf("counts: %+v", r.Counts)
	}
	out := scan.Text(r, scan.TextOptions{})
	if !strings.Contains(out, "UNDECIDED  tcp 22") || !strings.Contains(out, r.Unread[0][:20]) {
		t.Errorf("the unread rules are not loud enough:\n%s", out)
	}
}

func TestNoOutside(t *testing.T) {
	text := strings.Replace(machine(true, dropAll, []string{sshd}, ""), addrs,
		`[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]}]`, 1)
	r := report(t, text)
	eq(t, "headline", r.Headline, "No outside network interface was found, so nothing was asked.")
	if len(r.Ports) != 0 {
		t.Errorf("ports: %s", findings(r))
	}
	if out := scan.Text(r, scan.TextOptions{}); !strings.Contains(out, r.Headline) || !strings.Contains(out, scan.Caveat[:30]) {
		t.Errorf("text:\n%s", out)
	}
}

func TestTrace(t *testing.T) {
	b, err := snapshot.Parse(sample(t, "shop-1.snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	// The monitoring port is open to one network only.
	in := scan.Trace(rs, h, "tcp", 9100, netip.MustParseAddr("198.51.100.20"))
	out := scan.Trace(rs, h, "tcp", 9100, netip.MustParseAddr("192.0.2.200"))
	if len(in) != 1 || in[0].Class != "open" || len(out) != 1 || out[0].Class != "filtered" {
		t.Fatalf("in %+v\nout %+v", in, out)
	}
	if in[0].Deciding == nil || !strings.Contains(in[0].Deciding.Rule, "-s 198.51.100.0/24") {
		t.Errorf("deciding: %+v", in[0].Deciding)
	}
	// An IPv6 sender arrives at the IPv6 address, where the database is not published.
	six := scan.Trace(rs, h, "tcp", 5432, netip.MustParseAddr("2001:db8:99::1"))
	if len(six) != 1 || six[0].Dst != "2001:db8:1::10" || six[0].Class != "filtered" {
		t.Fatalf("six %+v", six)
	}
	text := scan.TraceText("tcp", 9100, in, scan.TextOptions{})
	if !strings.Contains(text, "gets through") || !strings.Contains(text, "198.51.100.20 -> 203.0.113.10") {
		t.Errorf("trace text:\n%s", text)
	}
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// The terminal report, as a person sees it.
func TestText(t *testing.T) {
	r := report(t, sample(t, "shop-1.snapshot"))
	why := func(o scan.TextOptions) string {
		var b strings.Builder
		for _, n := range []uint16{5432, 9100, 53} {
			for i := range r.Ports {
				if r.Ports[i].Port == n {
					b.WriteString(scan.WhyText(&r.Ports[i], o) + "\n")
				}
			}
		}
		return b.String()
	}
	for name, render := range map[string]func(scan.TextOptions) string{
		"shop-1.scan.txt": func(o scan.TextOptions) string { o.Hint = "seaward why PORT"; return scan.Text(r, o) },
		"shop-1.why.txt":  why,
	} {
		for _, width := range []int{100, 72} {
			plain := render(scan.TextOptions{Width: width})
			for _, ln := range strings.Split(plain, "\n") {
				if utf8.RuneCountInString(ln) > width {
					t.Errorf("%s at %d columns: a line of %d: %q", name, width, utf8.RuneCountInString(ln), ln)
				}
				if strings.TrimRight(ln, " ") != ln {
					t.Errorf("%s: trailing space in %q", name, ln)
				}
			}
			// Colour is paint only: without it the words are the same.
			if got := ansi.ReplaceAllString(render(scan.TextOptions{Width: width, Color: true}), ""); got != plain {
				t.Errorf("%s at %d columns: the coloured text reads differently", name, width)
			}
			if width != 100 {
				continue
			}
			path := filepath.Join("testdata", name)
			if *update {
				if err := os.WriteFile(path, []byte(plain), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if plain != string(want) {
				t.Errorf("%s differs from the golden file; run go test ./internal/scan -update and read the diff.\n%s", name, plain)
			}
		}
	}
	if !strings.Contains(render100(r), "\x1b[1;31mEXPOSED\x1b[0m") {
		t.Error("an exposed port is not red on a terminal")
	}
}

func render100(r *scan.Report) string { return scan.Text(r, scan.TextOptions{Color: true}) }
