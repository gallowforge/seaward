package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const shop = "../../samples/shop-1.snapshot"

// v4Machine is the machine part of a small snapshot: sshd on one interface that has an IPv4
// address and no IPv6 one. A test puts its own meta and rules in front.
const v4Machine = `### ss
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=830,fd=3))
### ip-addr
[{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","UP","LOWER_UP"],"link_type":"ether","addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global"}]}]
### ip-route-4
[{"dst":"default","gateway":"203.0.113.1","dev":"eth0"},{"dst":"203.0.113.0/24","dev":"eth0","scope":"link"}]
`

// seaward runs the command as a person would, and returns what it printed and its exit status.
func seaward(t *testing.T, stdin string, args ...string) (out, errOut string, code int) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(context.Background(), args, strings.NewReader(stdin), &o, &e)
	return o.String(), e.String(), code
}

func TestScan(t *testing.T) {
	out, errOut, code := seaward(t, "", "scan", "-f", shop)
	if code != exitOK || errOut != "" {
		t.Fatalf("status %d, stderr %q", code, errOut)
	}
	for _, want := range []string{
		"seaward  shop-1",
		"7 ports can be reached from outside. ufw allows only 4 of them.",
		"EXPOSED  tcp 5432  postgres in container db (postgres:16)",
		"--to-destination",
		"To follow a packet rule by rule: seaward why 5432 -f " + shop,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour in output that is not a terminal")
	}
	// The same file through a pipe, options before the command, colour forced.
	data, err := os.ReadFile(shop)
	if err != nil {
		t.Fatal(err)
	}
	piped, _, code := seaward(t, string(data), "--color", "--file=-", "scan")
	if code != exitOK || !strings.Contains(piped, "\x1b[1;31mEXPOSED\x1b[0m") {
		t.Errorf("status %d, piped report:\n%s", code, piped)
	}
	if plain, _, _ := seaward(t, string(data), "scan", "-f", "-", "--color", "--no-color"); strings.Contains(plain, "\x1b[") {
		t.Error("--no-color did not win")
	}
}

func TestScanJSON(t *testing.T) {
	out, _, code := seaward(t, "", "scan", "--json", "-f", shop)
	if code != exitOK {
		t.Fatalf("status %d", code)
	}
	var rep struct {
		Host     string
		Headline string
		Ports    []struct {
			Proto   string
			Port    int
			Finding string
		}
		Counts struct{ Exposed int }
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Host != "shop-1" || len(rep.Ports) != 13 || rep.Ports[0].Finding != "exposed" || rep.Ports[0].Port != 5432 || rep.Counts.Exposed != 3 {
		t.Errorf("report: %+v", rep)
	}
}

// --check is for a deploy script: the status alone says whether to stop.
func TestCheck(t *testing.T) {
	if _, _, code := seaward(t, "", "scan", "--check", "-f", shop); code != exitExposed {
		t.Errorf("an exposed port: status %d, want %d", code, exitExposed)
	}
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	clean := write("clean.snapshot", "# seaward snapshot 1\n### meta\nhost box\nroot yes\n### iptables-save\n*filter\n"+
		":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"+v4Machine)
	out, _, code := seaward(t, "", "scan", "--check", "-f", clean)
	if code != exitOK || !strings.Contains(out, "1 port can be reached from outside.") {
		t.Errorf("a clean machine: status %d\n%s", code, out)
	}
	// Collected without root: the rules were out of reach, and a script must not read that as "fine".
	unread := write("unread.snapshot", "# seaward snapshot 1\n### meta\nhost box\nroot no\n"+v4Machine)
	out, _, code = seaward(t, "", "scan", "--check", "-f", unread)
	if code != exitIncomplete || !strings.Contains(out, "could not be read, so nothing is decided") {
		t.Errorf("unread rules: status %d\n%s", code, out)
	}
	if _, _, code = seaward(t, "", "scan", "-f", unread); code != exitOK {
		t.Errorf("without --check the status is %d", code)
	}

	// A scan that stopped at a ceiling did not ask everything, and a script must not read
	// "nothing exposed was found" as "nothing is exposed". Here 1,500 rules each let one sender
	// in: more groups of senders than are asked about from one place.
	var rules strings.Builder
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&rules, "-A INPUT -s 10.%d.%d.1/32 -p tcp -m tcp --dport 8080 -j ACCEPT\n", i>>8, i&255)
	}
	const head = "# seaward snapshot 1\n### meta\nhost box\nroot yes\n### iptables-save\n"
	crowded := write("crowded.snapshot", head+"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"+rules.String()+
		"-A INPUT -s 10.19.0.1/32 -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"+v4Machine)
	out, _, code = seaward(t, "", "scan", "--check", "-f", crowded)
	if code != exitIncomplete || !strings.Contains(out, "Nothing was found reachable from outside, but not every sender was asked.") ||
		!strings.Contains(out, "\nnot asked  ") || strings.Contains(out, "Nothing can be reached") {
		t.Errorf("past the ceiling of senders: status %d\n%s", code, out)
	}
	// The report says so to a program as well.
	type partial struct {
		Headline string   `json:"headline"`
		Partial  []string `json:"partial"`
		Counts   struct {
			Exposed   int `json:"exposed"`
			Undecided int `json:"undecided"`
		} `json:"counts"`
	}
	rep, _ := answer[partial](t, "scan", "--json", "-f", crowded)
	if !strings.HasSuffix(rep.Headline, "but not every sender was asked.") || len(rep.Partial) != 1 || !strings.Contains(rep.Partial[0], "senders beyond those were not asked") || rep.Counts.Undecided == 0 {
		t.Errorf("past the ceiling of senders, as JSON: partial %q, counts %+v", rep.Partial, rep.Counts)
	}
	// The ceiling of ports: 4,200 ports are each sent to another machine, 4,096 are asked about,
	// and none of those is exposed or undecided. The status is still not 0.
	var nat strings.Builder
	for i := 0; i < 4200; i += 15 {
		var list []string
		for j := i; j < i+15; j++ {
			list = append(list, fmt.Sprint(10000+3*j))
		}
		fmt.Fprintf(&nat, "-A PREROUTING -p tcp -m multiport --dports %s -j DNAT --to-destination 192.0.2.50\n", strings.Join(list, ","))
	}
	ports := write("ports.snapshot", head+"*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n"+nat.String()+
		"COMMIT\n*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"+v4Machine)
	out, _, code = seaward(t, "", "scan", "--check", "-f", ports)
	if code != exitIncomplete || !strings.Contains(out, "but not every port was asked.") {
		t.Errorf("past the ceiling of ports: status %d\n%s", code, firstLines(out, 8))
	}
	rep, _ = answer[partial](t, "scan", "--json", "-f", ports)
	if len(rep.Partial) != 1 || !strings.Contains(rep.Partial[0], "asked about the first 4096 and stopped") || rep.Counts.Undecided != 0 || rep.Counts.Exposed != 0 {
		t.Errorf("past the ceiling of ports, as JSON: partial %q, counts %+v", rep.Partial, rep.Counts)
	}

	// "why" for one port says no more than the scan knows either. Past the ceiling of senders
	// its answer carries the same sentence.
	type one struct {
		Ports []struct {
			Port    int    `json:"port"`
			Finding string `json:"finding"`
			Reach   string `json:"reach"`
		} `json:"ports"`
		Partial []string `json:"partial"`
	}
	w, _ := answer[one](t, "why", "22", "--json", "-f", crowded)
	if len(w.Ports) != 1 || w.Ports[0].Finding != "undecided" || w.Ports[0].Reach != "nobody that was asked" ||
		len(w.Partial) != 1 || !strings.Contains(w.Partial[0], "senders beyond those were not asked") {
		t.Errorf("why 22 past the ceiling of senders: %+v", w)
	}
	out, _, _ = seaward(t, "", "why", "22", "-f", crowded)
	if !strings.Contains(out, "No sender that was asked gets through, and not every sender was asked.") || strings.Contains(out, "Stopped by the firewall") {
		t.Errorf("why 22 past the ceiling of senders:\n%s", out)
	}
	// A port the scan did not come to before its ceiling of ports is asked about by itself. The
	// ceiling has no part in that answer, and "no rule sends it somewhere else" would be false.
	last := fmt.Sprint(10000 + 3*4199)
	w, _ = answer[one](t, "why", last, "--json", "-f", ports)
	if len(w.Ports) != 1 || fmt.Sprint(w.Ports[0].Port) != last || len(w.Partial) != 0 {
		t.Errorf("why %s past the ceiling of ports: %+v", last, w)
	}
	out, _, _ = seaward(t, "", "why", last, "-f", ports)
	if strings.Contains(out, "no rule sends it somewhere else") || !strings.Contains(out, "destination becomes 192.0.2.50:"+last) {
		t.Errorf("why %s past the ceiling of ports:\n%s", last, firstLines(out, 12))
	}
}

// firstLines is the head of a long output, for a failure message.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func TestWhy(t *testing.T) {
	out, _, code := seaward(t, "", "why", "5432", "-f", shop)
	if code != exitOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{"tcp 5432  postgres in container db", "gets through", "destination becomes 172.18.0.2:5432", "handed to container db"} {
		if !strings.Contains(out, want) {
			t.Errorf("why lacks %q:\n%s", want, out)
		}
	}
	// A port with both protocols: one or both. Both is the one, a blank line, then the other.
	both, _, _ := seaward(t, "", "why", "53", "-f", shop)
	tcp, _, _ := seaward(t, "", "why", "53/tcp", "-f", shop)
	udp, _, _ := seaward(t, "", "why", "53/udp", "-f", shop)
	if !strings.HasPrefix(tcp, "tcp 53  systemd-resolve\n") || !strings.HasPrefix(udp, "udp 53  systemd-resolve\n") || both != tcp+"\n"+udp {
		t.Errorf("both:\n%s\ntcp:\n%s\nudp:\n%s", both, tcp, udp)
	}
	// From one sender.
	in, _, _ := seaward(t, "", "why", "9100", "--from", "198.51.100.20", "-f", shop)
	away, _, _ := seaward(t, "", "why", "9100", "--from=192.0.2.200", "-f", shop)
	if !strings.Contains(in, "gets through") || !strings.Contains(away, "dropped") {
		t.Errorf("from inside the allowed network:\n%s\nfrom elsewhere:\n%s", in, away)
	}
	// A port nobody uses.
	none, _, code := seaward(t, "", "why", "7000", "-f", shop)
	if code != exitOK || !strings.Contains(none, "Nothing listens on port 7000 and no rule sends it somewhere else") || !strings.Contains(none, "seaward why 7000 --from 198.51.100.7 -f "+shop) {
		t.Errorf("status %d:\n%s", code, none)
	}
	// The command it suggests keeps the protocol that was asked for.
	none, _, _ = seaward(t, "", "why", "7000/udp", "-f", shop)
	if !strings.Contains(none, "Nothing listens on udp port 7000") || !strings.Contains(none, "seaward why 7000/udp --from 198.51.100.7 -f "+shop) {
		t.Errorf("with a protocol:\n%s", none)
	}
	// A scan has rows for tcp and udp. Of another protocol it says that, and not that no rule
	// sends the port anywhere: it has not looked.
	none, _, code = seaward(t, "", "why", "7000/sctp", "-f", shop)
	if code != exitOK || !strings.HasPrefix(none, "A scan asks about tcp and udp ports only, so it followed no packet to sctp port 7000.\n") ||
		strings.Contains(none, "no rule sends") || !strings.Contains(none, "seaward why 7000/sctp --from 198.51.100.7 -f "+shop) {
		t.Errorf("another protocol: status %d\n%s", code, none)
	}
}

// A scan asks about a long range of ports in part, so most of its ports have no row. "why" asks
// about such a port by itself: fifteen hundred ports are sent to sshd here, and 8500 is one of
// them although the report lists only the two ends.
func TestWhyInsideALongRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "range.snapshot")
	text := "# seaward snapshot 1\n### meta\nhost box\nroot yes\n### iptables-save\n" +
		"*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n" +
		"-A PREROUTING -p tcp -m tcp --dport 8000:9500 -j REDIRECT --to-ports 22\nCOMMIT\n" +
		"*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n" + v4Machine
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, _ := seaward(t, "", "scan", "-f", path)
	if !strings.Contains(out, "At least 3 ports can be reached from outside.") || strings.Contains(out, "8500") {
		t.Fatalf("the scan:\n%s", out)
	}
	out, _, code := seaward(t, "", "why", "8500", "-f", path)
	for _, want := range []string{"tcp 8500  sshd", "Reachable from the internet.", "gets through", "destination becomes 203.0.113.10:22"} {
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("why 8500 lacks %q (status %d):\n%s", want, code, out)
		}
	}
	type ports struct {
		Ports []struct {
			Proto   string `json:"proto"`
			Port    int    `json:"port"`
			Finding string `json:"finding"`
		} `json:"ports"`
	}
	got, _ := answer[ports](t, "why", "8500", "--json", "-f", path)
	if len(got.Ports) != 1 || got.Ports[0].Proto != "tcp" || got.Ports[0].Port != 8500 || got.Ports[0].Finding != "open" {
		t.Errorf("why 8500 --json: %+v", got)
	}
	// The other protocol, and a port outside the range, are sent nowhere.
	for _, arg := range []string{"8500/udp", "9501", "7999"} {
		out, _, _ = seaward(t, "", "why", arg, "-f", path)
		if !strings.Contains(out, "no rule sends it somewhere else") {
			t.Errorf("why %s:\n%s", arg, out)
		}
		if got, _ := answer[ports](t, "why", arg, "--json", "-f", path); len(got.Ports) != 0 {
			t.Errorf("why %s --json: %+v", arg, got)
		}
	}
}

// answer runs the command and decodes the JSON it printed into a new value, so that nothing an
// earlier answer held can stand in for a field this one lacks.
func answer[T any](t *testing.T, args ...string) (v T, out string) {
	t.Helper()
	out, errOut, code := seaward(t, "", args...)
	if code != exitOK || errOut != "" {
		t.Fatalf("%v: status %d, stderr %q", args, code, errOut)
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return v, out
}

// why --json gives what the text gives, for a program to read: the matching ports of the report,
// or the packets of one named sender.
func TestWhyJSON(t *testing.T) {
	type step struct{ Kind, Hook, Family, Table, Chain, Rule, Effect string }
	type cell struct {
		Src, Dst, Class string
		Steps           []step
	}
	type port struct {
		Proto   string
		Port    int
		Finding string
		Cells   []cell
	}
	type ports struct {
		Host  string
		Ports []port
	}
	type trace struct {
		Host, Proto string
		Port        int
		From        string
		Cells       []cell
	}
	// brief is each cell without its steps, and found is each port without its cells: the parts
	// whose whole value is known here.
	brief := func(cs []cell) []cell {
		out := []cell{}
		for _, c := range cs {
			out = append(out, cell{Src: c.Src, Dst: c.Dst, Class: c.Class})
		}
		return out
	}
	found := func(ps []port) []port {
		out := []port{}
		for _, p := range ps {
			out = append(out, port{Proto: p.Proto, Port: p.Port, Finding: p.Finding})
		}
		return out
	}

	got, _ := answer[ports](t, "why", "5432", "--json", "-f", shop)
	if got.Host != "shop-1" || !reflect.DeepEqual(found(got.Ports), []port{{Proto: "tcp", Port: 5432, Finding: "exposed"}}) {
		t.Fatalf("why 5432: %+v", got)
	}
	// Every packet the scan sent at it: anyone and a neighbour, over IPv4 and over IPv6.
	cells := got.Ports[0].Cells
	wantCells := []cell{
		{Src: "192.0.2.7", Dst: "203.0.113.10", Class: "open"},
		{Src: "2001:db8:99::7", Dst: "2001:db8:1::10", Class: "filtered"},
		{Src: "203.0.113.11", Dst: "203.0.113.10", Class: "open"},
		{Src: "2001:db8:1::11", Dst: "2001:db8:1::10", Class: "filtered"},
	}
	if !reflect.DeepEqual(brief(cells), wantCells) {
		t.Fatalf("why 5432, the packets:\n got %+v\nwant %+v", brief(cells), wantCells)
	}
	// The step that turns the first packet towards the container, whole.
	wantStep := step{Kind: "rule", Hook: "prerouting", Family: "ip", Table: "nat", Chain: "DOCKER",
		Rule:   "-A DOCKER ! -i br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.18.0.2:5432",
		Effect: "destination becomes 172.18.0.2:5432"}
	if steps := cells[0].Steps; len(steps) != 8 || steps[1] != wantStep {
		t.Errorf("why 5432, the first packet's steps:\n got %+v\nwant 8 of them, the second %+v", steps, wantStep)
	}
	// The port is the one scan --json has, unchanged.
	type raw struct{ Ports []json.RawMessage }
	whole, _ := answer[raw](t, "scan", "--json", "-f", shop)
	one, _ := answer[raw](t, "why", "5432/tcp", "--json", "-f", shop)
	if len(whole.Ports) != 13 || len(one.Ports) != 1 {
		t.Fatalf("scan --json has %d ports and why 5432/tcp --json has %d; want 13 and 1", len(whole.Ports), len(one.Ports))
	}
	var a, b bytes.Buffer
	if json.Compact(&a, whole.Ports[0]) != nil || json.Compact(&b, one.Ports[0]) != nil || a.String() != b.String() {
		t.Errorf("why --json and scan --json disagree about tcp 5432:\n%s\n%s", a.String(), b.String())
	}
	// Both protocols, or the one asked for.
	got, _ = answer[ports](t, "why", "53", "--json", "-f", shop)
	if want := []port{{Proto: "tcp", Port: 53, Finding: "local"}, {Proto: "udp", Port: 53, Finding: "local"}}; got.Host != "shop-1" || !reflect.DeepEqual(found(got.Ports), want) {
		t.Errorf("why 53: host %q, ports %+v; want %+v", got.Host, found(got.Ports), want)
	}
	got, _ = answer[ports](t, "why", "53/udp", "--json", "-f", shop)
	if want := []port{{Proto: "udp", Port: 53, Finding: "local"}}; got.Host != "shop-1" || !reflect.DeepEqual(found(got.Ports), want) {
		t.Errorf("why 53/udp: host %q, ports %+v; want %+v", got.Host, found(got.Ports), want)
	}
	// A port nobody uses is an empty list, not a sentence and not null. The whole answer is known.
	if _, out := answer[ports](t, "why", "7000", "--json", "-f", shop); out != "{\n  \"host\": \"shop-1\",\n  \"ports\": []\n}\n" {
		t.Errorf("why 7000:\n%s", out)
	}
	// One sender.
	sent, _ := answer[trace](t, "why", "9100", "--from", "198.51.100.20", "--json", "-f", shop)
	want := trace{Host: "shop-1", Proto: "tcp", Port: 9100, From: "198.51.100.20",
		Cells: []cell{{Src: "198.51.100.20", Dst: "203.0.113.10", Class: "open"}}}
	if sent.Cells = brief(sent.Cells); !reflect.DeepEqual(sent, want) {
		t.Errorf("from the allowed network:\n got %+v\nwant %+v", sent, want)
	}
	sent, _ = answer[trace](t, "why", "9100/tcp", "--from=192.0.2.200", "--json", "-f", shop)
	want = trace{Host: "shop-1", Proto: "tcp", Port: 9100, From: "192.0.2.200",
		Cells: []cell{{Src: "192.0.2.200", Dst: "203.0.113.10", Class: "filtered"}}}
	if sent.Cells = brief(sent.Cells); !reflect.DeepEqual(sent, want) {
		t.Errorf("from elsewhere:\n got %+v\nwant %+v", sent, want)
	}
	// A sender with no address of this machine to arrive at: the list is empty, and still a list.
	// The machine has IPv4 addresses only, and the sender an IPv6 one.
	v4only := filepath.Join(t.TempDir(), "v4only.snapshot")
	if err := os.WriteFile(v4only, []byte("# seaward snapshot 1\n### meta\nhost box\nroot yes\n"+v4Machine), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, out := answer[trace](t, "why", "22/udp", "--from", "2001:db8:77::7", "--json", "-f", v4only); out !=
		"{\n  \"host\": \"box\",\n  \"proto\": \"udp\",\n  \"port\": 22,\n  \"from\": \"2001:db8:77::7\",\n  \"cells\": []\n}\n" {
		t.Errorf("no way in:\n%s", out)
	}
	// The same answer in words.
	if out, _, code := seaward(t, "", "why", "22", "--from", "2001:db8:77::7", "-f", v4only); code != exitOK ||
		out != "A packet from 2001:db8:77::7 has no outside address of this machine to arrive at.\n" {
		t.Errorf("no way in, in words: status %d\n%s", code, out)
	}
}

// A suggested command names the snapshot so that a shell reads the name as one word.
func TestFileArg(t *testing.T) {
	for file, want := range map[string]string{
		"":                        "",
		"-":                       "",
		"server.snapshot":         " -f server.snapshot",
		"../snaps/web-1.snapshot": " -f ../snaps/web-1.snapshot",
		"my server.snapshot":      " -f 'my server.snapshot'",
		"it's.snapshot":           ` -f 'it'\''s.snapshot'`,
		"$(id).snapshot":          " -f '$(id).snapshot'",
		"-odd.snapshot":           " -f '-odd.snapshot'",
	} {
		if got := fileArg(options{file: file}); got != want {
			t.Errorf("%q: got %q, want %q", file, got, want)
		}
	}
}

func TestMistakes(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want string
	}{
		{[]string{"why", "abc", "-f", shop}, exitUsage, `"abc" is not a port`},
		{[]string{"why", "tcp", "-f", shop}, exitUsage, "names no port"},
		{[]string{"why", "-f", shop}, exitUsage, "why needs a port"},
		// A port written wrongly is refused, never read as something near it.
		{[]string{"why", "22/tcp/udp", "-f", shop}, exitUsage, `"22/tcp/udp" names more than one protocol`},
		{[]string{"why", "22/tcp/udp", "--json", "-f", shop}, exitUsage, `"22/tcp/udp" names more than one protocol`},
		{[]string{"why", "22", "80", "-f", shop}, exitUsage, `"22 80" names more than one port`},
		{[]string{"why", "65536", "-f", shop}, exitUsage, `"65536" is not a port: ports run from 1 to 65535.`},
		{[]string{"why", "22/icmp", "-f", shop}, exitUsage, `"icmp" is not a protocol with ports`},
		{[]string{"why", "udp", "53", "-f", shop}, exitUsage, `"udp 53" is not how a port is written. Write it as 53/udp.`},
		{[]string{"why", "tcp/5432", "-f", shop}, exitUsage, `"tcp/5432" is not how a port is written. Write it as 5432/tcp.`},
		// The port is looked at before the snapshot is: a mistake in it is not a missing file.
		{[]string{"why", "22/", "-f", "no-such-file.snapshot"}, exitUsage, `"22/" is not a port`},
		{[]string{"why", "22", "--from", "everywhere", "-f", shop}, exitUsage, "--from wants one address"},
		{[]string{"scan", "extra", "-f", shop}, exitUsage, "scan takes no argument"},
		{[]string{"scan", "--frob"}, exitUsage, "unknown option --frob"},
		{[]string{"why", "22", "--check", "-f", shop}, exitUsage, "--check goes with scan, not with why"},
		{[]string{"scan", "--from", "198.51.100.7", "-f", shop}, exitUsage, "--from goes with why, not with scan"},
		{[]string{"scan", "-o", "out.snapshot", "-f", shop}, exitUsage, "--output goes with snapshot, not with scan"},
		{[]string{"snapshot", "--script", "--json"}, exitUsage, "--json goes with scan and why, not with snapshot"},
		{[]string{"snapshot", "--script", "-f", shop}, exitUsage, "--file goes with scan and why, not with snapshot"},
		{[]string{"why", "22", "--script", "-f", shop}, exitUsage, "--script goes with snapshot, not with why"},
		{[]string{"scan", "-f"}, exitUsage, "-f"},
		{[]string{"sail"}, exitUsage, `unknown command "sail"`},
		{[]string{"scan", "-f", "no-such-file.snapshot"}, exitError, "no-such-file.snapshot"},
		{[]string{"scan", "-f", "main.go"}, exitError, "this is not a Seaward snapshot"},
	}
	for _, c := range cases {
		out, errOut, code := seaward(t, "", c.args...)
		if code != c.code || !strings.Contains(errOut, c.want) || out != "" {
			t.Errorf("%v: status %d, want %d; stderr %q should say %q; stdout %q", c.args, code, c.code, errOut, c.want, out)
		}
		if !strings.HasPrefix(errOut, "seaward: ") {
			t.Errorf("%v: stderr does not say who is talking: %q", c.args, errOut)
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"scan", "--help"}} {
		out, _, code := seaward(t, "", args...)
		if code != exitOK || out != usage {
			t.Errorf("%v: status %d, output %q", args, code, out)
		}
	}
	for _, ln := range strings.Split(usage, "\n") {
		if len(ln) > 80 {
			t.Errorf("a help line of %d columns: %q", len(ln), ln)
		}
	}
	for _, args := range [][]string{{"version"}, {"--version"}, {"-V"}} {
		if out, _, code := seaward(t, "", args...); code != exitOK || !strings.HasPrefix(out, "seaward ") {
			t.Errorf("%v: status %d, output %q", args, code, out)
		}
	}
}

// The collector script is what a person runs on a machine they will not install anything on.
func TestSnapshotScript(t *testing.T) {
	out, _, code := seaward(t, "", "snapshot", "--script")
	if code != exitOK || !strings.HasPrefix(out, "#!/bin/sh\n") || !strings.Contains(out, "# seaward snapshot 1") {
		t.Fatalf("status %d, script:\n%.300s", code, out)
	}
	// It only reads: nothing in it may change a rule or a setting.
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") {
			continue
		}
		for _, bad := range []string{"iptables -A", "iptables -I", "iptables -D", "iptables -F", "iptables -P", "nft add", "nft delete", "nft flush",
			"ufw allow", "ufw deny", "ufw enable", "ufw disable", "ufw delete", "sysctl -w", "docker run", "docker exec", "docker rm", "rm -", "ipset add", "ipset del", "> /etc"} {
			if strings.Contains(ln, bad) {
				t.Errorf("the collector script holds %q: %s", bad, ln)
			}
		}
	}
}

// A port is written one way, PORT or PORT/PROTO. Everything else is a usage error that says what
// is wrong, and nothing is ever read as the nearest thing that would have been right.
func TestPortArg(t *testing.T) {
	good := []struct {
		words []string
		proto string
		port  uint16
	}{
		{[]string{"5432"}, "", 5432},
		{[]string{"1"}, "", 1},
		{[]string{"65535"}, "", 65535},
		{[]string{"0080"}, "", 80},
		{[]string{"5432/tcp"}, "tcp", 5432},
		{[]string{"53/udp"}, "udp", 53},
		{[]string{"53/UDP"}, "udp", 53},
		{[]string{"9/sctp"}, "sctp", 9},
		{[]string{"9/dccp"}, "dccp", 9},
		{[]string{"9/udplite"}, "udplite", 9},
		{[]string{"65535/udp"}, "udp", 65535},
	}
	for _, c := range good {
		proto, port, err := portArg(c.words...)
		if err != nil || proto != c.proto || port != c.port {
			t.Errorf("%q: got %q %d, %v; want %q %d", c.words, proto, port, err, c.proto, c.port)
		}
	}

	const how = " Write it as 5432, or 53/udp."
	const span = " is not a port: ports run from 1 to 65535."
	const protos = " is not a protocol with ports. Write tcp, udp, sctp, dccp or udplite."
	bad := []struct {
		words []string
		want  string
	}{
		// Not a port at all.
		{[]string{""}, `"" is not a port.` + how},
		{[]string{"abc"}, `"abc" is not a port.` + how},
		{[]string{"http"}, `"http" is not a port.` + how},
		{[]string{"-1"}, `"-1" is not a port.` + how},
		{[]string{"+22"}, `"+22" is not a port.` + how},
		{[]string{"22.0"}, `"22.0" is not a port.` + how},
		{[]string{"0x16"}, `"0x16" is not a port.` + how},
		{[]string{" 22"}, `" 22" is not a port.` + how},
		{[]string{"2 2"}, `"2 2" is not a port.` + how},
		{[]string{"２２"}, `"２２" is not a port.` + how}, // digits, but not the ones a port is written in
		{[]string{"22,80"}, `"22,80" is not a port.` + how},
		{[]string{"22-80"}, `"22-80" is not a port.` + how},
		// A number no port has.
		{[]string{"0"}, `"0"` + span},
		{[]string{"65536"}, `"65536"` + span},
		{[]string{"99999999999999999999"}, `"99999999999999999999"` + span},
		{[]string{"0/tcp"}, `"0"` + span},
		{[]string{"70000/udp"}, `"70000"` + span},
		// A protocol and no port.
		{[]string{"tcp"}, `"tcp" names no port.` + how},
		{[]string{"tcp/udp"}, `"tcp/udp" names no port.` + how},
		// A protocol this is not asked of.
		{[]string{"22/icmp"}, `"icmp"` + protos},
		{[]string{"22/http"}, `"http"` + protos},
		{[]string{"22/tc"}, `"tc"` + protos},
		{[]string{"22/tcpp"}, `"tcpp"` + protos},
		{[]string{"9/udplİte"}, `"udplİte"` + protos}, // a dotted capital I is not an i
		{[]string{"9/UDPLİTE"}, `"UDPLİTE"` + protos},
		{[]string{"9/ＴＣＰ"}, `"ＴＣＰ"` + protos},
		// More than was asked for. The first of these used to be read as udp.
		{[]string{"22/tcp/udp"}, `"22/tcp/udp" names more than one protocol. Ask about one at a time.`},
		{[]string{"22/6"}, `"22/6" names more than one port. Ask about one at a time.`},
		{[]string{"22/tcp/tcp"}, `"22/tcp/tcp" names more than one protocol. Ask about one at a time.`},
		{[]string{"22/tcp", "udp"}, `"22/tcp udp" names more than one protocol. Ask about one at a time.`},
		{[]string{"22/80"}, `"22/80" names more than one port. Ask about one at a time.`},
		{[]string{"22", "80"}, `"22 80" names more than one port. Ask about one at a time.`},
		{[]string{"22/80/tcp"}, `"22/80/tcp" names more than one port. Ask about one at a time.`},
		{[]string{"22/tcp/80"}, `"22/tcp/80" names more than one port. Ask about one at a time.`},
		{[]string{"22", "tcp", "extra"}, `"22 tcp extra" is not a port.` + how},
		// Pieces missing around the slash.
		{[]string{"22/"}, `"22/" is not a port.` + how},
		{[]string{"/22"}, `"/22" is not a port.` + how},
		{[]string{"/"}, `"/" is not a port.` + how},
		{[]string{"/tcp"}, `"/tcp" is not a port.` + how},
		{[]string{"22//tcp"}, `"22//tcp" is not a port.` + how},
		{[]string{"22/tcp/"}, `"22/tcp/" is not a port.` + how},
		{[]string{"22/ tcp"}, `" tcp"` + protos},
		// The right pieces in the wrong shape: the message gives the right one.
		{[]string{"tcp/5432"}, `"tcp/5432" is not how a port is written. Write it as 5432/tcp.`},
		{[]string{"UDP/53"}, `"UDP/53" is not how a port is written. Write it as 53/udp.`},
		{[]string{"udp", "53"}, `"udp 53" is not how a port is written. Write it as 53/udp.`},
		{[]string{"53", "udp"}, `"53 udp" is not how a port is written. Write it as 53/udp.`},
		{[]string{"22", ""}, `"22 " is not a port.` + how},
	}
	for _, c := range bad {
		proto, port, err := portArg(c.words...)
		var usage usageError
		if !errors.As(err, &usage) || err.Error() != c.want || proto != "" || port != 0 {
			t.Errorf("%q: got %q %d, %v\nwant the usage error %s", c.words, proto, port, err, c.want)
		}
	}
}

// A snapshot is written for its owner alone, whatever was under that name before.
func TestWritePrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.snapshot")
	if err := writePrivate(path, []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	// An older file that anyone could read: the new one must not inherit that.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(path, []byte("two\n")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two\n" {
		t.Fatalf("read back %q, %v", got, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 600", st.Mode().Perm())
	}

	// A link planted under the name: refused, and what it points at is untouched.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.snapshot")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(link, []byte("three\n")); err == nil {
		t.Error("wrote through a symlink")
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep\n" {
		t.Errorf("the link's target now holds %q", got)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link itself was replaced: %v, %v", st, err)
	}
	// Neither a directory nor a missing directory is written to.
	if err := writePrivate(dir, []byte("x")); err == nil {
		t.Error("wrote over a directory")
	}
	if err := writePrivate(filepath.Join(dir, "missing", "x.snapshot"), []byte("x")); err == nil {
		t.Error("wrote into a directory that is not there")
	}
	// Nothing is left behind: the snapshot, the victim and the link.
	if ents, _ := os.ReadDir(dir); len(ents) != 3 {
		t.Errorf("%d entries left in the directory, want 3", len(ents))
	}
}

// Under sudo the snapshot belongs to whoever ran sudo.
func TestSudoUser(t *testing.T) {
	for _, c := range []struct {
		euid     int
		uid, gid string
		ok       bool
	}{
		{0, "1000", "1000", true},
		{1000, "1000", "1000", false}, // not root: nothing to hand over
		{0, "", "", false},            // root without sudo
		{0, "0", "0", false},          // sudo from root
		{0, "1000; id", "1000", false},
		{0, "-5", "1000", false},
	} {
		if _, _, ok := sudoUser(c.euid, c.uid, c.gid); ok != c.ok {
			t.Errorf("sudoUser(%d, %q, %q) = %v, want %v", c.euid, c.uid, c.gid, ok, c.ok)
		}
	}
}
