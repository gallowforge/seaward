package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const shop = "../../samples/shop-1.snapshot"

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
	const machine = `### ss
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=830,fd=3))
### ip-addr
[{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","UP","LOWER_UP"],"link_type":"ether","addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global"}]}]
### ip-route-4
[{"dst":"default","gateway":"203.0.113.1","dev":"eth0"},{"dst":"203.0.113.0/24","dev":"eth0","scope":"link"}]
`
	clean := write("clean.snapshot", "# seaward snapshot 1\n### meta\nhost box\nroot yes\n### iptables-save\n*filter\n"+
		":INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"+machine)
	out, _, code := seaward(t, "", "scan", "--check", "-f", clean)
	if code != exitOK || !strings.Contains(out, "1 port can be reached from outside.") {
		t.Errorf("a clean machine: status %d\n%s", code, out)
	}
	// Collected without root: the rules were out of reach, and a script must not read that as "fine".
	unread := write("unread.snapshot", "# seaward snapshot 1\n### meta\nhost box\nroot no\n"+machine)
	out, _, code = seaward(t, "", "scan", "--check", "-f", unread)
	if code != exitIncomplete || !strings.Contains(out, "could not be read, so nothing is decided") {
		t.Errorf("unread rules: status %d\n%s", code, out)
	}
	if _, _, code = seaward(t, "", "scan", "-f", unread); code != exitOK {
		t.Errorf("without --check the status is %d", code)
	}
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
	// A port with both protocols: one or both.
	both, _, _ := seaward(t, "", "why", "53", "-f", shop)
	udp, _, _ := seaward(t, "", "why", "53/udp", "-f", shop)
	spaced, _, _ := seaward(t, "", "why", "udp", "53", "-f", shop)
	if !strings.Contains(both, "tcp 53") || !strings.Contains(both, "udp 53") || strings.Contains(udp, "tcp 53") || udp != spaced {
		t.Errorf("both:\n%s\nudp:\n%s\nspaced:\n%s", both, udp, spaced)
	}
	// From one sender.
	in, _, _ := seaward(t, "", "why", "9100", "--from", "198.51.100.20", "-f", shop)
	away, _, _ := seaward(t, "", "why", "9100", "--from=192.0.2.200", "-f", shop)
	if !strings.Contains(in, "gets through") || !strings.Contains(away, "dropped") {
		t.Errorf("from inside the allowed network:\n%s\nfrom elsewhere:\n%s", in, away)
	}
	// A port nobody uses.
	none, _, code := seaward(t, "", "why", "7000", "-f", shop)
	if code != exitOK || !strings.Contains(none, "Nothing listens on port 7000") || !strings.Contains(none, "seaward why 7000 --from 198.51.100.7 -f "+shop) {
		t.Errorf("status %d:\n%s", code, none)
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
		{[]string{"why", "22", "--from", "everywhere", "-f", shop}, exitUsage, "--from wants one address"},
		{[]string{"scan", "extra", "-f", shop}, exitUsage, "scan takes no argument"},
		{[]string{"scan", "--frob"}, exitUsage, "unknown option --frob"},
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

func TestPortArg(t *testing.T) {
	for in, want := range map[string]string{
		"5432": " 5432", "5432/tcp": "tcp 5432", "tcp/5432": "tcp 5432", "UDP/53": "udp 53", "53/udp": "udp 53", "sctp/9": "sctp 9",
	} {
		proto, port, err := portArg(in)
		if got := proto + " " + strconv.Itoa(int(port)); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "65536", "http", "22/icmp", "-1"} {
		if _, _, err := portArg(in); err == nil {
			t.Errorf("%q was taken for a port", in)
		}
	}
}

// A snapshot is written for its owner alone, and under sudo the owner is whoever ran sudo.
func TestWriteOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.snapshot")
	if err := writeOwned(path, []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeOwned(path, []byte("two\n")); err != nil {
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
