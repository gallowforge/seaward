package snapshot

import (
	"context"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// readOnly says, for each program, which argument lists are pure listings. It is written
// independently of the command table on purpose: the test is that the two agree.
var readOnly = map[string]func(args []string) bool{
	"iptables":              func(a []string) bool { return eq(a, "-V") },
	"iptables-save":         func(a []string) bool { return len(a) == 0 },
	"ip6tables-save":        func(a []string) bool { return len(a) == 0 },
	"iptables-legacy-save":  func(a []string) bool { return len(a) == 0 },
	"ip6tables-legacy-save": func(a []string) bool { return len(a) == 0 },
	"nft":                   func(a []string) bool { return eq(a, "-j", "list", "ruleset") },
	"ipset":                 func(a []string) bool { return eq(a, "save") },
	// ss -K kills sockets; only the listing flags are allowed.
	"ss": func(a []string) bool { return eq(a, "-Htulpn") },
	"ip": func(a []string) bool {
		return len(a) >= 4 && a[0] == "-j" && slices.Contains(a, "show") &&
			(eq(a, "-j", "-d", "addr", "show") || eq(a, "-j", "-4", "route", "show", "table", "main") || eq(a, "-j", "-6", "route", "show", "table", "main"))
	},
	// sysctl writes with -w, with key=value, or with -p/--system/--load.
	"sysctl": func(a []string) bool {
		for _, x := range a {
			if strings.Contains(x, "=") || x == "-w" || x == "-p" || x == "--write" || x == "--system" || x == "--load" {
				return false
			}
		}
		return true
	},
	"docker": func(a []string) bool {
		switch {
		case eq(a, "version", "--format", "{{.Server.Version}}"):
			return true
		case eq(a, "ps", "--no-trunc", "--format", "{{json .}}"):
			return true
		case len(a) >= 4 && a[0] == "inspect" && a[1] == "--format":
			// The template must name fields; a bare inspect would print environments.
			return a[2] == dockerInspectTemplate && !strings.Contains(a[2], ".Config") && !strings.Contains(a[2], "json .")
		}
		return false
	},
	"nsenter": func(a []string) bool {
		return len(a) == 5 && a[0] == "-t" && a[2] == "-n" && a[3] == "ss" && a[4] == "-Htulpn"
	},
	"ufw": func(a []string) bool { return eq(a, "status", "verbose") },
	"firewall-cmd": func(a []string) bool {
		if len(a) != 1 {
			return false
		}
		return a[0] == "--state" || a[0] == "--get-active-zones" || a[0] == "--list-all-zones" ||
			(strings.HasPrefix(a[0], "--info-service=") && !strings.Contains(a[0], " "))
	},
}

func eq(a []string, want ...string) bool { return slices.Equal(a, want) }

// filled returns the table entry with its placeholders given sample values.
func filled(c command) []string {
	var out []string
	for _, a := range c.argv {
		switch {
		case a == "<ids>":
			out = append(out, idWeb, idDB)
		case a == "<pid>":
			out = append(out, "1388")
		default:
			out = append(out, strings.ReplaceAll(a, "<service>", "ssh"))
		}
	}
	return out
}

func TestCommandsAreReadOnly(t *testing.T) {
	for _, c := range commands {
		argv := filled(c)
		ok, known := readOnly[argv[0]]
		if !known {
			t.Errorf("%s: program %q is not on the read-only list", c.section, argv[0])
			continue
		}
		if !ok(argv[1:]) {
			t.Errorf("%s: %q is not a read-only use of %s", c.section, argv, argv[0])
		}
	}
	// argvFor is the only way commands are built; it must give the same lists.
	seen := map[string]int{}
	for _, c := range commands {
		got := argvFor(c.section, seen[c.section], map[string][]string{"ids": {idWeb, idDB}, "pid": {"1388"}, "service": {"ssh"}})
		seen[c.section]++
		if !reflect.DeepEqual(got, filled(c)) {
			t.Errorf("argvFor(%s) = %q", c.section, got)
		}
	}
}

func TestReadOnlyListCatchesWrites(t *testing.T) {
	for _, argv := range [][]string{
		{"iptables", "-F"}, {"nft", "flush", "ruleset"}, {"ss", "-K", "dport", "22"}, {"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"sysctl", "net.ipv4.ip_forward=1"}, {"docker", "inspect", idWeb}, {"docker", "inspect", "--format", "{{json .}}", idWeb},
		{"docker", "rm", idWeb}, {"ufw", "disable"}, {"firewall-cmd", "--reload"}, {"firewall-cmd", "--add-port=22/tcp"},
		{"ip", "-j", "addr", "del", "192.0.2.10/24", "dev", "eth0"}, {"nsenter", "-t", "1", "-n", "sh"}, {"ipset", "flush"},
	} {
		if readOnly[argv[0]](argv[1:]) {
			t.Errorf("%q passed the read-only check", argv)
		}
	}
}

// fakeCmd is what one fake command prints.
type fakeCmd struct {
	out, stderr string
	code        int
}

const fakeHost = "web-1"

// fakeMachine is an invented machine as the collector would see it. Keys are full argument
// lists joined by spaces.
func fakeMachine() (programs []string, cmds map[string]fakeCmd) {
	programs = []string{"iptables", "iptables-save", "ip6tables-save", "iptables-legacy-save", "ip6tables-legacy-save",
		"nft", "ss", "ip", "sysctl", "docker", "nsenter", "ufw", "firewall-cmd"}
	ps := `{"ID":"` + idWeb + `","Image":"nginx:1.27","Names":"web","Networks":"app","Ports":"0.0.0.0:8080->80/tcp","State":"running"}` + "\n" +
		`{"ID":"` + idDB + `","Image":"postgres:16","Names":"postgres","Networks":"app","Ports":"127.0.0.1:5432->5432/tcp","State":"running"}` + "\n" +
		`{"ID":"` + idMon + `","Image":"grafana/grafana","Names":"grafana","Networks":"host","Ports":"","State":"running"}` + "\n"
	cmds = map[string]fakeCmd{
		"iptables -V":                    {out: "iptables v1.8.10 (nf_tables)\n"},
		"iptables-save":                  {out: "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n"},
		"ip6tables-save":                 {out: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"},
		"iptables-legacy-save":           {out: "# Warning: no tables\n"},
		"ip6tables-legacy-save":          {out: "*raw\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n"},
		"nft -j list ruleset":            {out: `{"nftables": [{"metainfo": {"json_schema_version": 1}}]}` + "\n"},
		"ss -Htulpn":                     {out: "tcp   LISTEN 0      128   0.0.0.0:22   0.0.0.0:*   users:((\"sshd\",pid=812,fd=3))\n### odd line\n"},
		"ip -j -d addr show":             {out: `[{"ifname":"lo","flags":["LOOPBACK","UP"],"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]}]` + "\n"},
		"ip -j -4 route show table main": {out: `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]` + "\n"},
		"ip -j -6 route show table main": {out: "[]\n"},
		// The IPv6 key is missing: sysctl complains and fails, but prints the other key.
		"sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding": {out: "net.ipv4.ip_forward = 1\n",
			stderr: "sysctl: cannot stat /proc/sys/net/ipv6/conf/all/forwarding: No such file or directory\n", code: 255},
		`sysctl -a -r net\.ipv4\.conf\..*\.route_localnet`: {out: "net.ipv4.conf.all.route_localnet = 0\nnet.ipv4.conf.lo.route_localnet = 0\n"},
		"docker version --format {{.Server.Version}}":      {out: "27.3.1\n"},
		"docker ps --no-trunc --format {{json .}}":         {out: ps},
		"docker inspect --format " + dockerInspectTemplate + " " + idWeb + " " + idDB + " " + idMon: {out: idWeb + " 1388 app app=172.18.0.2|\n" +
			idDB + " 1447 app app=172.18.0.3|\n" + idMon + " 1500 host\n"},
		"nsenter -t 1388 -n ss -Htulpn":   {out: "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n"},
		"nsenter -t 1447 -n ss -Htulpn":   {stderr: "nsenter: cannot open /proc/1447/ns/net: No such file or directory\n", code: 1},
		"ufw status verbose":              {stderr: "ERROR: You need to be root to run this script\n", code: 1},
		"firewall-cmd --state":            {out: "running\n"},
		"firewall-cmd --get-active-zones": {out: "public\n  interfaces: eth0\n"},
		"firewall-cmd --list-all-zones": {out: "block\n  target: %%REJECT%%\n  services: \n\npublic (active)\n  target: default\n" +
			"  interfaces: eth0\n  services: ssh web-extra\n  ports: 8080/tcp\n"},
		"firewall-cmd --info-service=ssh":       {out: "ssh\n  ports: 22/tcp\n  includes: \n"},
		"firewall-cmd --info-service=web-extra": {out: "web-extra\n  ports: \n  includes: https ssh\n"},
		"firewall-cmd --info-service=https":     {stderr: "Error: INVALID_SERVICE: https\n", code: 101},
	}
	return programs, cmds
}

func fakeRunner(t *testing.T, programs []string, cmds map[string]fakeCmd, calls *[][]string) runner {
	return func(_ context.Context, argv []string) runResult {
		*calls = append(*calls, argv)
		if !slices.Contains(programs, argv[0]) {
			return runResult{missing: true}
		}
		c, ok := cmds[strings.Join(argv, " ")]
		if !ok {
			t.Errorf("unexpected command %q", argv)
			return runResult{errLine: "unexpected", code: 1}
		}
		r := runResult{stdout: strings.TrimRight(c.out, "\n"), code: c.code}
		if c.code != 0 {
			r.errLine = firstLine(c.stderr)
		}
		return r
	}
}

func TestCollectWith(t *testing.T) {
	programs, cmds := fakeMachine()
	var calls [][]string
	b := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })

	var names []string
	for _, s := range b.Sections {
		n := s.Name
		if s.Arg != "" {
			n += " " + s.Arg
		}
		names = append(names, n)
	}
	want := []string{"meta", "iptables-version", "iptables-save", "ip6tables-save", "ip6tables-legacy-save", "nft-json",
		"ss", "ip-addr", "ip-route-4", "ip-route-6", "sysctl", "docker-version", "docker-ps", "docker-net",
		"docker-ss " + idWeb, "firewalld-state", "firewalld-active", "firewalld-zones",
		"firewalld-service ssh", "firewalld-service web-extra", "errors"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("sections:\n got %q\nwant %q", names, want)
	}
	if m := b.Meta(); m["host"] != fakeHost || m["collector"] != "cli" || m["root"] != "yes" || m["seaward"] != Version {
		t.Errorf("meta: %v", m)
	}
	if s, _ := b.Get("sysctl"); s != "net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.route_localnet = 0\nnet.ipv4.conf.lo.route_localnet = 0" {
		t.Errorf("sysctl: %q", s)
	}
	errs := b.Errors()
	wantErrs := map[string]string{
		"docker-ss " + idDB:       "nsenter: cannot open /proc/1447/ns/net: No such file or directory",
		"ufw-status":              "ERROR: You need to be root to run this script",
		"firewalld-service https": "Error: INVALID_SERVICE: https",
	}
	if !reflect.DeepEqual(errs, wantErrs) {
		t.Errorf("errors:\n got %q\nwant %q", errs, wantErrs)
	}
	// The odd ss line that looks like a header survives the trip through text.
	again, _ := Parse(b.String())
	if !reflect.DeepEqual(again, b) {
		t.Error("collected bundle does not survive a round trip")
	}
	checkCalls(t, calls)
	for _, c := range calls {
		if c[0] == "nsenter" && strings.Contains(strings.Join(c, " "), "1500") {
			t.Error("nsenter ran for a host-network container")
		}
	}
}

func TestCollectWithoutRoot(t *testing.T) {
	programs, cmds := fakeMachine()
	for k := range cmds {
		if strings.HasPrefix(k, "iptables-save") || strings.HasPrefix(k, "ip6tables-save") || strings.HasPrefix(k, "nft ") {
			cmds[k] = fakeCmd{stderr: "iptables-save v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)\n", code: 4}
		}
	}
	var calls [][]string
	b := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, false, func(string) bool { return true })
	for _, s := range []string{"iptables-save", "ip6tables-save", "nft-json", "docker-ss"} {
		if b.Has(s) {
			t.Errorf("%s should be missing", s)
		}
	}
	for _, c := range calls {
		if c[0] == "nsenter" {
			t.Error("nsenter ran without root")
		}
	}
	errs := b.Errors()
	if !strings.Contains(errs["iptables-save"], "Permission denied") || errs["nft-json"] == "" {
		t.Errorf("errors: %q", errs)
	}
	if b.Meta()["root"] != "no" {
		t.Error("meta root")
	}
}

func TestCollectNothingInstalled(t *testing.T) {
	var calls [][]string
	b := collectWith(context.Background(), fakeRunner(t, nil, nil, &calls), fakeHost, false, func(string) bool { return false })
	if len(b.Sections) != 1 || b.Sections[0].Name != "meta" {
		t.Errorf("a machine with none of the tools gives only meta, got %+v", b.Sections)
	}
}

func TestCollectFirewalldStopped(t *testing.T) {
	programs, cmds := fakeMachine()
	cmds["firewall-cmd --state"] = fakeCmd{out: "not running\n", code: 252}
	var calls [][]string
	b := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	if s, _ := b.Get("firewalld-state"); s != "not running" {
		t.Errorf("state: %q", s)
	}
	if b.Has("firewalld-zones") {
		t.Error("zones asked of a stopped firewalld")
	}
	if _, bad := b.Errors()["firewalld-state"]; bad {
		t.Error("a stopped firewalld is not an error")
	}
}

func TestCollectFirewalldNotRunningOnStderr(t *testing.T) {
	programs, cmds := fakeMachine()
	cmds["firewall-cmd --state"] = fakeCmd{stderr: "not running\n", code: 252}
	var calls [][]string
	b := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	if s, _ := b.Get("firewalld-state"); s != "not running" {
		t.Errorf("state: %q", s)
	}
	if _, bad := b.Errors()["firewalld-state"]; bad {
		t.Error("a stopped firewalld is not an error")
	}
}

func TestCollectKeepsPartialInspect(t *testing.T) {
	programs, cmds := fakeMachine()
	k := "docker inspect --format " + dockerInspectTemplate + " " + idWeb + " " + idDB + " " + idMon
	c := cmds[k]
	c.code, c.stderr = 1, "Error: No such object: "+idMon+"\n"
	cmds[k] = c
	var calls [][]string
	b := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	if _, ok := b.GetArg("docker-ss", idWeb); !b.Has("docker-net") || !ok {
		t.Error("the lines for the containers still running should be kept")
	}
}

func TestLocalEnvDropsRemoteDocker(t *testing.T) {
	t.Setenv("DOCKER_HOST", "ssh://admin@192.0.2.50")
	t.Setenv("DOCKER_CONTEXT", "remote")
	for _, kv := range localEnv() {
		if strings.HasPrefix(kv, "DOCKER_HOST=") || strings.HasPrefix(kv, "DOCKER_CONTEXT=") {
			t.Errorf("kept %s", kv)
		}
	}
	if !strings.Contains(Script(), "unset DOCKER_HOST DOCKER_CONTEXT") {
		t.Error("the script must not follow DOCKER_HOST either")
	}
}

func TestCollectRefusesOddNames(t *testing.T) {
	programs, cmds := fakeMachine()
	cmds["firewall-cmd --list-all-zones"] = fakeCmd{out: "public (active)\n  services: --reload ok/../x ssh\n"}
	cmds["docker ps --no-trunc --format {{json .}}"] = fakeCmd{out: `{"ID":"--help","Names":"x","State":"running"}` + "\n"}
	var calls [][]string
	collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	for _, c := range calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "--reload") || strings.Contains(j, "/../") || strings.Contains(j, "--help") {
			t.Errorf("ran %q", c)
		}
	}
	checkCalls(t, calls)
}

// checkCalls asserts that every command actually run is a read-only one from the table.
func checkCalls(t *testing.T, calls [][]string) {
	t.Helper()
	for _, c := range calls {
		ok, known := readOnly[c[0]]
		if !known || !ok(c[1:]) {
			t.Errorf("ran a command that is not a read-only listing: %q", c)
		}
	}
}

func TestExecRun(t *testing.T) {
	// A program that cannot exist leaves no trace.
	if r := execRun(context.Background(), []string{"seaward-no-such-program-x"}); !r.missing {
		t.Errorf("got %+v", r)
	}
	r := execRun(context.Background(), []string{"sh", "-c", "echo $LC_ALL; echo; echo; echo first >&2; echo second >&2; exit 3"})
	if r.stdout != "C" || r.errLine != "first" || r.code != 3 || r.missing {
		t.Errorf("got %+v", r)
	}
	old := commandTimeout
	commandTimeout = 200 * time.Millisecond
	defer func() { commandTimeout = old }()
	start := time.Now()
	r = execRun(context.Background(), []string{"sh", "-c", "sleep 5"})
	if !strings.Contains(r.errLine, "timed out") || time.Since(start) > 3*time.Second {
		t.Errorf("timeout: %+v after %v", r, time.Since(start))
	}
	if !isHex(idWeb) || isHex("--help") || isHex("") {
		t.Error("isHex")
	}
	if !safeName("dhcpv6-client") || safeName("--reload") || safeName("a b") || safeName("") {
		t.Error("safeName")
	}
}

// TestCollectLive runs the real collector on the machine running the tests, when asked to with
// SEAWARD_LIVE_COLLECT=1. It prints only section names and sizes, never their contents.
func TestCollectLive(t *testing.T) {
	if os.Getenv("SEAWARD_LIVE_COLLECT") != "1" {
		t.Skip("set SEAWARD_LIVE_COLLECT=1 to run the collector on this machine")
	}
	start := time.Now()
	b := Collect(context.Background())
	for _, s := range b.Sections {
		t.Logf("%-22s %-14.14s %6d bytes", s.Name, s.Arg, len(s.Body))
	}
	for label := range b.Errors() {
		t.Logf("error: %s", label)
	}
	t.Logf("took %v", time.Since(start))
	_, h, err := Build(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range h.Notes {
		t.Logf("note: %s", n)
	}
	if again, err := Parse(b.String()); err != nil || !reflect.DeepEqual(again, b) {
		t.Fatal("live bundle does not survive a round trip")
	}
}
