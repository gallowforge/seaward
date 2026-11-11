package lab

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
)

// TestMain turns the test binary into the lab helper when the script runs it as one.
func TestMain(m *testing.M) {
	if role := os.Getenv(HelperEnv); role != "" {
		os.Exit(RunHelper(role, os.Args[1:], os.Stdout))
	}
	os.Exit(m.Run())
}

const sample = `name: sample
about: one of each thing
container: yes
sysctl: net.ipv4.conf.eth0.route_localnet=1
publish: 0.0.0.0:8080->80/tcp
--- iptables
*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
--- listen
host tcp 0.0.0.0 22
host tcp :: 8080 dual
host tcp :: 8081 v6only
host udp 203.0.113.10 53 dev=eth0
ctr tcp 0.0.0.0 80
--- probes
eth0 198.51.100.7 203.0.113.10 tcp 22 want:open
eth0 203.0.113.77 203.0.113.10 tcp 23 want:silent
eth1 192.0.2.50 10.20.0.1 udp 53 want:silent expect-undecided
eth0 2001:db8:99::7 2001:db8:1::10 tcp 8081 want:silent
`

func TestScriptStartsWithGuard(t *testing.T) {
	sc, err := ParseScenario("sample.txt", sample)
	if err != nil {
		t.Fatal(err)
	}
	s := Script(sc, ScriptOptions{})
	rest, ok := strings.CutPrefix(s, scriptHeader)
	if !ok {
		t.Fatal("script does not start with its header")
	}
	for _, line := range strings.Split(scriptHeader, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			t.Fatalf("header line %q is not a comment", line)
		}
	}
	if !strings.HasPrefix(rest, guard) {
		t.Fatalf("the guard is not the first thing the script runs:\n%s", rest[:200])
	}
	// The guard checks the marker and that lo is the only interface.
	for _, want := range []string{`"${SEAWARD_LAB_INSIDE:-}" = 1`, `ip -o link show`, `-eq 1`, `"1: lo: "*`} {
		if !strings.Contains(guard, want) {
			t.Errorf("guard lacks %q", want)
		}
	}
	// Right after the guard: private /run, then lo up.
	after := rest[len(guard):]
	if i, j := strings.Index(after, "mount -t tmpfs tmpfs /run"), strings.Index(after, "ip link set lo up"); i < 0 || j < i {
		t.Error("the script does not mount a private /run before anything else")
	}
}

// TestGuardRefusesHere runs only the guard on this machine. It lists interfaces (read-only) and
// must refuse: without the marker, and with the marker because this is not a fresh namespace.
func TestGuardRefusesHere(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("no ip command")
	}
	run := func(env ...string) int {
		cmd := exec.Command("sh", "-c", guard+"echo PASSED")
		// Later entries win, so the marker is cleared unless env sets it.
		cmd.Env = append(os.Environ(), "SEAWARD_LAB_INSIDE=")
		cmd.Env = append(cmd.Env, env...)
		out, err := cmd.CombinedOutput()
		if strings.Contains(string(out), "PASSED") {
			t.Fatalf("guard let the script run here: %s", out)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("guard: %v %s", err, out)
		return 0
	}
	if code := run(); code != 97 {
		t.Errorf("without the marker the guard exited %d, want 97", code)
	}
	links, _ := exec.Command("ip", "-o", "link", "show").Output()
	if strings.Count(strings.TrimSpace(string(links)), "\n") == 0 {
		t.Skip("this machine has only lo; cannot test the interface check here")
	}
	if code := run("SEAWARD_LAB_INSIDE=1"); code != 98 {
		t.Errorf("with the marker outside a fresh namespace the guard exited %d, want 98", code)
	}
}

func TestLauncherRefusesWithoutUnshare(t *testing.T) {
	bad := [][]string{
		{"sh", "/x/scenario.sh"},
		{"env", "SEAWARD_LAB_INSIDE=1", "sh", "/x/scenario.sh"},
		{"sudo", "-n", "sh", "/x/scenario.sh"},
		{"unshare", "-Ur", "sh", "/x/scenario.sh"},      // no network namespace
		{"unshare", "-n", "sh", "/x/scenario.sh"},       // no mount namespace
		{"unshare", "-Urnm", "bash", "/x/scenario.sh"},  // not sh
		{"unshare", "-Urnm", "sh", "-c", "iptables -F"}, // not a script
		{"unshare", "--fork", "-nm", "sh", "/x/scenario.sh"},
		{"sh", "-c", "unshare -Urnm sh /x/scenario.sh"},
		{"/bin/sh", "unshare", "-Urnm", "sh", "/x/s.sh"},
		{},
	}
	for _, argv := range bad {
		if err := checkArgv(argv); err == nil {
			t.Errorf("checkArgv accepted %q", argv)
		}
	}
	for _, sudo := range []bool{false, true} {
		l := &Launcher{Sudo: sudo, Helper: "/x/lab.test"}
		argv, err := l.Argv("/x/scenario.sh", "/x")
		if err != nil {
			t.Fatalf("sudo=%v: %v", sudo, err)
		}
		joined := strings.Join(argv, " ")
		want := "unshare -Urnm sh /x/scenario.sh"
		if sudo {
			want = "unshare -n -m sh /x/scenario.sh"
			if argv[0] != "sudo" || argv[1] != "-n" {
				t.Errorf("sudo argv %q does not start with sudo -n", joined)
			}
		}
		if !strings.HasSuffix(joined, want) || !strings.Contains(joined, "SEAWARD_LAB_INSIDE=1") {
			t.Errorf("argv %q", joined)
		}
	}
	l := &Launcher{Helper: "relative/lab.test"}
	if _, err := l.Argv("/x/scenario.sh", "/x"); err == nil {
		t.Error("Argv accepted a relative helper path")
	}
}

func TestParseScenarioRoundTrip(t *testing.T) {
	sc, err := ParseScenario("sample.txt", sample)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Containers != 1 || !sc.Forwarding() || !sc.UsesEth1() || len(sc.Listens) != 5 || len(sc.Probes) != 4 {
		t.Fatalf("parsed wrong: %+v", sc)
	}
	if l := sc.Listens[2]; !l.V6Only || l.Addr != netip.IPv6Unspecified() {
		t.Errorf("v6only listener: %+v", l)
	}
	if l := sc.Listens[3]; l.Dev != "eth0" {
		t.Errorf("dev listener: %+v", l)
	}
	if p := sc.Probes[2]; p.Want != OutSilent || !p.ExpectUndecided || p.Iif != "eth1" {
		t.Errorf("probe: %+v", p)
	}
	again, err := ParseScenario("sample.txt", sc.Format(nil))
	if err != nil {
		t.Fatalf("%v\n%s", err, sc.Format(nil))
	}
	for i := range again.Probes {
		again.Probes[i].Line = sc.Probes[i].Line
	}
	if !reflect.DeepEqual(sc, again) {
		t.Errorf("round trip changed the scenario:\n%+v\n%+v", sc, again)
	}
}

func TestParseScenarioErrors(t *testing.T) {
	head := "name: x\n--- probes\n"
	bad := map[string]string{
		"no name":         "--- probes\neth0 198.51.100.7 203.0.113.10 tcp 22\n",
		"no probes":       "name: x\n",
		"bad block":       "name: x\n--- rules\n",
		"bad source":      head + "eth0 8.8.8.8 203.0.113.10 tcp 22\n",
		"eth1 source":     head + "eth1 198.51.100.7 10.20.0.1 tcp 22\n",
		"mixed families":  head + "eth0 198.51.100.7 2001:db8:1::10 tcp 22\n",
		"loopback dst":    head + "eth0 198.51.100.7 127.0.0.1 tcp 22\n",
		"bad want":        head + "eth0 198.51.100.7 203.0.113.10 tcp 22 want:maybe\n",
		"bad iif":         head + "eth9 198.51.100.7 203.0.113.10 tcp 22\n",
		"shell in sysctl": "name: x\nsysctl: net.a=1;reboot\n--- probes\neth0 198.51.100.7 203.0.113.10 tcp 22\n",
		"shell in name":   "name: x$(id)\n--- probes\neth0 198.51.100.7 203.0.113.10 tcp 22\n",
		"ctr w/o ctr":     "name: x\n--- listen\nctr tcp 0.0.0.0 80\n--- probes\neth0 198.51.100.7 203.0.113.10 tcp 22\n",
		"quote publish":   "name: x\npublish: 0.0.0.0:1->2/tcp'\n--- probes\neth0 198.51.100.7 203.0.113.10 tcp 22\n",
		"dual on v4":      "name: x\n--- listen\nhost tcp 0.0.0.0 80 dual\n--- probes\neth0 198.51.100.7 203.0.113.10 tcp 22\n",
	}
	for what, text := range bad {
		if _, err := ParseScenario("t.txt", text); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}

func TestScenarioFiles(t *testing.T) {
	scs, err := LoadScenarios("scenarios")
	if err != nil {
		t.Fatal(err)
	}
	ipt, nft := 0, 0
	for _, sc := range scs {
		if sc.NFT != "" {
			nft++
		} else {
			ipt++
		}
		if sc.About == "" {
			t.Errorf("%s: no about:", sc.File)
		}
		if want := strings.TrimSuffix(sc.File, ".txt"); sc.Name != want {
			t.Errorf("%s: name %q should match the file name", sc.File, sc.Name)
		}
		for _, p := range sc.Probes {
			if p.Want == "" {
				t.Errorf("%s:%d: probe without want:", sc.File, p.Line)
			}
		}
		// Every scenario must produce a script and files without error.
		_ = Script(sc, ScriptOptions{})
		_ = Files(sc)
	}
	if ipt < 30 || nft < 8 {
		t.Errorf("%d iptables and %d nft scenarios; want at least 30 and 8", ipt, nft)
	}
}

func TestScriptContainer(t *testing.T) {
	sc, err := ParseScenario("sample.txt", sample)
	if err != nil {
		t.Fatal(err)
	}
	s := Script(sc, ScriptOptions{TimeoutMS: 500})
	for _, want := range []string{
		`sysctl -q -w net.ipv4.ip_forward=1`,
		`ip link add docker0 address 02:42:ac:11:00:01 type bridge`,
		`ip netns add peer2`,
		`ip -n peer addr add 203.0.113.77/32 dev lo`,
		`ip neigh replace 203.0.113.77 lladdr 02:00:00:00:00:01 dev eth0 nud permanent`,
		`sysctl -q -w net.ipv4.conf.eth0.route_localnet=1`,
		`iptables-restore < "$LAB_OUT/iptables.rules"`,
		`echo '{"ID":"c1c1c1c1c1c1","Names":"web","Image":"lab","Ports":"0.0.0.0:8080->80/tcp","Networks":"bridge","State":"running"}'`,
		`echo "c1c1c1c1c1c1 $lab_pid_ctr bridge bridge=172.17.0.2|"`,
		`lab_sec 'docker-ss c1c1c1c1c1c1' ip netns exec ctr ss -Htulpn`,
		`"$LAB_OUT/probes-eth1.txt" 500`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "ip6tables-restore") || strings.Contains(s, "nft -f") {
		t.Error("script loads rules the scenario does not have")
	}
	// The sysctls that a new namespace inherits must be set before the first interface.
	if strings.Index(s, "rp_filter=0") > strings.Index(s, "ip link add") {
		t.Error("rp_filter is set after interfaces exist")
	}
	f := Files(sc)
	if f["probes-eth0.txt"] != "0 198.51.100.7 203.0.113.10 tcp 22\n1 203.0.113.77 203.0.113.10 tcp 23\n3 2001:db8:99::7 2001:db8:1::10 tcp 8081\n" {
		t.Errorf("probes-eth0.txt:\n%s", f["probes-eth0.txt"])
	}
	if f["listen-ctr.txt"] != "tcp 0.0.0.0 80 0 -\n" || !strings.Contains(f["listen-host.txt"], "tcp :: 8081 1 -\n") {
		t.Errorf("listen files: %q %q", f["listen-ctr.txt"], f["listen-host.txt"])
	}
}

func TestGenerate(t *testing.T) {
	a, b := Generate(7, 20), Generate(7, 20)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("the generator is not deterministic")
	}
	if reflect.DeepEqual(GenerateOne(7, 0).IPTables, GenerateOne(8, 0).IPTables) &&
		reflect.DeepEqual(GenerateOne(7, 1).IPTables, GenerateOne(8, 1).IPTables) {
		t.Error("different seeds gave the same rulesets")
	}
	if !reflect.DeepEqual(GenerateOne(7, 13), a[13]) {
		t.Error("one ruleset cannot be replayed alone")
	}
	for _, sc := range Generate(3, 200) {
		if err := sc.validate(); err != nil {
			t.Fatalf("%s: %v", sc.Name, err)
		}
		again, err := ParseScenario("gen.txt", sc.Format(nil))
		if err != nil {
			t.Fatalf("%s: %v\n%s", sc.Name, err, sc.Format(nil))
		}
		if again.IPTables != sc.IPTables || len(again.Probes) != len(sc.Probes) || len(again.Listens) != len(sc.Listens) {
			t.Fatalf("%s: format round trip lost something", sc.Name)
		}
		// No user chain may jump to itself or to an earlier one.
		for _, line := range strings.Split(sc.IPTables, "\n") {
			var from, to int
			var verb string
			if n, _ := sscanJump(line, &from, &verb, &to); n == 3 && to <= from {
				t.Fatalf("%s: loop risk in %q", sc.Name, line)
			}
		}
		if len(sc.Probes) != 40 {
			t.Fatalf("%s: %d probes", sc.Name, len(sc.Probes))
		}
	}
}

func sscanJump(line string, from *int, verb *string, to *int) (int, error) {
	if !strings.HasPrefix(line, "-A U") {
		return 0, nil
	}
	f := strings.Fields(line)
	n := 0
	if _, err := fmt.Sscanf(f[1], "U%d", from); err == nil {
		n++
	}
	for i := 2; i+1 < len(f); i++ {
		if (f[i] == "-j" || f[i] == "-g") && strings.HasPrefix(f[i+1], "U") {
			*verb = f[i]
			n++
			if _, err := fmt.Sscanf(f[i+1], "U%d", to); err == nil {
				n++
			}
		}
	}
	return n, nil
}

func TestJudge(t *testing.T) {
	sc, err := ParseScenario("sample.txt", sample)
	if err != nil {
		t.Fatal(err)
	}
	run := &Run{Scenario: sc, Reals: map[int]Real{
		0: {ID: 0, Outcome: OutOpen},
		1: {ID: 1, Outcome: OutSilent},
		2: {ID: 2, Outcome: OutSilent},
		3: {ID: 3, Outcome: OutRefused}, // the scenario wants silent
	}}
	fake := func(_ string, probes []Probe) ([]engine.Result, error) {
		return []engine.Result{
			{Class: engine.Open},
			{Class: engine.Rejected}, // kernel was silent: disagreement
			{Class: engine.Undecided, Unknowns: []string{"x"}},
			{Class: engine.Closed},
		}, nil
	}
	rep := Judge(run, false, fake)
	if rep.Err != nil {
		t.Fatal(rep.Err)
	}
	v := rep.Verdicts
	if v[0].Disagree || v[0].WantMismatch || !v[1].Disagree || !v[2].Undecided || !v[2].UndecidedOK || !v[3].WantMismatch || v[3].Disagree {
		t.Errorf("verdicts: %+v", v)
	}
	if !rep.Failed() {
		t.Error("report with a disagreement did not fail")
	}
	table := FormatTable([]*Report{rep})
	for _, want := range []string{"eth0 203.0.113.77 203.0.113.10 tcp 23", "rejected", "engine and kernel disagree", "the scenario wants silent"} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
	if strings.Contains(table, "udp 53") {
		t.Errorf("an expected undecided probe is in the table:\n%s", table)
	}
	s := Summarize([]*Report{rep}, "compare", 1)
	if s.Scenarios != 1 || s.Probes != 4 || s.Disagreements != 1 || s.Undecided != 1 || s.WantMismatches != 1 || s.WantMatched != 3 {
		t.Errorf("summary: %+v", s)
	}

	rec := Judge(run, true, func(string, []Probe) ([]engine.Result, error) {
		t.Fatal("record mode called the engine")
		return nil, nil
	})
	if rec.Verdicts[1].Disagree || !rec.Verdicts[3].WantMismatch {
		t.Errorf("record verdicts: %+v", rec.Verdicts)
	}
	failing := Judge(run, false, func(string, []Probe) ([]engine.Result, error) {
		return nil, errors.New("snapshot.Parse: not written yet")
	})
	if failing.Err == nil || !failing.Failed() {
		t.Error("an engine error did not fail the scenario")
	}
}

func TestAgrees(t *testing.T) {
	cases := []struct {
		c engine.Class
		o Outcome
		y bool
	}{
		{engine.Open, OutOpen, true}, {engine.Open, OutRefused, false},
		{engine.Closed, OutRefused, true}, {engine.Rejected, OutRefused, true},
		{engine.Rejected, OutSilent, false}, {engine.Filtered, OutSilent, true},
		{engine.Filtered, OutOpen, false}, {engine.Forwarded, OutOpen, false},
		{engine.Undecided, OutSilent, false},
	}
	for _, c := range cases {
		if Agrees(c.c, c.o) != c.y {
			t.Errorf("Agrees(%v, %v) != %v", c.c, c.o, c.y)
		}
	}
}

func TestClassify(t *testing.T) {
	op := func(e error) error { return &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", e)} }
	cases := map[error]Outcome{
		op(syscall.ECONNREFUSED):  OutRefused,
		op(syscall.EHOSTUNREACH):  OutRefused,
		op(syscall.ENETUNREACH):   OutRefused,
		op(syscall.EACCES):        OutRefused,
		op(syscall.EADDRNOTAVAIL): OutError,
		os.ErrDeadlineExceeded:    OutSilent,
	}
	for err, want := range cases {
		if got, _ := classify(err); got != want {
			t.Errorf("classify(%v) = %v, want %v", err, got, want)
		}
	}
}

func TestReplyOOB(t *testing.T) {
	// A received in_pktinfo for 203.0.113.10 must become a reply from 203.0.113.10.
	data := []byte{2, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 10}
	got := replyOOB(cmsg(syscall.IPPROTO_IP, syscall.IP_PKTINFO, data))
	msgs, err := syscall.ParseSocketControlMessage(got)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("%v %v", msgs, err)
	}
	if want := []byte{0, 0, 0, 0, 203, 0, 113, 10, 0, 0, 0, 0}; !reflect.DeepEqual(msgs[0].Data[:12], want) {
		t.Errorf("reply pktinfo %v, want %v", msgs[0].Data, want)
	}
}
