package snapshot

import (
	"context"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestScriptSyntax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seaward-snapshot.sh")
	if err := os.WriteFile(path, []byte(Script()), 0o644); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, shell := range []string{"sh", "dash", "busybox", "bash"} {
		bin, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		args := []string{"-n", path}
		if shell == "busybox" {
			args = []string{"sh", "-n", path}
		}
		if shell == "bash" {
			args = []string{"--posix", "-n", path}
		}
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", shell, err, out)
		}
		ran++
	}
	if ran == 0 {
		t.Skip("no shell to check the script with")
	}
}

func TestScriptIsReadable(t *testing.T) {
	s := Script()
	if !strings.HasPrefix(s, "#!/bin/sh\n") || !strings.Contains(s, "collector script") || strings.Contains(s, "@VERSION@") ||
		strings.Contains(s, "@TEMPLATE@") || !strings.Contains(s, dockerInspectTemplate) ||
		strings.Contains(s, "@PS@") || !strings.Contains(s, dockerPSTemplate) || strings.Contains(s, "{{json .}}") {
		t.Error("script template not filled in")
	}
	if n := strings.Count(s, "\n"); n > 150 {
		t.Errorf("the script should stay short enough to read before running; it has %d lines", n)
	}
	// Every program the collector table names appears in the script, and docker inspect only
	// ever with the template.
	for _, c := range commands {
		if !strings.Contains(s, c.argv[0]) {
			t.Errorf("script never runs %s", c.argv[0])
		}
	}
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, "docker inspect") && !strings.HasPrefix(strings.TrimSpace(ln), "#") && !strings.Contains(ln, "--format '"+dockerInspectTemplate+"'") {
			t.Errorf("docker inspect without the field template: %s", ln)
		}
	}
}

// runScript runs the collector script against fake programs that print an invented machine, the
// same one the collector tests hand to collectWith, and returns the snapshot it printed and what
// it wrote to standard error. The second result is false when this machine lacks a tool the
// script needs.
func runScript(t *testing.T, programs []string, cmds map[string]fakeCmd) (b *Bundle, stderr string, ok bool) {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		return nil, "", false
	}
	tools := map[string]string{}
	for _, n := range []string{"sed", "grep", "awk", "cat"} {
		p, err := exec.LookPath(n)
		if err != nil {
			return nil, "", false
		}
		tools[n] = p
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, p := range tools {
		if err := os.Symlink(p, filepath.Join(bin, n)); err != nil {
			t.Fatal(err)
		}
	}
	writeExe := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!"+shell+"\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExe("hostname", "echo "+fakeHost+"\n")
	writeExe("id", "echo 0\n")

	// One fake per program: it finds its argument list in a case statement and prints the
	// stored output.
	keys := make([]string, 0, len(cmds))
	for k := range cmds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cases := map[string]*strings.Builder{}
	for i, k := range keys {
		c := cmds[k]
		prog, args, _ := strings.Cut(k, " ")
		n := strconv.Itoa(i)
		if err := os.WriteFile(filepath.Join(dir, "out."+n), []byte(c.out), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "err."+n), []byte(c.stderr), 0o644); err != nil {
			t.Fatal(err)
		}
		if cases[prog] == nil {
			cases[prog] = &strings.Builder{}
		}
		if strings.Contains(args, "'") {
			t.Fatalf("fake arguments cannot hold a quote: %q", k)
		}
		cases[prog].WriteString("'" + args + "') " + tools["cat"] + " " + dir + "/out." + n + "; " +
			tools["cat"] + " " + dir + "/err." + n + " >&2; exit " + strconv.Itoa(c.code) + " ;;\n")
	}
	for _, p := range programs {
		body := ""
		if cases[p] != nil {
			body = cases[p].String()
		}
		writeExe(p, "case \"$*\" in\n"+body+"esac\necho \"unexpected: $0 $*\" >&2\nexit 99\n")
	}

	// The script adds the sbin directories to PATH; here only the fakes may be found.
	text := strings.Replace(Script(), `PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"`, "", 1)
	cmd := exec.Command(shell, "-c", text)
	cmd.Env = []string{"PATH=" + bin}
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, errb.String())
	}
	b, err = Parse(string(out))
	if err != nil {
		t.Fatalf("script output is not a snapshot: %v\n%s", err, out)
	}
	return b, errb.String(), true
}

// sameSnapshot checks that the script and the collector made the same bundle of one machine.
// Meta differs in one word, and the script can only report exit codes, not messages, so of the
// errors it is the labels that are compared. It returns the collector's sections and labels.
func sameSnapshot(t *testing.T, got, want *Bundle) (sections []Section, errLabels []string) {
	t.Helper()
	strip := func(b *Bundle) (secs []Section, errLabels []string) {
		for _, s := range b.Sections {
			switch s.Name {
			case "meta":
				s.Body = strings.Replace(s.Body, "collector script", "collector cli", 1)
			case "errors":
				for label := range b.Errors() {
					errLabels = append(errLabels, label)
				}
				sort.Strings(errLabels)
				continue
			}
			secs = append(secs, s)
		}
		return secs, errLabels
	}
	gs, ge := strip(got)
	ws, we := strip(want)
	if !reflect.DeepEqual(gs, ws) {
		for i := 0; i < len(gs) || i < len(ws); i++ {
			var g, w Section
			if i < len(gs) {
				g = gs[i]
			}
			if i < len(ws) {
				w = ws[i]
			}
			if g != w {
				t.Errorf("section %d:\nscript    %+v\ncollector %+v", i, g, w)
			}
		}
	}
	if !reflect.DeepEqual(ge, we) {
		t.Errorf("errors: script %q, collector %q", ge, we)
	}
	return ws, we
}

// TestScriptMatchesCollector runs the script against fake programs that print the same invented
// machine the collector tests use, and checks that both produce the same bundle.
func TestScriptMatchesCollector(t *testing.T) {
	programs, cmds := fakeMachine()
	got, stderr, ok := runScript(t, programs, cmds)
	if !ok {
		t.Skip("no sh, sed, grep, awk or cat to run the script with")
	}
	var calls [][]string
	want := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	ws, we := sameSnapshot(t, got, want)
	if len(ws) < 15 || len(we) != 3 {
		t.Fatalf("the fake machine should give a full bundle; got %d sections, %d errors", len(ws), len(we))
	}
	// Not only alike: the script's interface list is the one the collector test spells out, with
	// no hardware address left in it or anywhere else.
	if s, _ := got.Get("ip-addr"); s != fakeIPAddrKept {
		t.Errorf("the script's ip-addr:\n got %s\nwant %s", s, fakeIPAddrKept)
	}
	if text := got.String(); strings.Contains(text, "5e:00:53") || strings.Contains(text, "5e:0:53") || strings.Contains(text, "5e0053") || strings.Contains(text, "5e00-53") {
		t.Error("a hardware address is in the script's snapshot")
	}
	if strings.Contains(stderr, "unexpected") {
		t.Errorf("the script ran a command the collector does not: %s", stderr)
	}
}

// TestScriptAsksForTheTextListingOnce: like the collector, the script asks nft for its text
// listing only when the JSON listing worked, so a machine that refuses nft says so in one line.
func TestScriptAsksForTheTextListingOnce(t *testing.T) {
	programs, cmds := fakeMachine()
	for k := range cmds {
		if strings.HasPrefix(k, "nft ") {
			cmds[k] = fakeCmd{stderr: "Error: Operation not permitted (you must be root)\n", code: 1}
		}
	}
	got, _, ok := runScript(t, programs, cmds)
	if !ok {
		t.Skip("no sh, sed, grep, awk or cat to run the script with")
	}
	var calls [][]string
	want := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	sameSnapshot(t, got, want)
	if errs := got.Errors(); errs["nft-json"] == "" || errs["nft-text"] != "" || got.Has("nft-text") {
		t.Errorf("errors: %q", errs)
	}
	// And when nft answers, the text is in the script's snapshot as the collector has it.
	programs, cmds = fakeMachine()
	got, _, _ = runScript(t, programs, cmds)
	want = collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
	g, _ := got.Get("nft-text")
	w, _ := want.Get("nft-text")
	if g != w || !strings.Contains(g, "hook input") {
		t.Errorf("nft-text:\n got %q\nwant %q", g, w)
	}
}

// TestScriptLegacySave runs the script on the machines of TestCollectLegacySave: a legacy listing
// that fails leaves the same errors line the collector writes, and one that is missing or empty
// leaves nothing.
func TestScriptLegacySave(t *testing.T) {
	for _, tt := range legacyMachines {
		t.Run(tt.name, func(t *testing.T) {
			programs, cmds := fakeMachine()
			programs = tt.change(programs, cmds)
			got, stderr, ok := runScript(t, programs, cmds)
			if !ok {
				t.Skip("no sh, sed, grep, awk or cat to run the script with")
			}
			var calls [][]string
			want := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })
			sameSnapshot(t, got, want)
			// And against the table itself, not only against the collector.
			var kept, failed, wantFailed []string
			for _, s := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
				if got.Has(s) {
					kept = append(kept, s)
				}
				if msg, bad := got.Errors()[s]; bad {
					failed = append(failed, s)
					if !strings.HasPrefix(msg, "exit status ") {
						t.Errorf("%s: the script wrote %q, want an exit status", s, msg)
					}
				}
				if _, bad := tt.errs[s]; bad {
					wantFailed = append(wantFailed, s)
				}
			}
			if !slices.Equal(kept, tt.kept) || !slices.Equal(failed, wantFailed) {
				t.Errorf("legacy sections kept %q, want %q; noted as failed %q, want %q", kept, tt.kept, failed, wantFailed)
			}
			if strings.Contains(stderr, "unexpected") {
				t.Errorf("the script ran a command the collector does not: %s", stderr)
			}
		})
	}
}

// TestScriptMaskIsTheCollectorMask cuts the mask function out of the script as it is printed,
// runs it with every sed this machine has, and wants from it, byte for byte, what the collector's
// maskHardware makes of the same text: the texts of TestMaskHardware, the invented machine's
// interface list, and thousands of generated lines made of the pieces that hardware addresses,
// bridge ids, IP addresses, names and device ids are written with.
func TestScriptMaskIsTheCollectorMask(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	text := Script()
	start := strings.Index(text, "\nmask() {\n")
	if start < 0 {
		t.Fatal("the script has no mask function")
	}
	fn, _, ok := strings.Cut(text[start+1:], "\n}\n")
	if !ok || !strings.Contains(fn, "sed ") {
		t.Fatalf("could not cut the mask function out of the script:\n%s", fn)
	}
	fn += "\n}\n"

	var lines []string
	for _, c := range maskCases {
		in, _ := unmark(c.marked)
		lines = append(lines, strings.Split(in, "\n")...)
	}
	lines = append(lines, fakeIPAddr)
	r := rand.New(rand.NewPCG(7, 2026))
	pieces := []string{`"`, `"`, `"`, `"`, ":", ":", ":", ":", ":", ".", "::", "0", "5", "e", "5e", "53", "00", "ff", "A", "0a", "1F", "8000", "8000.",
		"g", "x", "xx", " ", ",", ",", `\"`, `\\`, "[", "[", "]", "{", "}", "/", "-", "en", "enx", "wlx", "00005e005301", "é", "\xff", "\t", "\r"}
	hexDigits := func(n int) string {
		var sb strings.Builder
		for range n {
			sb.WriteByte("0123456789abcdefABCDEF"[r.IntN(22)])
		}
		return sb.String()
	}
	for range 4000 {
		// Anything at all, from those pieces.
		var sb strings.Builder
		for range 1 + r.IntN(40) {
			sb.WriteString(pieces[r.IntN(len(pieces))])
		}
		lines = append(lines, sb.String())
		// And strings that are hardware addresses or just miss being one: a few of them to a
		// line, each some number of groups of some width, perhaps after a bridge id's priority.
		sb.Reset()
		for range 1 + r.IntN(4) {
			sb.WriteString([]string{`"`, `"`, `"`, `"`, `"`, `\"`, ``, `" `}[r.IntN(8)])
			if r.IntN(3) == 0 {
				sb.WriteString(hexDigits([]int{4, 4, 4, 4, 3, 5}[r.IntN(6)]) + []string{".", ".", ".", ".", ":", ""}[r.IntN(6)])
			}
			width := []func() int{func() int { return 2 }, func() int { return 2 }, func() int { return 1 + r.IntN(2) }, func() int { return 1 + r.IntN(3) }}[r.IntN(4)]
			groups := []int{6, 6, 6, 6, 5, 7, 8, 9, 10, 20, 1 + r.IntN(34)}[r.IntN(11)]
			for g := range groups {
				if g > 0 {
					sb.WriteString(":")
				}
				sb.WriteString(hexDigits(width()))
			}
			sb.WriteString([]string{`"`, `"`, `"`, `"`, `"`, `",`, ``, ` "`, `:"`}[r.IntN(9)])
		}
		lines = append(lines, sb.String())
		// And the same for names made from an address and for device ids: in a list or after a
		// key, with a digit too few or too many, in capitals.
		sb.Reset()
		for range 1 + r.IntN(4) {
			sb.WriteString([]string{`["`, `,"`, `,"`, `:"`, `"`, `[ "`, `,\"`}[r.IntN(7)])
			if r.IntN(2) == 0 {
				sb.WriteString([]string{"en", "en", "wl", "ww", "EN", "e", "enp", "e1"}[r.IntN(8)] + []string{"x", "x", "x", "p", "X"}[r.IntN(5)])
				sb.WriteString(hexDigits([]int{12, 12, 12, 11, 13}[r.IntN(5)]))
			} else {
				for i, n := range []int{8, 4, 4, 4, []int{12, 12, 12, 11, 13}[r.IntN(5)]} {
					if i > 0 {
						sb.WriteString([]string{"-", "-", "-", "-", "-", "-", "-", ":", ""}[r.IntN(9)])
					}
					sb.WriteString(hexDigits(n))
				}
			}
			sb.WriteString([]string{`"`, `"`, `"`, `"]`, `",`, ``, ` "`}[r.IntN(7)])
		}
		lines = append(lines, sb.String())
	}
	input := strings.Join(lines, "\n") + "\n"
	want := maskHardware(input)
	macs, names, ids := strings.Count(want, maskedMAC), strings.Count(want, "xxxxxxxxxxxx\""), strings.Count(want, maskedID)
	if macs < 1500 || names-ids < 250 || ids < 500 || strings.Count(want, ":") < 20*macs {
		t.Fatalf("the texts should hold plenty to mask and plenty to leave; masked were %d addresses, %d names and %d device ids", macs, names-ids, ids)
	}

	// Each sed gets a directory of its own to be found in.
	seds := map[string]string{}
	for name, argv := range map[string][]string{"sed": {"sed"}, "gsed": {"gsed"}, "busybox sed": {"busybox", "sed"}} {
		if p, err := exec.LookPath(argv[0]); err == nil {
			dir := t.TempDir()
			if err := os.Symlink(p, filepath.Join(dir, "sed")); err != nil {
				t.Fatal(err)
			}
			seds[name] = dir
		}
	}
	if len(seds) == 0 {
		t.Skip("no sed")
	}
	for name, dir := range seds {
		cmd := exec.Command(shell, "-c", fn+"mask")
		cmd.Env = []string{"PATH=" + dir, "LC_ALL=C"} // the script sets LC_ALL=C itself
		cmd.Stdin = strings.NewReader(input)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("%s: %v\n%s", name, err, stderr.String())
			continue
		}
		if got := string(out); got != want {
			gl, wl, il := strings.Split(got, "\n"), strings.Split(want, "\n"), strings.Split(input, "\n")
			for i := 0; i < len(gl) && i < len(wl); i++ {
				if gl[i] != wl[i] {
					t.Errorf("%s and the collector part ways on line %d:\ntext      %q\nscript    %q\ncollector %q", name, i+1, il[i], gl[i], wl[i])
					break
				}
			}
			t.Errorf("%s: the script's mask printed %d lines, the collector's %d, and they differ", name, len(gl), len(wl))
		}
	}
}
