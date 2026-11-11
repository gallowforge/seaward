package snapshot

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// TestScriptMatchesCollector runs the script against fake programs that print the same invented
// machine the collector tests use, and checks that both produce the same bundle.
func TestScriptMatchesCollector(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	tools := map[string]string{}
	for _, n := range []string{"sed", "grep", "awk", "cat"} {
		p, err := exec.LookPath(n)
		if err != nil {
			t.Skipf("no %s", n)
		}
		tools[n] = p
	}
	programs, cmds := fakeMachine()
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
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, stderr.String())
	}
	got, err := Parse(string(out))
	if err != nil {
		t.Fatalf("script output is not a snapshot: %v\n%s", err, out)
	}

	var calls [][]string
	want := collectWith(context.Background(), fakeRunner(t, programs, cmds, &calls), fakeHost, true, func(string) bool { return true })

	// Meta differs in one word, and the script can only report exit codes, not messages.
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
	if len(ws) < 15 || len(we) != 3 {
		t.Fatalf("the fake machine should give a full bundle; got %d sections, %d errors", len(ws), len(we))
	}
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
	if strings.Contains(stderr.String(), "unexpected") {
		t.Errorf("the script ran a command the collector does not: %s", stderr.String())
	}
}
