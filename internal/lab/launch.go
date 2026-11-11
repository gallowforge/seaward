package lab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Launcher starts scenario scripts, always inside a fresh network namespace.
type Launcher struct {
	// Sudo runs `sudo -n unshare -n -m` (for CI, where unprivileged user namespaces may be off)
	// instead of the unprivileged `unshare -Urnm`.
	Sudo bool
	// Helper is the path of the helper binary (the test binary itself).
	Helper    string
	TimeoutMS int
}

// LauncherFromEnv reads SEAWARD_LAB_SUDO and SEAWARD_LAB_TIMEOUT_MS.
func LauncherFromEnv(helper string) *Launcher {
	l := &Launcher{Helper: helper, Sudo: os.Getenv("SEAWARD_LAB_SUDO") == "1", TimeoutMS: DefaultTimeoutMS}
	if v := os.Getenv("SEAWARD_LAB_TIMEOUT_MS"); v != "" {
		var ms int
		if _, err := fmt.Sscan(v, &ms); err == nil && ms > 0 {
			l.TimeoutMS = ms
		}
	}
	return l
}

// Argv is the command line that runs script with outDir as its LAB_OUT. It always passes
// through checkArgv, so it cannot produce a command that would run outside a new namespace.
func (l *Launcher) Argv(script, outDir string) ([]string, error) {
	if !filepath.IsAbs(script) || !filepath.IsAbs(outDir) || !filepath.IsAbs(l.Helper) {
		return nil, errors.New("lab: script, output directory and helper must be absolute paths")
	}
	env := []string{"SEAWARD_LAB_INSIDE=1", "LAB_OUT=" + outDir, "LAB_HELPER=" + l.Helper}
	var argv []string
	if l.Sudo {
		// sudo drops the environment, so env carries the marker through it.
		argv = append([]string{"sudo", "-n", "env"}, env...)
		argv = append(argv, "unshare", "-n", "-m", "sh", script)
	} else {
		argv = append([]string{"env"}, env...)
		argv = append(argv, "unshare", "-Urnm", "sh", script)
	}
	if err := checkArgv(argv); err != nil {
		return nil, err
	}
	return argv, nil
}

// checkArgv refuses any command line that does not start the shell through unshare with new
// network and mount namespaces. It is the last gate before exec.
func checkArgv(argv []string) error {
	u := -1
	for i, a := range argv {
		if a == "unshare" {
			u = i
			break
		}
		if a == "sh" || strings.HasSuffix(a, "/sh") {
			return errors.New("lab: refusing a command line that runs the shell before unshare")
		}
	}
	if u < 0 {
		return errors.New("lab: refusing a command line without unshare")
	}
	rest := argv[u+1:]
	net, mnt := false, false
	i := 0
	for ; i < len(rest) && strings.HasPrefix(rest[i], "-"); i++ {
		a := rest[i]
		switch {
		case a == "--net":
			net = true
		case a == "--mount":
			mnt = true
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("lab: refusing unknown unshare option %q", a)
		default:
			net = net || strings.Contains(a, "n")
			mnt = mnt || strings.Contains(a, "m")
		}
	}
	if !net || !mnt {
		return errors.New("lab: refusing unshare without a new network and mount namespace")
	}
	if len(rest)-i != 2 || rest[i] != "sh" {
		return errors.New("lab: refusing a command line that does not run exactly `sh <script>` inside unshare")
	}
	return nil
}

// Real is the outcome of one probe as the prober reported it.
type Real struct {
	ID      int     `json:"id"`
	Outcome Outcome `json:"outcome"`
	Detail  string  `json:"detail,omitempty"`
	MS      int64   `json:"ms"`
	Tries   int     `json:"tries"` // always 1: see sendProbe
}

// Run is one scenario run in the kernel.
type Run struct {
	Scenario *Scenario
	Dir      string
	Snapshot string
	Reals    map[int]Real // by probe index
	Elapsed  time.Duration
	Err      error
	Log      string // the script's output, for a failed run
	// Counters are the kernel's non-zero drop and error counters after the probes, in the host
	// and the peer namespace, to trace a lost answer.
	Counters string
}

// RunScenario builds the scenario in a fresh namespace, sends its probes and reads back the
// snapshot and the real outcomes. dir must be an empty directory the caller owns.
func (l *Launcher) RunScenario(ctx context.Context, sc *Scenario, dir string) *Run {
	r := &Run{Scenario: sc, Dir: dir, Reals: map[int]Real{}}
	start := time.Now()
	defer func() { r.Elapsed = time.Since(start) }()
	for name, body := range Files(sc) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			r.Err = err
			return r
		}
	}
	script := filepath.Join(dir, "scenario.sh")
	if err := os.WriteFile(script, []byte(Script(sc, ScriptOptions{TimeoutMS: l.TimeoutMS})), 0o644); err != nil {
		r.Err = err
		return r
	}
	argv, err := l.Argv(script, dir)
	if err != nil {
		r.Err = err
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	r.Log = out.String()
	if runErr != nil {
		r.Err = fmt.Errorf("scenario script failed: %v\n%s%s", runErr, r.Log, readTail(filepath.Join(dir, "listen-host.out")))
		return r
	}
	if _, err := os.Stat(filepath.Join(dir, "done")); err != nil {
		r.Err = fmt.Errorf("scenario script stopped early\n%s", r.Log)
		return r
	}
	snap, err := os.ReadFile(filepath.Join(dir, "snapshot.txt"))
	if err != nil {
		r.Err = err
		return r
	}
	r.Snapshot = string(snap)
	if c, err := os.ReadFile(filepath.Join(dir, "counters.txt")); err == nil {
		r.Counters = interestingCounters(string(c))
	}
	for _, iif := range []string{"eth0", "eth1"} {
		f, err := os.Open(filepath.Join(dir, "results-"+iif+".jsonl"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			r.Err = err
			return r
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			var re Real
			if err := json.Unmarshal(s.Bytes(), &re); err != nil {
				f.Close()
				r.Err = fmt.Errorf("prober output %q: %v", s.Text(), err)
				return r
			}
			r.Reals[re.ID] = re
		}
		f.Close()
	}
	for i := range sc.Probes {
		if _, ok := r.Reals[i]; !ok {
			r.Err = fmt.Errorf("no result for probe %d (%s)", i, sc.Probes[i])
			return r
		}
	}
	return r
}

func readTail(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	if len(b) > 2000 {
		b = b[len(b)-2000:]
	}
	return "listener: " + string(b)
}

// interestingCounters keeps the non-zero nstat lines that say a packet was dropped, refused or
// rate limited.
func interestingCounters(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "#" && (f[1] == "host" || f[1] == "peer") {
			b.WriteString(f[1] + ":")
			continue
		}
		if len(f) < 2 || f[1] == "0" {
			continue
		}
		name := f[0]
		for _, k := range []string{"RateLimit", "Drop", "Error", "Errors", "NoPorts", "OutDestUnreachs", "InDestUnreachs", "Backlog", "Overflow", "Fail"} {
			if strings.Contains(name, k) {
				b.WriteString(" " + name + "=" + f[1])
				break
			}
		}
	}
	return b.String()
}
