//go:build kernel && linux

package lab

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var seedFlag = flag.Uint64("lab.seed", 0, "seed for the random rulesets (default: SEAWARD_LAB_SEED, else 1)")

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v >= 0 {
		return v
	}
	return def
}

// TestKernel runs every hand-written scenario and the random rulesets in the real kernel.
//
//	SEAWARD_LAB_RECORD=1     skip the engine; check the scenario wants and print real outcomes
//	SEAWARD_LAB_RANDOM=N     random rulesets to run (default 40)
//	SEAWARD_LAB_SEED=S       seed for them (or -lab.seed S)
//	SEAWARD_LAB_ONLY=regexp  run only scenarios whose name matches
//	SEAWARD_LAB_WORKERS=N    scenarios at once (default: CPUs, at most 12)
//	SEAWARD_LAB_SUMMARY=path write a JSON summary
//	SEAWARD_LAB_KEEP=dir     keep each scenario's snapshot there as <name>.snapshot
//	SEAWARD_LAB_SUDO=1       use sudo -n unshare -n -m instead of unshare -Urnm (CI)
func TestKernel(t *testing.T) {
	start := time.Now()
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	l := LauncherFromEnv(helper)
	record := os.Getenv("SEAWARD_LAB_RECORD") == "1"
	seed := *seedFlag
	if seed == 0 {
		seed = uint64(envInt("SEAWARD_LAB_SEED", 1))
	}
	scs, err := LoadScenarios("scenarios")
	if err != nil {
		t.Fatal(err)
	}
	scs = append(scs, Generate(seed, envInt("SEAWARD_LAB_RANDOM", 40))...)
	if only := os.Getenv("SEAWARD_LAB_ONLY"); only != "" {
		re, err := regexp.Compile(only)
		if err != nil {
			t.Fatal(err)
		}
		var keep []*Scenario
		for _, sc := range scs {
			if re.MatchString(sc.Name) {
				keep = append(keep, sc)
			}
		}
		scs = keep
	}
	workers := envInt("SEAWARD_LAB_WORKERS", min(runtime.NumCPU(), 12))
	if workers < 1 {
		workers = 1
	}

	reps := make([]*Report, len(scs))
	unasked := make([]string, len(scs))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				dir, err := os.MkdirTemp(t.TempDir(), "run")
				if err != nil {
					reps[i] = &Report{Run: &Run{Scenario: scs[i]}, Err: err}
					continue
				}
				run := l.RunScenario(context.Background(), scs[i], dir)
				if keep := os.Getenv("SEAWARD_LAB_KEEP"); keep != "" && run.Snapshot != "" {
					os.WriteFile(filepath.Join(keep, scs[i].Name+".snapshot"), []byte(run.Snapshot), 0o644)
				}
				reps[i] = Judge(run, record, EnginePredictor)
				// The scan is held against the kernel too: a port the kernel answers on has to
				// be a port the scan asks about by itself.
				if run.Err == nil && !record {
					missed, err := Unasked(run.Snapshot, scs[i].Probes, run.Reals)
					for _, m := range missed {
						unasked[i] += fmt.Sprintf("\n  %s: %s", scs[i].Name, m)
					}
					if err != nil {
						unasked[i] += fmt.Sprintf("\n  %s: %v", scs[i].Name, err)
					}
				}
			}
		}()
	}
	for i := range scs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	mode := "compare"
	if record {
		mode = "record"
	}
	var slowest time.Duration
	var maxMS int64
	for _, r := range reps {
		slowest = max(slowest, r.Run.Elapsed)
		for _, v := range r.Verdicts {
			if v.Real.Outcome != OutSilent {
				maxMS = max(maxMS, v.Real.MS)
			}
		}
		if record || testing.Verbose() && r.Failed() {
			t.Logf("%s (%s, %s)\n%s", r.Run.Scenario.Name, r.Run.Elapsed.Round(time.Millisecond), mode, FormatOutcomes(r))
		}
		if r.Failed() && r.Run.Counters != "" {
			t.Logf("%s kernel counters: %s", r.Run.Scenario.Name, r.Run.Counters)
		}
		// The table below has room for the first line of a failure only; the rest, what the
		// scenario's script printed before it gave up, says which rule the kernel would not load.
		if r.Err != nil && testing.Verbose() {
			t.Logf("%s failed: %v", r.Run.Scenario.Name, r.Err)
		}
	}
	sum := Summarize(reps, mode, seed)
	sum.Seconds = time.Since(start).Seconds()
	// The counts stand on a line of their own: they are the same on every run and on every
	// machine, so they can be quoted (the README's pictures do). How long it took is not, and is
	// said in a second line short enough to stay one line in a terminal: go test prints the
	// whole run's time itself, and the summary file has it.
	t.Logf("%d scenarios, %d random rulesets, %d probes, %d wants matched, %d want mismatches, %d disagreements, %d undecided, %d failed runs",
		sum.Scenarios, sum.Rulesets, sum.Probes, sum.WantMatched, sum.WantMismatches, sum.Disagreements, sum.Undecided, sum.FailedRuns)
	t.Logf("slowest scenario %s, answer %d ms", slowest.Round(time.Millisecond), maxMS)
	if p := os.Getenv("SEAWARD_LAB_SUMMARY"); p != "" {
		if err := WriteSummary(p, sum); err != nil {
			t.Error(err)
		}
	}
	if missed := strings.Join(unasked, ""); missed != "" {
		t.Errorf("ports the kernel answers on and a scan does not account for:%s", missed)
	}
	if table := FormatTable(reps); table != "" {
		t.Errorf("problems:\n%s", table)
		for _, r := range reps {
			if !r.Failed() || r.Run.Scenario.File != "" || r.Err != nil {
				continue
			}
			wants := map[int]Outcome{}
			for _, v := range r.Verdicts {
				wants[v.Index] = v.Real.Outcome
			}
			t.Logf("random ruleset %s (replay with SEAWARD_LAB_SEED=%d SEAWARD_LAB_ONLY='^%s$'); as a scenario file with the kernel's outcomes as wants:\n%s",
				r.Run.Scenario.Name, seed, regexp.QuoteMeta(r.Run.Scenario.Name), r.Run.Scenario.Format(wants))
		}
		if seed != 0 && sum.Rulesets > 0 {
			t.Logf("random seed was %d", seed)
		}
	}
}
