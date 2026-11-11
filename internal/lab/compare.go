//go:build linux

package lab

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

// Agrees says whether an engine class matches what the kernel really did. Closed and Rejected
// both look like "refused" from outside: something answered. Forwarded is not expected in the lab,
// whose probes all end on this machine or in its containers, so it never agrees.
func Agrees(c engine.Class, o Outcome) bool {
	switch c {
	case engine.Open:
		return o == OutOpen
	case engine.Closed, engine.Rejected:
		return o == OutRefused
	case engine.Filtered:
		return o == OutSilent
	}
	return false
}

// Predictor answers every probe of a scenario from its snapshot. The real one reads the bundle
// and asks the engine; tests use fakes.
type Predictor func(snap string, probes []Probe) ([]engine.Result, error)

// EnginePredictor parses the snapshot with the snapshot package and walks each probe with
// engine.Run. A panic in the engine becomes an error for that scenario instead of ending the run.
func EnginePredictor(snap string, probes []Probe) (res []engine.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("engine panic: %v", p)
		}
	}()
	b, err := snapshot.Parse(snap)
	if err != nil {
		return nil, fmt.Errorf("snapshot.Parse: %v", err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		return nil, fmt.Errorf("snapshot.Build: %v", err)
	}
	for _, p := range probes {
		res = append(res, engine.Run(rs, h, engine.Probe{Iif: p.Iif, Src: p.Src, Dst: p.Dst, Proto: p.Proto, Dport: p.Dport}))
	}
	return res, nil
}

// A Miss is a probe the kernel answered, sent to one of the machine's own addresses, that a scan
// of the same snapshot does not account for.
type Miss struct {
	Probe Probe
	// Said is the scan's finding for the port ("blocked", "closed" ...), or "" when the scan does
	// not ask about the port at all.
	Said string
	// Stand is set when the finding is that of another port: the port asked about in a long
	// range that the report lets stand for this one.
	Stand uint16
}

func (m Miss) String() string {
	switch {
	case m.Said == "":
		return fmt.Sprintf("the kernel answers %s, and a scan does not ask about %s port %d", m.Probe, m.Probe.Proto, m.Probe.Dport)
	case m.Stand != 0:
		return fmt.Sprintf("the kernel answers %s, and a scan lets port %d stand for it, which it calls %s", m.Probe, m.Stand, m.Said)
	}
	return fmt.Sprintf("the kernel answers %s, and a scan calls %s port %d %s", m.Probe, m.Probe.Proto, m.Probe.Dport, m.Said)
}

// Unasked holds a whole scan against the kernel. A probe names its port and its sender. A scan
// has to find the ports by itself, from the listeners and from the rules that send a packet
// somewhere else, and the senders from the conditions in the rules. So for every probe the
// kernel answered, the scan of the same snapshot must ask about that port (have a row for it, or
// a long range asked in part that holds it), and must not say of it that nobody gets through:
// its finding is reachable or undecided, never blocked, closed, dead, shadowed or local. In a
// range asked in part the report lets a port stand for the ports up to the next one asked, so
// the same is wanted of the port that stands for the probe's.
func Unasked(snap string, probes []Probe, reals map[int]Real) (missed []Miss, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("scan panic: %v", p)
		}
	}()
	b, err := snapshot.Parse(snap)
	if err != nil {
		return nil, fmt.Errorf("snapshot.Parse: %v", err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		return nil, fmt.Errorf("snapshot.Build: %v", err)
	}
	own := map[netip.Addr]bool{}
	for n, i := range h.Interfaces {
		// The lab's two outside interfaces are ends of veth pairs, which a scan takes for the way
		// to a container and asks nothing from. They stand for network cards here.
		if (i.Name == "eth0" || i.Name == "eth1") && i.Kind == "veth" {
			h.Interfaces[n].Kind = ""
		}
		for _, a := range i.Addrs {
			own[a.Addr()] = true
		}
	}
	type key struct {
		proto string
		port  uint16
	}
	rows := map[key]string{}
	for _, p := range scan.Run(rs, h).Ports {
		rows[key{p.Proto, p.Port}] = p.Finding
	}
	done := map[key]bool{}
	for i, p := range probes {
		k := key{p.Proto, p.Dport}
		if reals[i].Outcome != OutOpen || !own[p.Dst] || done[k] {
			continue
		}
		done[k] = true // a port is looked into, and said, once
		stopped := func(said string) bool {
			return said != scan.Exposed && said != scan.Open && said != scan.Limited && said != scan.Undecided
		}
		if said, asked := rows[k]; asked {
			if stopped(said) {
				missed = append(missed, Miss{Probe: p, Said: said})
			}
			continue
		}
		in := scan.One(rs, h, p.Proto, p.Dport)
		if len(in) == 0 {
			missed = append(missed, Miss{Probe: p})
			continue
		}
		if stopped(in[0].Finding) {
			missed = append(missed, Miss{Probe: p, Said: in[0].Finding})
			continue
		}
		// The row that stands for it in the report: the nearest port below that was asked.
		for port := p.Dport - 1; port > 0; port-- {
			if said, asked := rows[key{p.Proto, port}]; asked {
				if stopped(said) {
					missed = append(missed, Miss{Probe: p, Said: said, Stand: port})
				}
				break
			}
		}
	}
	return missed, nil
}

// Verdict is one probe: what the kernel did, what the engine said, and whether they fit.
type Verdict struct {
	Index  int
	Probe  Probe
	Real   Real
	Engine *engine.Result // nil in record mode or when the engine could not run
	// WantMismatch: the kernel did not do what the scenario author worked out. The scenario or
	// the lab is wrong (or the kernel surprised us); it is never the engine's fault.
	WantMismatch bool
	Disagree     bool // the engine's class does not fit the real outcome
	Undecided    bool // the engine said Undecided
	// UndecidedOK: Undecided was expected by the scenario, so it does not fail.
	UndecidedOK bool
}

// Report is the judgement of one scenario run.
type Report struct {
	Run      *Run
	Verdicts []Verdict
	// Err is a failure of the whole scenario: the script, the snapshot or the engine.
	Err error
}

// Failed says whether anything in the report fails the test.
func (r *Report) Failed() bool {
	if r.Err != nil {
		return true
	}
	for _, v := range r.Verdicts {
		if v.WantMismatch || v.Disagree || v.Undecided && !v.UndecidedOK {
			return true
		}
	}
	return false
}

// Judge compares a run with the scenario's wants and, unless record is set, with the engine.
func Judge(run *Run, record bool, predict Predictor) *Report {
	rep := &Report{Run: run}
	if run.Err != nil {
		rep.Err = run.Err
		return rep
	}
	sc := run.Scenario
	for i, p := range sc.Probes {
		got := run.Reals[i]
		v := Verdict{Index: i, Probe: p, Real: got}
		if got.Outcome == OutError {
			v.WantMismatch = true
		} else if p.Want != "" && p.Want != got.Outcome {
			v.WantMismatch = true
		}
		rep.Verdicts = append(rep.Verdicts, v)
	}
	if record {
		return rep
	}
	res, err := predict(run.Snapshot, sc.Probes)
	if err == nil && len(res) != len(sc.Probes) {
		err = fmt.Errorf("predictor gave %d results for %d probes", len(res), len(sc.Probes))
	}
	if err != nil {
		rep.Err = err
		return rep
	}
	for i := range rep.Verdicts {
		v := &rep.Verdicts[i]
		r := res[i]
		v.Engine = &r
		if r.Class == engine.Undecided {
			v.Undecided = true
			v.UndecidedOK = sc.ExpectUndecided || v.Probe.ExpectUndecided
			continue
		}
		v.Disagree = !Agrees(r.Class, v.Real.Outcome)
	}
	return rep
}

// Summary is the small JSON written to SEAWARD_LAB_SUMMARY.
type Summary struct {
	Mode           string  `json:"mode"` // "compare" or "record"
	Seed           uint64  `json:"seed"`
	Scenarios      int     `json:"scenarios"` // hand-written scenarios run
	Rulesets       int     `json:"rulesets"`  // random rulesets run
	Probes         int     `json:"probes_checked"`
	Disagreements  int     `json:"disagreements"`
	Undecided      int     `json:"undecided"`
	WantMatched    int     `json:"want_matched"`
	WantMismatches int     `json:"want_mismatches"`
	FailedRuns     int     `json:"failed_runs"`
	Seconds        float64 `json:"seconds"`
}

// Summarize counts the reports.
func Summarize(reps []*Report, mode string, seed uint64) Summary {
	s := Summary{Mode: mode, Seed: seed}
	for _, r := range reps {
		if r.Run.Scenario.File == "" {
			s.Rulesets++
		} else {
			s.Scenarios++
		}
		if r.Err != nil {
			s.FailedRuns++
		}
		for _, v := range r.Verdicts {
			s.Probes++
			if v.Disagree {
				s.Disagreements++
			}
			if v.Undecided {
				s.Undecided++
			}
			if v.WantMismatch {
				s.WantMismatches++
			} else if v.Probe.Want != "" {
				s.WantMatched++
			}
		}
	}
	return s
}

// WriteSummary writes the summary as JSON to path.
func WriteSummary(path string, s Summary) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// engineSaid is the engine's answer in a few words.
func engineSaid(v Verdict) string {
	if v.Engine == nil {
		return "-"
	}
	return v.Engine.Class.String()
}

// FormatTable prints every problem in the reports: an aligned table with one row per probe, then
// the engine's steps for each row, so the reason is on screen without widening the table.
func FormatTable(reps []*Report) string {
	var b, steps strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SCENARIO\tPROBE\tENGINE SAID\tKERNEL DID\tPROBLEM")
	rows := 0
	for _, r := range reps {
		name := r.Run.Scenario.Name
		if r.Err != nil {
			fmt.Fprintf(tw, "%s\t-\t-\t-\t%s\n", name, firstLine(r.Err.Error()))
			rows++
			continue
		}
		for _, v := range r.Verdicts {
			var why []string
			if v.WantMismatch {
				w := string(v.Probe.Want)
				if v.Real.Outcome == OutError {
					w = "a usable probe (" + v.Real.Detail + ")"
				}
				why = append(why, "the scenario wants "+w)
			}
			if v.Disagree {
				why = append(why, "engine and kernel disagree")
			}
			if v.Undecided && !v.UndecidedOK {
				why = append(why, "undecided: "+strings.Join(v.Engine.Unknowns, "; "))
			}
			if len(why) == 0 {
				continue
			}
			rows++
			did := string(v.Real.Outcome)
			if v.Real.Detail != "" {
				did += " (" + v.Real.Detail + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, v.Probe, engineSaid(v), did, strings.Join(why, ", "))
			if v.Engine != nil && len(v.Engine.Steps) > 0 {
				fmt.Fprintf(&steps, "%s  %s  (engine said %s, kernel did %s)\n", name, v.Probe, engineSaid(v), v.Real.Outcome)
				for _, st := range v.Engine.Steps {
					fmt.Fprintf(&steps, "    %s\n", formatStep(st))
				}
			}
		}
	}
	tw.Flush()
	if rows == 0 {
		return ""
	}
	if steps.Len() > 0 {
		b.WriteString("\nThe engine's steps for each row:\n")
		b.WriteString(steps.String())
	}
	return b.String()
}

func formatStep(st engine.Step) string {
	where := st.Hook
	if st.Table != "" {
		where += " " + st.Family + "/" + st.Table + "/" + st.Chain
	}
	s := fmt.Sprintf("%s [%s] %s", st.Kind, where, st.Effect)
	if st.Rule != "" {
		s += ": " + st.Rule
	}
	if st.Decisive {
		s += " (decisive)"
	}
	return s
}

// FormatOutcomes prints every probe's real outcome, for record mode.
func FormatOutcomes(r *Report) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	for _, v := range r.Verdicts {
		mark := "ok"
		if v.WantMismatch {
			mark = "WANT " + string(v.Probe.Want)
		} else if v.Probe.Want == "" {
			mark = ""
		}
		detail := v.Real.Detail
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%dms\t%s\n", v.Probe, v.Real.Outcome, detail, v.Real.MS, mark)
	}
	tw.Flush()
	return b.String()
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
