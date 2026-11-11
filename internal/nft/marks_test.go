package nft

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/rules"
)

// markTree is a mark value the way nft writes one in JSON: a number, the packet mark, the
// connection mark, or two of those joined by &, | or ^.
type markTree struct {
	op   string // "", "&", "|", "^"
	n    uint32 // op "": the number, unless src is set
	src  string // op "": "meta" or "ct"
	l, r *markTree
}

func (m *markTree) json() string {
	switch {
	case m.op != "":
		return fmt.Sprintf(`{%q: [%s, %s]}`, m.op, m.l.json(), m.r.json())
	case m.src != "":
		return fmt.Sprintf(`{%q: {"key": "mark"}}`, m.src)
	}
	return fmt.Sprint(m.n)
}

// eval works the value out the plain way, with no knowledge of how the reader folds it.
func (m *markTree) eval(mark, ctmark uint32) uint32 {
	switch m.op {
	case "&":
		return m.l.eval(mark, ctmark) & m.r.eval(mark, ctmark)
	case "|":
		return m.l.eval(mark, ctmark) | m.r.eval(mark, ctmark)
	case "^":
		return m.l.eval(mark, ctmark) ^ m.r.eval(mark, ctmark)
	}
	switch m.src {
	case "meta":
		return mark
	case "ct":
		return ctmark
	}
	return m.n
}

// someBits picks numbers that make mask mistakes show: single bits, bytes, everything, nothing.
func someBits(r *rand.Rand) uint32 {
	switch r.Intn(6) {
	case 0:
		return 0
	case 1:
		return ^uint32(0)
	case 2:
		return 1 << uint(r.Intn(32))
	case 3:
		return 0xff << uint(8*r.Intn(4))
	}
	return r.Uint32()
}

// randomMark builds a value around one mark (or none): the mark, then up to three operations with
// a number, the number on either side.
func randomMark(r *rand.Rand) *markTree {
	var m *markTree
	switch r.Intn(5) {
	case 0:
		m = &markTree{n: someBits(r)}
	case 1, 2:
		m = &markTree{src: "meta"}
	default:
		m = &markTree{src: "ct"}
	}
	for i := r.Intn(4); i > 0; i-- {
		k := &markTree{n: someBits(r)}
		op := []string{"&", "|", "^"}[r.Intn(3)]
		if r.Intn(4) == 0 {
			m = &markTree{op: op, l: k, r: m}
		} else {
			m = &markTree{op: op, l: m, r: k}
		}
	}
	return m
}

// TestMarkArithmeticAgainstTheEngine checks "meta mark set" and "ct mark set" end to end: the
// reader turns the statement into SetMark and CopyMark, the engine applies them with its own
// formulas, and the marks that come out must be the ones plain arithmetic gives. Each case is a
// chain that sets both marks to known values, runs the statement, and accepts only a packet whose
// two marks are exactly the expected ones.
func TestMarkArithmeticAgainstTheEngine(t *testing.T) {
	r := rand.New(rand.NewSource(20261111))
	h := labHost()
	pr := engine.Probe{Iif: "eth0", Src: addr("198.51.100.7"), Dst: addr("203.0.113.10"), Proto: "tcp", Dport: 22}
	set := func(dst, value string) string {
		return fmt.Sprintf(`{"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"mangle": {"key": {%q: {"key": "mark"}}, "value": %s}}]}}`, dst, value)
	}
	check := func(mark, ctmark uint32) string {
		return fmt.Sprintf(`{"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [`+
			`{"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": %d}}, `+
			`{"match": {"op": "==", "left": {"ct": {"key": "mark"}}, "right": %d}}, {"accept": null}]}}`, mark, ctmark)
	}
	shapes := map[string]int{}
	for i := 0; i < 2000; i++ {
		mark, ctmark := someBits(r), someBits(r)
		m := randomMark(r)
		dst := []string{"meta", "ct"}[r.Intn(2)]
		wantMark, wantCt := mark, ctmark
		if dst == "meta" {
			wantMark = m.eval(mark, ctmark)
		} else {
			wantCt = m.eval(mark, ctmark)
		}
		build := func(wm, wc uint32) *rules.Ruleset {
			rs, err := ParseJSON(doc(
				`{"table": {"family": "inet", "name": "t", "handle": 1}}`,
				`{"chain": {"family": "inet", "table": "t", "name": "in", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}`,
				set("meta", fmt.Sprint(mark)), set("ct", fmt.Sprint(ctmark)), set(dst, m.json()), check(wm, wc),
			), nil)
			if err != nil {
				t.Fatal(err)
			}
			return rs
		}
		rs := build(wantMark, wantCt)
		stmt := rs.Tables[0].Chains["in"].Rules[2]
		for _, x := range stmt.Exprs {
			shapes[fmt.Sprintf("%T", x)]++
		}
		what := fmt.Sprintf("%s (packet mark %#x, connection mark %#x)", stmt.Text, mark, ctmark)
		if got := engine.Run(rs, h, pr); got.Class != engine.Open {
			t.Errorf("%s: want packet mark %#x and connection mark %#x afterwards; the engine says %s %v\n  read as %s",
				what, wantMark, wantCt, got.Class, got.Unknowns, dumpRule(stmt))
			continue
		}
		// And the check itself can fail: one bit off in either mark and the packet is dropped.
		bit := uint32(1) << uint(r.Intn(32))
		if got := engine.Run(build(wantMark^bit, wantCt), h, pr); got.Class != engine.Filtered {
			t.Errorf("%s: a wrong packet mark was accepted too (%s)", what, got.Class)
		}
		if got := engine.Run(build(wantMark, wantCt^bit), h, pr); got.Class != engine.Filtered {
			t.Errorf("%s: a wrong connection mark was accepted too (%s)", what, got.Class)
		}
	}
	if shapes["*rules.SetMark"] < 500 || shapes["*rules.CopyMark"] < 300 || shapes["*rules.UnknownStmt"] != 0 {
		t.Errorf("the cases did not exercise both statements, or some were not understood: %v", shapes)
	}
}

func dumpRule(r *rules.Rule) string {
	s := ""
	for _, x := range r.Exprs {
		s += dumpExpr(x) + "; "
	}
	return s
}

// TestMarkFromTwoMarksIsUnknown: a value that mixes the packet mark with the connection mark is
// not one mask and one number; the reader has to say so, not guess.
func TestMarkFromTwoMarksIsUnknown(t *testing.T) {
	rs, err := ParseJSON(doc(
		`{"table": {"family": "inet", "name": "t", "handle": 1}}`,
		`{"chain": {"family": "inet", "table": "t", "name": "in", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}`,
		`{"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"|": [{"meta": {"key": "mark"}}, {"ct": {"key": "mark"}}]}}}]}}`,
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	x := rs.Tables[0].Chains["in"].Rules[0].Exprs
	if u, ok := x[len(x)-1].(*rules.UnknownStmt); !ok || u.Why != "the rule sets the packet mark from a value seaward cannot work out" {
		t.Errorf("read as %s", dumpRule(rs.Tables[0].Chains["in"].Rules[0]))
	}
}
