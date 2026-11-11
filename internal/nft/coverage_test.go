package nft

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/rules"
)

// catchAll are the sentences the reader falls back on for something it has never heard of.
var catchAll = []string{
	"something seaward does not understand",
	"is not one seaward understands",
	"not written the way nft writes",
}

func whys(r *rules.Rule) []string {
	var out []string
	for _, x := range r.Exprs {
		switch x := x.(type) {
		case *rules.Unknown:
			out = append(out, x.Why)
		case *rules.UnknownStmt:
			out = append(out, x.Why)
		}
	}
	return out
}

// TestFixturesHoldNothingUnheardOf reads every fixture from the nft listing alone, so that every
// rule in it is translated, and fails if any key of any expression was left unread without the
// reader having said what it is: an unread key shows up as one of the catch-all sentences. An
// unknown with a sentence of its own is fine; that is the reader knowing what it does not model.
func TestFixturesHoldNothingUnheardOf(t *testing.T) {
	for _, name := range fixtures {
		rs, err := ParseJSON(readFile(t, name+".json"), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n := 0
		for _, tb := range rs.Tables {
			for _, c := range tb.Chains {
				for _, r := range c.Rules {
					n++
					for _, why := range whys(r) {
						if why == "" {
							t.Errorf("%s: %s: an unknown with no sentence", name, r.Text)
						}
						for _, s := range catchAll {
							if strings.Contains(why, s) {
								t.Errorf("%s: %s: %s", name, r.Text, why)
							}
						}
					}
				}
			}
		}
		if n == 0 {
			t.Errorf("%s: no rules read", name)
		}
	}
}

const strayKey = "zz-not-an-nft-word"

// plant copies a node and adds a stray key to the n-th object under it, counting from 0 in a
// fixed order. It reports the path to that object, or "" when there are fewer objects.
func plant(n *node, counter *int, path string, where *string) *node {
	switch v := n.v.(type) {
	case *object:
		o := &object{m: make(map[string]*node, len(v.m)+1)}
		if *counter == 0 {
			o.m[strayKey] = &node{v: "x"}
			*where = path
		}
		*counter--
		for _, k := range v.keys() {
			o.m[k] = plant(v.m[k], counter, path+"/"+k, where)
		}
		return &node{v: o}
	case []*node:
		a := make([]*node, len(v))
		for i, x := range v {
			a[i] = plant(x, counter, path, where)
		}
		return &node{v: a}
	}
	return &node{v: n.v}
}

// unlooked are the only places where the reader does not look at the details, because whatever is
// there cannot change what happens to a first packet: a counter's numbers, a log's prefix, what a
// reject answers with, the element a rule adds to a set, the address source NAT rewrites to.
func unlooked(path string, plain []rules.Expr) bool {
	for _, p := range []string{
		"/counter", "/log", "/masquerade", "/snat", "/flow", "/dup", "/last", "/reject",
		"/ct helper", "/ct timeout", "/ct expectation",
		"/set/elem", "/set/data", "/map/elem", "/map/data", "/meter/key",
		"/set/stmt/counter", "/set/stmt/log", "/map/stmt/counter", "/meter/stmt/counter",
	} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	// A "mangle" that changes something seaward does not track (a TCP option, the DSCP bits, a
	// connection tracking setting) is a no-op whatever value it writes.
	if strings.HasPrefix(path, "/mangle") {
		for _, x := range plain {
			if _, ok := x.(*rules.Noop); !ok {
				return false
			}
		}
		return len(plain) > 0
	}
	return false
}

// TestNoKeyIsDroppedSilently plants a key the reader has never heard of into every object of every
// expression of every fixture, one at a time, and fails unless the rule then holds an unknown.
func TestNoKeyIsDroppedSilently(t *testing.T) {
	planted, exempt := 0, 0
	for _, name := range fixtures {
		p, err := read(readFile(t, name+".json"), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, tb := range p.tables {
			for _, cname := range tb.order {
				for ri, raw := range tb.chains[cname].raw {
					exprs := raw.obj().peek("expr").arr()
					for ei, e := range exprs {
						plain := p.rule(tb, ruleWith(raw, exprs, ei, e))[0].Exprs
						for k := 0; ; k++ {
							counter, where := k, "-"
							mutated := plant(e, &counter, "", &where)
							if where == "-" {
								break
							}
							planted++
							got := p.rule(tb, ruleWith(raw, exprs, ei, mutated))
							if hasUnknown(got[0].Exprs) {
								continue
							}
							if unlooked(where, plain) {
								exempt++
								continue
							}
							t.Errorf("%s: %s %s rule %d (%s): a stray key at %q went unnoticed", name, tb.name, cname, ri+1, ruleText(raw.obj(), tb.family), where)
						}
					}
				}
			}
		}
	}
	if planted < 1000 || exempt*4 > planted {
		t.Errorf("planted %d stray keys, %d of them where the reader does not look: the test is not testing much", planted, exempt)
	}
	t.Logf("planted %d stray keys; %d were in places the reader need not look", planted, exempt)
}

// ruleWith builds a fresh copy of a rule that holds one expression of it alone, so that an unknown
// in the result can only come from that expression. A verdict map reads differently when it is
// not the rule's last expression, so the copy keeps a trailing expression where the rule has one.
func ruleWith(raw *node, exprs []*node, i int, e *node) *node {
	zero := -1
	none := ""
	list := []*node{plant(e, &zero, "", &none)}
	if i < len(exprs)-1 {
		list = append(list, &node{v: &object{m: map[string]*node{"counter": {v: nil}}}})
	}
	o := &object{m: map[string]*node{"expr": {v: list}}}
	for _, k := range []string{"family", "table", "chain"} {
		if n := raw.obj().peek(k); n != nil {
			o.m[k] = &node{v: n.v}
		}
	}
	return &node{v: o}
}

// TestStrayKeyBecomesUnknown shows the two forms the catch-all takes.
func TestStrayKeyBecomesUnknown(t *testing.T) {
	doc := func(expr string) []byte {
		return []byte(fmt.Sprintf(`{"nftables":[{"table":{"family":"inet","name":"t"}},
			{"chain":{"family":"inet","table":"t","name":"c","type":"filter","hook":"input","prio":0,"policy":"accept"}},
			{"rule":{"family":"inet","table":"t","chain":"c","expr":[%s,{"accept":null}]}}]}`, expr))
	}
	for _, tc := range []struct{ expr, want string }{
		{`{"match":{"op":"==","left":{"meta":{"key":"l4proto","zz":1}},"right":"tcp"}}`, `UNKNOWN this rule holds something seaward does not understand (the word "zz" in its match)`},
		{`{"notrack":null,"zz":1}`, `UNKNOWN-STMT this rule holds something that is not written the way nft writes it`},
		{`{"zz":{"a":1}}`, `UNKNOWN-STMT the zz statement is not one seaward understands`},
		{`{"limit":{"rate":5,"per":"second","zz":true}}`, `UNKNOWN-STMT this rule holds something seaward does not understand (the word "zz" in its limit)`},
		{`"accept"`, `UNKNOWN-STMT this rule holds something that is not written the way nft writes it`},
	} {
		rs, err := ParseJSON(doc(tc.expr), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		r := rs.Tables[0].Chains["c"].Rules[0]
		found := false
		for _, x := range r.Exprs {
			found = found || dumpExpr(x) == tc.want
		}
		if !found {
			var got []string
			for _, x := range r.Exprs {
				got = append(got, dumpExpr(x))
			}
			t.Errorf("%s:\n  want %s\n  got  %s", tc.expr, tc.want, strings.Join(got, "\n       "))
		}
	}
}
