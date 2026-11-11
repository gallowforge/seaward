package nft

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/rules"
)

// notListings are documents ParseJSON must refuse: they are not JSON, or not a listing.
var notListings = []string{
	``, ` `, `nft: command not found`, `{`, `[]`, `null`, `5`, `"nftables"`, `{}`,
	`{"nftables": null}`, `{"nftables": {}}`, `{"nftables": "x"}`, `{"nftables": []} trailing`,
	`{"nftables": []}{"nftables": []}`,
}

// oddListings are JSON of the right outer shape with everything inside wrong. None is an error:
// what cannot be read becomes a note or an unknown.
var oddListings = []string{
	`{"nftables": []}`,
	`{"nftables": [null, 5, "x", [], {}, {"rule": null}, {"table": null}, {"chain": 7}, {"set": []}, {"map": "m"}]}`,
	`{"nftables": [{"table": {"family": "ip"}}, {"table": {"name": "t"}}, {"table": {"family": 4, "name": 5}}]}`,
	`{"nftables": [{"rule": {"family": "ip", "table": "nowhere", "chain": "c", "expr": [{"accept": null}]}}]}`,
	`{"nftables": [{"table": {"family": "ip", "name": "t"}}, {"rule": {"family": "ip", "table": "t", "chain": "nowhere", "expr": [{"accept": null}]}}]}`,
	`{"nftables": [{"table": {"family": "ip", "name": "t"}}, {"chain": {"family": "ip", "table": "t", "name": "c", "hook": "input", "prio": "high", "policy": 3, "type": []}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c"}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": null}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": "accept"}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "comment": 5, "expr": [null, 5, "accept", [], {}, {"a": 1, "b": 2}]}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": [{"match": null}, {"match": []}, {"match": {"op": "==", "left": null, "right": null}},
	    {"match": {"op": 5, "left": {"payload": null}, "right": {"set": null}}}, {"match": {"op": "in", "left": {"concat": null}, "right": "@"}},
	    {"match": {"op": "==", "left": {"concat": [{"payload": {"protocol": "ip", "field": "saddr"}}, null]}, "right": {"set": [{"concat": ["x"]}, {"concat": null}, 5]}}},
	    {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": [{"range": [1]}, {"range": "x"}, {"prefix": {"addr": 5, "len": "x"}}, {"prefix": null}]}}},
	    {"match": {"op": "==", "left": {"&": [{"payload": {"protocol": "tcp", "field": "flags"}}]}, "right": {"|": null}}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "198.51.100.0", "len": 900}}}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "198.51.100.0", "len": -1}}}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 99999999999999999999}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": -1}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1.5}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"range": [90, 80]}}},
	    {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": ["new", 5, null, "nonsense"]}},
	    {"match": {"op": "==", "left": {"fib": {"result": "type", "flags": "daddr"}}, "right": 5}},
	    {"match": {"op": "==", "left": {"fib": null}, "right": "local"}}]}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": [{"vmap": null}, {"vmap": []}, {"vmap": {"key": null, "data": null}},
	    {"vmap": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": {"set": [[1], [1, 2, 3], [1, {"jump": null}], [1, {"jump": {"target": 5}}], null]}}},
	    {"vmap": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": "@"}},
	    {"vmap": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": "@missing"}}, {"counter": null}]}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": [{"jump": null}, {"goto": {"target": 5}}, {"jump": {}}, {"accept": 5}, {"continue": null}, {"return": {"x": 1}}]}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": [{"dnat": null}, {"dnat": 5}, {"dnat": {"addr": 5, "port": "x"}}, {"dnat": {"addr": {"map": null}}},
	    {"dnat": {"addr": {"map": {"key": null, "data": "@missing"}}}}, {"dnat": {"addr": {"range": ["x"]}, "port": {"range": [1, 2, 3]}}},
	    {"dnat": {"family": 5, "addr": "not an address", "port": 70000, "flags": 5, "type_flags": {}}}, {"redirect": {"port": {"range": null}}}, {"redirect": 5}]}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": [{"mangle": null}, {"mangle": {"key": null, "value": null}}, {"mangle": {"key": {"meta": null}, "value": {"|": [1]}}},
	    {"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"&": [{"^": [{"|": null}, 1]}, "x"]}}}, {"mangle": {"key": {"ct": {"key": "mark", "dir": 5}}, "value": []}}]}},
	  {"rule": {"family": "ip", "table": "t", "chain": "c", "expr": [{"limit": null}, {"limit": "@"}, {"limit": 5}, {"limit": {"rate": "x", "per": 5, "rate_unit": "furlongs", "burst": -1, "inv": "yes"}},
	    {"limit": {"rate": 99999999999999999999, "rate_unit": "bytes", "burst": 99999999999999999999, "burst_unit": "gbytes"}}, {"quota": null}, {"ct count": null}, {"ct count": {"val": "x", "inv": 5}},
	    {"reject": 5}, {"reject": {"type": 5, "expr": []}}, {"notrack": 5}, {"log": 5}, {"counter": "named"}, {"xt": null}, {"xt": {"type": 5, "name": []}}, {"xt": {"type": "target"}},
	    {"set": null}, {"set": {"op": 5, "elem": null, "set": 5, "stmt": [null, 5, {"limit": null}, {"set": {"stmt": [{"set": null}]}}]}}, {"map": {"stmt": "x"}}, {"meter": null},
	    {"meter": {"key": null, "stmt": null}}, {"meter": {"stmt": {"limit": {"rate": 1, "per": "second", "inv": true}}}}, {"queue": null}, {"tproxy": 5}, {"flow": null}, {"dup": []}, {"fwd": null},
	    {"synproxy": null}, {"last": null}, {"ct helper": 5}, {"zz": {"zz": [{"zz": null}]}}]}}]}`,
	`{"nftables": [{"table": {"family": "inet", "name": "t"}},
	  {"set": {"family": "inet", "table": "t", "name": "a"}}, {"set": {"family": "inet", "table": "t", "name": "b", "type": null, "elem": "x"}},
	  {"set": {"family": "inet", "table": "t", "name": "c", "type": "ipv4_addr", "flags": "interval", "elem": [null, 5, {"prefix": null}, {"range": ["198.51.100.9", "198.51.100.1"]}, {"elem": null}, {"elem": {"val": null}}, "2001:db8::1", "x"]}},
	  {"set": {"family": "inet", "table": "t", "name": "d", "type": ["ipv4_addr", 5, null, "inet_service"], "elem": [{"concat": ["198.51.100.1"]}, {"concat": ["198.51.100.1", 22, 5]}, {"concat": [5, "x"]}]}},
	  {"set": {"family": "inet", "table": "t", "name": "e", "type": {"typeof": {"payload": {"protocol": "ip", "field": "saddr"}}}, "timeout": "x", "flags": ["dynamic", 5, null]}},
	  {"map": {"family": "inet", "table": "t", "name": "f", "type": "inet_service", "map": "verdict", "elem": [[22], [22, null], [23, {"accept": null}, 5], [24, {"jump": {"target": "x"}}], ["*", {"drop": null}], 5, null]}},
	  {"map": {"family": "inet", "table": "t", "name": "g", "type": "inet_service", "map": ["ipv4_addr", "inet_service"], "elem": [[22, {"concat": ["198.51.100.1"]}], [23, 5]]}},
	  {"map": {"family": "inet", "table": "t", "name": "h", "map": 5}}, {"limit": null}, {"limit": {"family": "inet", "table": "t", "name": 5}}, {"limit": {"family": "inet", "table": "t", "name": "l", "inv": "x"}},
	  {"flowtable": null}, {"counter": 5}, {"quota": []}, {"ct helper": null}, {"zz": null},
	  {"chain": {"family": "inet", "table": "t", "name": "c", "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}},
	  {"chain": {"family": "inet", "table": "t", "name": "c", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
	  {"rule": {"family": "inet", "table": "t", "chain": "c", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@a"}},
	    {"match": {"op": "!=", "left": {"concat": [{"payload": {"protocol": "ip", "field": "saddr"}}, {"payload": {"protocol": "tcp", "field": "dport"}}, {"meta": {"key": "iifname"}}]}, "right": "@d"}},
	    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": "@f"}}, {"vmap": {"key": {"payload": {"protocol": "ip", "field": "saddr"}}, "data": "@f"}},
	    {"vmap": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": "@g"}}, {"dnat": {"addr": {"map": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": "@g"}}}},
	    {"dnat": {"addr": {"map": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": "@f"}}}}, {"limit": "l"}, {"limit": "nope"}]}}]}`,
	`{"nftables": [{"table": {"family": "netdev", "name": "t"}}, {"table": {"family": "bridge", "name": "t"}}, {"table": {"family": "arp", "name": "t"}}, {"table": {"family": "zz", "name": "t"}},
	  {"table": {"family": "inet", "name": "t", "flags": "dormant"}}, {"table": {"family": "inet", "name": "t", "flags": ["dormant", 5]}},
	  {"chain": {"family": "inet", "table": "t", "name": "in", "type": "filter", "hook": "ingress", "dev": "eth0", "prio": 0, "policy": "accept"}},
	  {"chain": {"family": "netdev", "table": "t", "name": "in", "type": "filter", "hook": "egress", "dev": ["eth0", 5], "prio": 0}},
	  {"rule": {"family": "inet", "table": "t", "chain": "in", "expr": [{"drop": null}]}}, {"rule": {"family": "netdev", "table": "t", "chain": "in", "expr": [{"drop": null}]}}]}`,
}

// checkShape fails when a result holds something the rest of seaward could trip over: a nil where
// a value belongs, a match with nothing to compare with, a verdict with no chain to go to.
func checkShape(t *testing.T, rs *rules.Ruleset) {
	t.Helper()
	if rs == nil || rs.Sets == nil {
		t.Fatal("no ruleset, or one without a set table")
	}
	for _, n := range rs.Notes {
		if strings.TrimSpace(n) == "" {
			t.Fatal("an empty note")
		}
	}
	elem := func(e rules.Elem, n int, where string) {
		if len(e) != n {
			t.Fatalf("%s: an element of %d parts for a key of %d", where, len(e), n)
		}
	}
	verdict := func(v rules.Verdict, where string) {
		if v.Kind < rules.Accept || v.Kind > rules.Goto {
			t.Fatalf("%s: a verdict of no kind (%d)", where, v.Kind)
		}
		if (v.Kind == rules.Jump || v.Kind == rules.Goto) != (v.Chain != "") {
			t.Fatalf("%s: verdict %d with chain %q", where, v.Kind, v.Chain)
		}
	}
	for key, s := range rs.Sets {
		if s == nil {
			t.Fatalf("set %q is nil", key)
		}
		if len(s.Verdicts) != 0 && len(s.Verdicts) != len(s.Elems) {
			t.Fatalf("set %q: %d verdicts for %d elements", key, len(s.Verdicts), len(s.Elems))
		}
		for _, v := range s.Verdicts {
			verdict(v, "set "+s.Name)
		}
		if s.Incomplete && s.Why == "" {
			t.Fatalf("set %q is incomplete and does not say why", key)
		}
	}
	for _, tb := range rs.Tables {
		if tb == nil || tb.Chains == nil {
			t.Fatal("a nil table, or one without a chain table")
		}
		if tb.Family != "ip" && tb.Family != "ip6" && tb.Family != "inet" && tb.Family != "netdev" {
			t.Fatalf("a table of family %q", tb.Family)
		}
		if tb.Origin == "" {
			t.Fatalf("table %s has no origin", tb.Name)
		}
		if len(tb.Order) != len(tb.Chains) {
			t.Fatalf("table %s: %d chains in order, %d in all", tb.Name, len(tb.Order), len(tb.Chains))
		}
		for _, name := range tb.Order {
			c := tb.Chains[name]
			if c == nil || c.Name != name {
				t.Fatalf("table %s: chain %q is missing or under the wrong name", tb.Name, name)
			}
			if c.Base && (c.Hook == "" || c.Type == "") {
				t.Fatalf("chain %s is a base chain without a hook or a type", name)
			}
			if c.Base && c.Policy != rules.Accept && c.Policy != rules.Drop {
				t.Fatalf("chain %s has the policy %d", name, c.Policy)
			}
			// An ingress chain is walked for the interfaces it names and for no other hook.
			if (c.Hook == rules.HookIngress) != (len(c.Devs) > 0) {
				t.Fatalf("chain %s: hook %q with the interfaces %q", name, c.Hook, c.Devs)
			}
			if tb.Family == "netdev" && c.Hook != "" && c.Hook != rules.HookIngress {
				t.Fatalf("chain %s of a netdev table is walked at hook %q", name, c.Hook)
			}
			for _, r := range c.Rules {
				if r == nil {
					t.Fatalf("chain %s holds a nil rule", name)
				}
				for _, x := range r.Exprs {
					where := "rule " + r.Text
					switch x := x.(type) {
					case *rules.Match:
						if x == nil || len(x.Key) == 0 || (x.Values == nil) == (x.SetRef == "") {
							t.Fatalf("%s: a match without a key, or without exactly one of values and a set", where)
						}
						if x.Values != nil {
							for _, e := range x.Values.Elems {
								elem(e, len(x.Key), where)
							}
						}
					case *rules.VerdictMap:
						if x == nil || len(x.Key) == 0 || (x.SetRef != "" && len(x.Entries) > 0) {
							t.Fatalf("%s: a verdict map without a key, or with both entries and a set", where)
						}
						for _, e := range x.Entries {
							elem(e.Key, len(x.Key), where)
							verdict(e.Verdict, where)
						}
					case *rules.Verdict:
						if x == nil {
							t.Fatalf("%s: a nil verdict", where)
						}
						verdict(*x, where)
					case *rules.Unknown:
						if x == nil || x.Why == "" {
							t.Fatalf("%s: an unknown that does not say why", where)
						}
					case *rules.UnknownStmt:
						if x == nil || x.Why == "" {
							t.Fatalf("%s: an unknown statement that does not say why", where)
						}
					case *rules.Always, *rules.Never, *rules.Noop, *rules.Notrack, *rules.DNAT, *rules.Redirect, *rules.SetMark, *rules.CopyMark:
					default:
						t.Fatalf("%s: an expression of the kind %T", where, x)
					}
				}
			}
		}
	}
}

// TestNotAListing: the only errors are for input that is not a listing at all.
func TestNotAListing(t *testing.T) {
	for _, s := range notListings {
		rs, err := ParseJSON([]byte(s), nil)
		if err == nil || rs != nil {
			t.Errorf("%q: want an error and no ruleset, got %v, %v", s, rs, err)
		} else if !strings.HasPrefix(err.Error(), "nft: ") {
			t.Errorf("%q: the error does not say where it comes from: %v", s, err)
		}
	}
}

// TestOddListingsDegrade: a listing with nonsense inside is read as far as it goes. parse is
// called directly, so that a panic shows here and is not caught by ParseJSON.
func TestOddListingsDegrade(t *testing.T) {
	h := labHost()
	shared := sharedOf(t, "mixed")
	for i, s := range oddListings {
		if !json.Valid([]byte(s)) {
			t.Fatalf("odd listing %d is not JSON; fix the test", i)
		}
		for _, sh := range [][]*rules.Table{nil, shared} {
			rs, err := parse([]byte(s), nil, sh)
			if err != nil {
				t.Errorf("odd listing %d: %v", i, err)
				continue
			}
			checkShape(t, rs)
			for _, dst := range []string{"203.0.113.10", "2001:db8:1::10", "172.17.0.2"} {
				src := "198.51.100.7"
				if strings.Contains(dst, ":") {
					src = "2001:db8:99::7"
				}
				engine.Run(rs, h, engine.Probe{Iif: "eth0", Src: addr(src), Dst: addr(dst), Proto: "tcp", Dport: 22})
			}
		}
	}
	// The big one must have turned its nonsense into unknowns, not into nothing.
	rs, _ := parse([]byte(oddListings[5]), nil, nil)
	unknowns, rulesN := 0, 0
	for _, tb := range rs.Tables {
		for _, c := range tb.Chains {
			for _, r := range c.Rules {
				rulesN++
				if hasUnknown(r.Exprs) {
					unknowns++
				}
			}
		}
	}
	if rulesN < 8 || unknowns < 8 {
		t.Errorf("%d rules, %d of them with an unknown; the nonsense went somewhere else:\n%s", rulesN, unknowns, dump(rs))
	}
}

// TestParseJSONCatchesAPanic: should the parser ever panic after all, ParseJSON turns it into an
// error. A nil receiver stands in for a bug.
func TestParseJSONCatchesAPanic(t *testing.T) {
	var rs *rules.Ruleset
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("a panic got out: %v", r)
			}
		}()
		rs, err = guarded(func() (*rules.Ruleset, error) {
			var p *parser
			return p.rs, nil
		})
	}()
	if rs != nil || err == nil || !strings.HasPrefix(err.Error(), "nft: ") {
		t.Errorf("got %v, %v", rs, err)
	}
}

// FuzzParseJSON feeds the parser whatever the fuzzer makes of real listings, cut down to one rule
// each so that a mutation lands inside a rule more often than not. The parser must not panic
// (parse is called directly: ParseJSON would hide it), must return either an error or a ruleset
// of sound shape, and that ruleset must be one the engine can walk.
func FuzzParseJSON(f *testing.F) {
	for _, s := range notListings {
		f.Add([]byte(s))
	}
	for _, s := range oddListings {
		f.Add([]byte(s))
	}
	for _, name := range fixtures {
		data := readFile(f, name+".json")
		f.Add(data)
		var top struct {
			Items []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(data, &top); err != nil {
			f.Fatal(err)
		}
		// One seed per rule, set and map: the tables and chains of the fixture, then that item.
		var frame []string
		for _, it := range top.Items {
			for k, v := range it {
				if k == "table" || k == "chain" {
					frame = append(frame, `{"`+k+`": `+string(v)+`}`)
				}
			}
		}
		for _, it := range top.Items {
			for k, v := range it {
				if k == "rule" || k == "set" || k == "map" {
					f.Add([]byte(`{"nftables": [` + strings.Join(frame, ", ") + `, {"` + k + `": ` + string(v) + `}]}`))
				}
			}
		}
	}
	shared := sharedOf(f, "mixed")
	h := labHost()
	probes := []engine.Probe{
		{Iif: "eth0", Src: addr("198.51.100.7"), Dst: addr("203.0.113.10"), Proto: "tcp", Dport: 22},
		{Iif: "eth0", Src: addr("2001:db8:99::7"), Dst: addr("2001:db8:1::10"), Proto: "udp", Dport: 53},
		{Iif: "eth1", Src: addr("10.20.0.5"), Dst: addr("172.17.0.2"), Proto: "tcp", Dport: 80},
	}
	// The text listing is read out of the same snapshot, and has to take any bytes as well.
	for _, name := range append([]string{"old-nft-ingress"}, fixtures...) {
		f.Add(readFile(f, name+".txt"))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for k, c := range textChains(string(data)) {
			if c.hook == "" || strings.Count(k, "\x00") < 2 {
				t.Fatalf("a base chain with no hook or no table: %q %+v", k, c)
			}
		}
		for _, sh := range [][]*rules.Table{nil, shared} {
			rs, err := parse(data, nil, sh)
			if err != nil {
				if rs != nil {
					t.Fatal("an error and a ruleset")
				}
				continue
			}
			checkShape(t, rs)
			for _, pr := range probes {
				engine.Run(rs, h, pr)
			}
		}
	})
}
