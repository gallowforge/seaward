package nft

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// The tests of this file are about the chains that hook in outside the five hooks of the IP path:
// an ingress chain, which is walked, and everything else (an egress chain, a bridge table, a hook
// nobody knows), which is not and goes into Ruleset.Unfollowed or into a note. Their listings are
// put together from the items below, written the way "nft -j list ruleset" writes them.

// tbl is a table, with its flags when it has any.
func tbl(family, name string, flags ...string) string {
	f := ""
	if len(flags) > 0 {
		f = fmt.Sprintf(`, "flags": ["%s"]`, strings.Join(flags, `", "`))
	}
	return fmt.Sprintf(`{"table": {"family": %q, "name": %q%s}}`, family, name, f)
}

// hooked is a base chain: where it hooks in, at what priority, its policy and the interfaces it
// is attached to. nft writes one interface as a bare string and several as a list.
func hooked(family, table, name, hook string, prio int, policy string, devs ...string) string {
	dev := ""
	switch len(devs) {
	case 0:
	case 1:
		dev = fmt.Sprintf(`"dev": %q, `, devs[0])
	default:
		dev = fmt.Sprintf(`"dev": ["%s"], `, strings.Join(devs, `", "`))
	}
	return fmt.Sprintf(`{"chain": {"family": %q, "table": %q, "name": %q, %s"type": "filter", "hook": %q, "prio": %d, "policy": %q}}`,
		family, table, name, dev, hook, prio, policy)
}

// unhooked is a chain with no hook: only a jump reaches it.
func unhooked(family, table, name string) string {
	return fmt.Sprintf(`{"chain": {"family": %q, "table": %q, "name": %q}}`, family, table, name)
}

// ruleIn is a rule of a chain, made of the expressions given.
func ruleIn(family, table, chain string, exprs ...string) string {
	return fmt.Sprintf(`{"rule": {"family": %q, "table": %q, "chain": %q, "expr": [%s]}}`, family, table, chain, strings.Join(exprs, ", "))
}

const (
	xDrop   = `{"drop": null}`
	xAccept = `{"accept": null}`
	xFrom   = `{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "198.51.100.7"}}`
	xMark   = `{"mangle": {"key": {"meta": {"key": "mark"}}, "value": 1}}`
)

// toPort is "tcp dport 22" or "udp dport { 53, 123 }".
func toPort(proto string, ports ...int) string {
	right := fmt.Sprint(ports[0])
	if len(ports) > 1 {
		var list []string
		for _, p := range ports {
			list = append(list, fmt.Sprint(p))
		}
		right = `{"set": [` + strings.Join(list, ", ") + `]}`
	}
	return fmt.Sprintf(`{"match": {"op": "==", "left": {"payload": {"protocol": %q, "field": "dport"}}, "right": %s}}`, proto, right)
}

func jumpTo(chain string) string { return fmt.Sprintf(`{"jump": {"target": %q}}`, chain) }

// listing reads a document made of the items given, with no iptables-save beside it.
func listing(t *testing.T, items ...string) *rules.Ruleset {
	t.Helper()
	rs, err := ParseJSON(doc(items...), nil)
	if err != nil {
		t.Fatal(err)
	}
	checkShape(t, rs)
	return rs
}

// outside is everything the reader says about what it left out of the walked path, the way dump
// prints it: its notes, then the chains that were not followed.
func outside(rs *rules.Ruleset) string {
	return dump(&rules.Ruleset{Notes: rs.Notes, Unfollowed: rs.Unfollowed})
}

// entryFor finds the Unfollowed entry about a chain, named as its sentence names it: "c of table
// netdev nd".
func entryFor(t *testing.T, rs *rules.Ruleset, chain string) rules.Unfollowed {
	t.Helper()
	for _, u := range rs.Unfollowed {
		if strings.HasPrefix(u.Why, "the chain "+chain+" ") {
			return u
		}
	}
	t.Fatalf("nothing about the chain %s in:\n%s", chain, outside(rs))
	return rules.Unfollowed{}
}

// How the sentence about a walked ingress chain ends, and the note about one that drops by default.
const (
	underneath = ", underneath the bridge, bond or VLAN interface they arrive on, where seaward does not follow them"
	arpNote    = ": seaward follows the IP packet through it and takes it that the address lookups before it (ARP) get through"
)

// TestIngressChainIsWalked: an ingress chain that names its interfaces is a base chain of its
// table like any other, in a netdev table and in an inet table alike, whatever its policy. When it
// can stop a packet it is also listed as walked-but-unfollowed, for the packets that pass its
// interfaces one layer down. One with no rules and a policy of accept can stop nothing and is
// listed nowhere.
func TestIngressChainIsWalked(t *testing.T) {
	for _, tc := range []struct {
		name, family, policy string
		devs                 []string
		rule                 bool
		want                 string // what outside prints
	}{
		{"one interface", "netdev", "accept", []string{"eth0"}, true,
			"unfollowed: in eth0 only-stops walked: the chain ingress of table netdev early acts on packets as they pass eth0" + underneath + "\n"},
		{"two interfaces", "netdev", "accept", []string{"eth0", "eth1"}, true,
			"unfollowed: in eth0,eth1 only-stops walked: the chain ingress of table netdev early acts on packets as they pass eth0 and eth1" + underneath + "\n"},
		{"three interfaces", "netdev", "accept", []string{"eth0", "eth1", "bond0"}, true,
			"unfollowed: in eth0,eth1,bond0 only-stops walked: the chain ingress of table netdev early acts on packets as they pass eth0, eth1 and bond0" + underneath + "\n"},
		{"every interface of a name", "netdev", "accept", []string{"eth*"}, true,
			"unfollowed: in eth* only-stops walked: the chain ingress of table netdev early acts on packets as they pass eth*" + underneath + "\n"},
		{"an inet table", "inet", "accept", []string{"eth0"}, true,
			"unfollowed: in eth0 only-stops walked: the chain ingress of table inet early acts on packets as they pass eth0" + underneath + "\n"},
		{"no rules", "netdev", "accept", []string{"eth0"}, false, ""},
		{"no rules, an inet table", "inet", "accept", []string{"eth0", "eth1"}, false, ""},
		// A netdev chain that drops by default is walked all the same. It also drops the frames
		// that are not IP packets, which a note says.
		{"drop by default", "netdev", "drop", []string{"eth0"}, true,
			"note: the chain ingress of table netdev early drops by default every frame that arrives on eth0" + arpNote + "\n" +
				"unfollowed: in eth0 only-stops walked: the chain ingress of table netdev early acts on packets as they pass eth0" + underneath + "\n"},
		{"drop by default, no rules", "netdev", "drop", []string{"eth0", "eth1"}, false,
			"note: the chain ingress of table netdev early drops by default every frame that arrives on eth0 and eth1" + arpNote + "\n" +
				"unfollowed: in eth0,eth1 only-stops walked: the chain ingress of table netdev early acts on packets as they pass eth0 and eth1" + underneath + "\n"},
		// An inet chain only ever sees IP packets: no note.
		{"drop by default, an inet table", "inet", "drop", []string{"eth0"}, false,
			"unfollowed: in eth0 only-stops walked: the chain ingress of table inet early acts on packets as they pass eth0" + underneath + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := []string{tbl(tc.family, "early"), hooked(tc.family, "early", "ingress", "ingress", -500, tc.policy, tc.devs...)}
			nRules, policy := 0, rules.Accept
			if tc.rule {
				items = append(items, ruleIn(tc.family, "early", "ingress", xFrom, xDrop))
				nRules = 1
			}
			if tc.policy == "drop" {
				policy = rules.Drop
			}
			rs := listing(t, items...)
			c := tableOf(t, rs, tc.family, "early").Chains["ingress"]
			if c == nil || !c.Base || c.Hook != rules.HookIngress || c.Type != "filter" || c.Priority != -500 || c.Policy != policy || len(c.Rules) != nRules {
				t.Fatalf("the chain was not read as a running base chain on the ingress hook: %+v", c)
			}
			if !reflect.DeepEqual(c.Devs, tc.devs) {
				t.Errorf("the chain is attached to %q, want %q", c.Devs, tc.devs)
			}
			if got := outside(rs); got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// TestChainsOutsideTheWalkedPath: a base chain that hooks in anywhere else is not walked. One
// that can stop or change a packet seaward decides about becomes an Unfollowed entry that says
// which packets pass it; one that cannot (no rules, no interface, frames that are only switched)
// becomes a note.
func TestChainsOutsideTheWalkedPath(t *testing.T) {
	const (
		noRules  = " was left out: it has no rules and lets everything pass\n"
		noDevice = " was left out: it is attached to no interface, so it sees no packets\n"
		nowhere  = ", a point of the packet path seaward does not know\n"
		brIn     = "unfollowed: bridge-in only-stops: the chain c of table bridge br acts on frames as they arrive through a bridge, before the packet path seaward follows\n"
		brOut    = "unfollowed: bridge-out only-stops: the chain c of table bridge br acts on frames as they leave through a bridge, after the packet path seaward follows\n"
	)
	type left struct {
		name  string
		items []string
		want  string // what outside prints
	}
	// one is a table with the one base chain c, and a rule in it when asked for.
	one := func(family, table, hook, policy string, rule bool, devs ...string) []string {
		items := []string{tbl(family, table), hooked(family, table, "c", hook, 0, policy, devs...)}
		if rule {
			items = append(items, ruleIn(family, table, "c", xFrom, xDrop))
		}
		return items
	}
	cases := []left{
		// An egress chain sees what leaves through its interfaces.
		{"egress", one("netdev", "nd", "egress", "accept", true, "eth0"),
			"unfollowed: out eth0 only-stops: the chain c of table netdev nd acts on packets as they leave through eth0, after the packet path seaward follows\n"},
		{"egress, two interfaces", one("netdev", "nd", "egress", "accept", true, "eth0", "eth1"),
			"unfollowed: out eth0,eth1 only-stops: the chain c of table netdev nd acts on packets as they leave through eth0 and eth1, after the packet path seaward follows\n"},
		{"egress, drop by default and no rules", one("netdev", "nd", "egress", "drop", false, "eth0"),
			"unfollowed: out eth0 only-stops: the chain c of table netdev nd acts on packets as they leave through eth0, after the packet path seaward follows\n"},
		{"egress, no rules", one("netdev", "nd", "egress", "accept", false, "eth0"),
			"note: the chain c of table netdev nd" + noRules},
		{"egress, no interface", one("netdev", "nd", "egress", "accept", true),
			"note: the chain c of table netdev nd" + noDevice},

		// An ingress chain that names no interface is attached to nothing.
		{"ingress, no interface", one("netdev", "nd", "ingress", "accept", true),
			"note: the chain c of table netdev nd" + noDevice},
		{"ingress, no interface, an inet table that drops by default", one("inet", "t", "ingress", "drop", false),
			"note: the chain c of table inet t" + noDevice},
		{"ingress, no interface and no rules", one("netdev", "nd", "ingress", "accept", false),
			"note: the chain c of table netdev nd" + noRules},

		// A hook that is not known: every packet may pass the chain, and a netdev chain still sees
		// its own interfaces only.
		{"a hook nobody knows", one("ip", "t", "zz", "accept", true),
			"unfollowed: in * only-stops: the chain c of table ip t hooks in at zz" + nowhere},
		{"a hook nobody knows, a netdev table", one("netdev", "nd", "zz", "accept", true, "eth0", "eth1"),
			"unfollowed: in eth0,eth1 out eth0,eth1 only-stops: the chain c of table netdev nd hooks in at zz" + nowhere},
		// Only a netdev chain is taken at its word about its interfaces.
		{"a hook nobody knows, an inet table and an interface", one("inet", "t", "zz", "accept", true, "eth0"),
			"unfollowed: in * only-stops: the chain c of table inet t hooks in at zz" + nowhere},
		{"a hook nobody knows, no rules", one("ip", "t", "zz", "accept", false),
			"note: the chain c of table ip t" + noRules},
		{"a hook of the IP path in a netdev table, no interface", one("netdev", "nd", "input", "accept", true),
			"unfollowed: in * only-stops: the chain c of table netdev nd hooks in at input" + nowhere},
		{"a hook of the IP path in a netdev table, no rules", one("netdev", "nd", "input", "accept", false, "eth0"),
			"note: the chain c of table netdev nd" + noRules},

		// A bridge table: what arrives through a bridge, what leaves through one, and the frames
		// that are only switched between its ports, which never become packets seaward walks.
		{"bridge prerouting", one("bridge", "br", "prerouting", "accept", true), brIn},
		{"bridge input", one("bridge", "br", "input", "accept", true), brIn},
		{"bridge output", one("bridge", "br", "output", "accept", true), brOut},
		{"bridge postrouting", one("bridge", "br", "postrouting", "accept", true), brOut},
		{"bridge forward", one("bridge", "br", "forward", "accept", true),
			"note: the chain c of table bridge br was left out: it filters frames switched between the ports of a bridge, which never enter the packet path seaward follows\n"},
		{"bridge, a hook nobody knows", one("bridge", "br", "zz", "accept", true),
			"unfollowed: bridge-in bridge-out only-stops: the chain c of table bridge br hooks in at zz" + nowhere},
		{"bridge prerouting, drop by default and no rules", one("bridge", "br", "prerouting", "drop", false), brIn},
		{"bridge prerouting, no rules", one("bridge", "br", "prerouting", "accept", false),
			"note: the chain c of table bridge br" + noRules},
		{"bridge forward, no rules", one("bridge", "br", "forward", "accept", false),
			"note: the chain c of table bridge br" + noRules},
		// Only a base chain is ever called by the kernel.
		{"bridge, a chain with no hook", []string{tbl("bridge", "br"), unhooked("bridge", "br", "c"), ruleIn("bridge", "br", "c", xDrop)}, ""},
		// Nor are the sets and limits of a bridge table read: no walked rule can use them.
		{"bridge, a set and a limit", []string{tbl("bridge", "br"),
			`{"set": {"family": "bridge", "table": "br", "name": "seen", "type": "ether_addr"}}`,
			`{"limit": {"family": "bridge", "table": "br", "name": "slow", "rate": 5, "per": "second"}}`,
			hooked("bridge", "br", "c", "prerouting", 0, "accept"),
			ruleIn("bridge", "br", "c", `{"set": {"op": "add", "elem": {"payload": {"protocol": "ether", "field": "saddr"}}, "set": "@seen"}}`, `{"limit": "slow"}`, xDrop)}, brIn},
	}
	// A netdev table has none of the five hooks of the IP path.
	for _, hook := range []string{rules.HookPrerouting, rules.HookInput, rules.HookForward, rules.HookOutput, rules.HookPostrouting} {
		cases = append(cases, left{"hook " + hook + " in a netdev table", one("netdev", "nd", hook, "accept", true, "eth0"),
			"unfollowed: in eth0 out eth0 only-stops: the chain c of table netdev nd hooks in at " + hook + nowhere})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := listing(t, tc.items...)
			if got := outside(rs); got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
			// Nothing of it is walked: no table holds the chain, and a bridge table is no table
			// of the result at all.
			for _, tb := range rs.Tables {
				if tb.Family == "bridge" || len(tb.Chains) != 0 || len(tb.Order) != 0 {
					t.Errorf("the result holds chains of table %s %s:\n%s", tb.Family, tb.Name, dump(rs))
				}
			}
			if len(rs.Sets) != 0 {
				t.Errorf("the result holds sets:\n%s", dump(rs))
			}
		})
	}
}

// TestOnlyStops: an entry says whether its chain can do no more than drop a packet or let it
// pass. Looking, counting, logging and the plain verdicts are that. Anything that answers the
// sender, changes the packet or sends it elsewhere is not, and neither is a rule that hands the
// packet on (a jump, a verdict map) or fills a set: where that leads is not looked into. A bridge
// table is the exception for those: every rule of it is looked at, wherever a jump leads.
func TestOnlyStops(t *testing.T) {
	places := []struct {
		name   string
		bridge bool
		walked bool
		items  func(exprs []string) []string
	}{
		{"an egress chain", false, false, func(x []string) []string {
			return []string{tbl("netdev", "nd"), hooked("netdev", "nd", "c", "egress", 0, "accept", "eth0"),
				unhooked("netdev", "nd", "side"), ruleIn("netdev", "nd", "side", xDrop), ruleIn("netdev", "nd", "c", x...)}
		}},
		{"an ingress chain", false, true, func(x []string) []string {
			return []string{tbl("netdev", "nd"), hooked("netdev", "nd", "c", "ingress", 0, "accept", "eth0"),
				unhooked("netdev", "nd", "side"), ruleIn("netdev", "nd", "side", xDrop), ruleIn("netdev", "nd", "c", x...)}
		}},
		{"an ingress chain of an inet table", false, true, func(x []string) []string {
			return []string{tbl("inet", "t"), hooked("inet", "t", "c", "ingress", 0, "accept", "eth0"),
				unhooked("inet", "t", "side"), ruleIn("inet", "t", "side", xDrop), ruleIn("inet", "t", "c", x...)}
		}},
		{"a bridge chain", true, false, func(x []string) []string {
			return []string{tbl("bridge", "br"), hooked("bridge", "br", "c", "prerouting", 0, "accept"),
				unhooked("bridge", "br", "side"), ruleIn("bridge", "br", "side", xDrop), ruleIn("bridge", "br", "c", x...)}
		}},
	}
	for _, tc := range []struct {
		name  string
		exprs []string
		stops bool // in a netdev or inet table
		local bool // in a bridge table
	}{
		{"drop", []string{xDrop}, true, true},
		{"a condition and a drop", []string{xFrom, xDrop}, true, true},
		{"count, log, limit, accept", []string{toPort("tcp", 22), `{"counter": {"packets": 0, "bytes": 0}}`, `{"log": {"prefix": "seen "}}`,
			`{"limit": {"rate": 5, "burst": 5, "per": "second"}}`, xAccept}, true, true},
		{"quota", []string{`{"quota": {"val": 10, "val_unit": "mbytes"}}`, xDrop}, true, true},
		{"return", []string{`{"return": null}`}, true, true},
		{"continue", []string{`{"continue": null}`}, true, true},
		{"nothing at all", nil, true, true},

		// The sender is answered.
		{"reject", []string{`{"reject": null}`}, false, false},
		{"reject with a reset", []string{toPort("tcp", 22), `{"reject": {"type": "tcp reset"}}`}, false, false},
		// The packet is changed.
		{"a header rewritten", []string{`{"mangle": {"key": {"payload": {"protocol": "ip", "field": "dscp"}}, "value": "cs1"}}`}, false, false},
		{"an address rewritten", []string{`{"mangle": {"key": {"payload": {"protocol": "ip", "field": "daddr"}}, "value": "192.0.2.9"}}`}, false, false},
		{"a mark set", []string{xFrom, xMark}, false, false},
		{"notrack", []string{`{"notrack": null}`}, false, false},
		// The packet, or a copy of it, is sent elsewhere.
		{"fwd", []string{`{"fwd": {"dev": "eth1"}}`}, false, false},
		{"dup", []string{`{"dup": {"dev": "eth1"}}`, xDrop}, false, false},
		// Nobody knows what it does.
		{"a statement nobody knows", []string{`{"zz": null}`}, false, false},
		{"two words in one expression", []string{`{"drop": null, "zz": 1}`}, false, false},
		{"not an expression", []string{`"drop"`}, false, false},

		// Handed on, or remembered in a set.
		{"jump", []string{toPort("tcp", 80), jumpTo("side")}, false, true},
		{"goto", []string{`{"goto": {"target": "side"}}`}, false, true},
		{"a verdict map", []string{`{"vmap": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": {"set": [[22, {"jump": {"target": "side"}}]]}}}`}, false, true},
		{"adding to a set", []string{`{"set": {"op": "add", "elem": {"payload": {"protocol": "ip", "field": "saddr"}}, "set": "@seen"}}`, xDrop}, false, true},
	} {
		for _, pl := range places {
			rs := listing(t, pl.items(tc.exprs)...)
			if len(rs.Unfollowed) != 1 {
				t.Errorf("%s in %s: want one entry, got:\n%s", tc.name, pl.name, outside(rs))
				continue
			}
			want := tc.stops
			if pl.bridge {
				want = tc.local
			}
			if u := rs.Unfollowed[0]; u.OnlyStops != want || u.Walked != pl.walked {
				t.Errorf("%s in %s: only stops %v, walked %v; want %v, %v", tc.name, pl.name, u.OnlyStops, u.Walked, want, pl.walked)
			}
		}
	}
}

// TestOnlyStopsWhoseRulesCount: a chain of a netdev table answers for its own rules. A bridge
// table answers as one: a base chain may hand a frame to any chain of its table, so one rule
// that does more than stop counts against every base chain of that table, and of no other.
func TestOnlyStopsWhoseRulesCount(t *testing.T) {
	// One rule that does more is enough, wherever it stands among the others.
	rs := listing(t, tbl("netdev", "nd"), hooked("netdev", "nd", "c", "egress", 0, "accept", "eth0"),
		ruleIn("netdev", "nd", "c", xDrop), ruleIn("netdev", "nd", "c", xMark), ruleIn("netdev", "nd", "c", xDrop))
	if u := entryFor(t, rs, "c of table netdev nd"); u.OnlyStops {
		t.Errorf("a chain with a rule that sets a mark only stops packets:\n%s", outside(rs))
	}

	// Two chains of one netdev table, and a third that nothing jumps to.
	rs = listing(t, tbl("netdev", "nd"),
		hooked("netdev", "nd", "a", "egress", 0, "accept", "eth0"), hooked("netdev", "nd", "b", "egress", 0, "accept", "eth1"),
		hooked("netdev", "nd", "in", "ingress", 0, "accept", "eth0"), unhooked("netdev", "nd", "side"),
		ruleIn("netdev", "nd", "a", xMark), ruleIn("netdev", "nd", "b", xDrop), ruleIn("netdev", "nd", "in", xDrop), ruleIn("netdev", "nd", "side", xMark))
	for chain, want := range map[string]bool{"a": false, "b": true, "in": true} {
		if u := entryFor(t, rs, chain+" of table netdev nd"); u.OnlyStops != want {
			t.Errorf("chain %s: only stops %v, want %v\n%s", chain, u.OnlyStops, want, outside(rs))
		}
	}

	// A bridge table: the rule of the chain nothing jumps to counts against both base chains. The
	// other bridge table is not touched by it.
	rs = listing(t, tbl("bridge", "br"), tbl("bridge", "quiet"),
		hooked("bridge", "br", "pre", "prerouting", 0, "accept"), hooked("bridge", "br", "out", "output", 0, "accept"), unhooked("bridge", "br", "side"),
		hooked("bridge", "quiet", "pre", "prerouting", 0, "accept"),
		ruleIn("bridge", "br", "pre", xDrop), ruleIn("bridge", "br", "out", xDrop), ruleIn("bridge", "br", "side", xMark),
		ruleIn("bridge", "quiet", "pre", xDrop))
	for chain, want := range map[string]bool{"pre of table bridge br": false, "out of table bridge br": false, "pre of table bridge quiet": true} {
		if u := entryFor(t, rs, chain); u.OnlyStops != want {
			t.Errorf("chain %s: only stops %v, want %v\n%s", chain, u.OnlyStops, want, outside(rs))
		}
	}
	if len(rs.Unfollowed) != 3 {
		t.Errorf("want three entries, got:\n%s", outside(rs))
	}
}

// TestDormantTableIsNotRunning: the kernel calls no chain of a table that is switched off, so
// none of them is an Unfollowed entry or has a note of its own: not the ingress chain, which
// stays in its table marked as not running, nor the chains that are kept aside, each of which
// carries its own copy of the table's flag. The flag reaches them wherever the table stands in
// the listing.
func TestDormantTableIsNotRunning(t *testing.T) {
	const (
		off      = " is switched off (flags dormant): the kernel runs none of its chains, so seaward does not either\n"
		walkedIn = "unfollowed: in eth0 only-stops walked: the chain in of table netdev nd acts on packets as they pass eth0" + underneath + "\n"
		arp      = "note: the chain in of table netdev nd drops by default every frame that arrives on eth0" + arpNote + "\n"
		egress   = "unfollowed: out eth0 only-stops: the chain out of table netdev nd acts on packets as they leave through eth0, after the packet path seaward follows\n"
		odd      = "unfollowed: in eth0 out eth0 only-stops: the chain odd of table netdev nd hooks in at input, a point of the packet path seaward does not know\n"
		loose    = "note: the chain loose of table netdev nd was left out: it is attached to no interface, so it sees no packets\n"
		bridge   = "unfollowed: bridge-in only-stops: the chain pre of table bridge br acts on frames as they arrive through a bridge, before the packet path seaward follows\n"
	)
	h := labHost()
	web := engine.Probe{Iif: "eth0", Src: addr("198.51.100.7"), Dst: addr("203.0.113.10"), Proto: "tcp", Dport: 80}
	for _, tc := range []struct {
		name           string
		netdev, bridge string // the two tables as the listing writes them
		running        bool   // the netdev table's ingress chain
		want           string // what outside prints
		web            engine.Class
	}{
		{"both running", tbl("netdev", "nd"), tbl("bridge", "br"), true, arp + loose + walkedIn + egress + odd + bridge, engine.Filtered},
		{"both switched off", tbl("netdev", "nd", "dormant"), tbl("bridge", "br", "dormant"), false,
			"note: the table bridge br" + off + "note: the table netdev nd" + off, engine.Closed},
		// nft writes a single flag as a bare string.
		{"the netdev table switched off", `{"table": {"family": "netdev", "name": "nd", "flags": "dormant"}}`, tbl("bridge", "br"), false,
			"note: the table netdev nd" + off + bridge, engine.Closed},
		{"the bridge table switched off", tbl("netdev", "nd"), tbl("bridge", "br", "dormant"), true,
			"note: the table bridge br" + off + arp + loose + walkedIn + egress + odd, engine.Filtered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := listing(t,
				// The chains and rules come before their tables: the listing is read by kind.
				hooked("netdev", "nd", "in", "ingress", -500, "drop", "eth0"),
				hooked("netdev", "nd", "out", "egress", 0, "accept", "eth0"),
				hooked("netdev", "nd", "odd", "input", 0, "accept", "eth0"),
				hooked("netdev", "nd", "loose", "ingress", 0, "accept"),
				hooked("bridge", "br", "pre", "prerouting", 0, "accept"),
				ruleIn("netdev", "nd", "in", toPort("tcp", 22), xAccept),
				ruleIn("netdev", "nd", "out", xDrop),
				ruleIn("netdev", "nd", "odd", xDrop),
				ruleIn("netdev", "nd", "loose", xDrop),
				ruleIn("bridge", "br", "pre", xDrop),
				tc.netdev, tc.bridge)
			if got := outside(rs); got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
			// The ingress chain is in its table either way, with everything but the running.
			tb := tableOf(t, rs, "netdev", "nd")
			c := tb.Chains["in"]
			if len(tb.Chains) != 1 || c == nil || c.Base != tc.running || c.Hook != rules.HookIngress || c.Policy != rules.Drop ||
				!reflect.DeepEqual(c.Devs, []string{"eth0"}) || len(c.Rules) != 1 {
				t.Fatalf("the ingress chain: %+v\n%s", c, dump(rs))
			}
			// And the engine takes it at its word: a running chain drops what it does not
			// accept, one that is switched off lets it in to find nothing listening.
			if r := engine.Run(rs, h, web); r.Class != tc.web || len(r.Unknowns) != 0 {
				t.Errorf("tcp port 80: %s %q, want %s", r.Class, r.Unknowns, tc.web)
			}
		})
	}
}

// TestDormantTableSettled: a table iptables made is one settled table in the result, built from
// both listings. That copy keeps what the nft listing says about the table being switched off.
func TestDormantTableSettled(t *testing.T) {
	h := labHost()
	web := engine.Probe{Iif: "eth0", Src: addr("198.51.100.7"), Dst: addr("203.0.113.10"), Proto: "tcp", Dport: 80}
	for _, dormant := range []bool{false, true} {
		table, class := tblFilter, engine.Filtered
		if dormant {
			table, class = `{"table": {"family": "ip", "name": "filter", "handle": 1, "flags": ["dormant"]}}`, engine.Closed
		}
		shared := saved(t, "ip", "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n")
		rs, err := ParseJSON(doc(table, chInput, ruleSSH), shared)
		if err != nil {
			t.Fatal(err)
		}
		tb := tableOf(t, rs, "ip", "filter")
		c := tb.Chains["INPUT"]
		if tb.Origin != "iptables" || c == nil || c.Hook != rules.HookInput || c.Policy != rules.Drop ||
			!reflect.DeepEqual(texts(c), []string{"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"}) {
			t.Fatalf("dormant %v: the table was not settled from both listings:\n%s", dormant, dump(rs))
		}
		if c.Base == dormant {
			t.Errorf("dormant %v: the settled INPUT chain is running: %v", dormant, c.Base)
		}
		if noteWith(rs, "the table ip filter is switched off (flags dormant)") != dormant || len(rs.Notes) > 1 {
			t.Errorf("dormant %v: notes %q", dormant, rs.Notes)
		}
		if r := engine.Run(rs, h, web); r.Class != class {
			t.Errorf("dormant %v: tcp port 80 is %s, want %s", dormant, r.Class, class)
		}
	}
}

// TestNfprotoInANetdevTable: in a netdev table the kernel answers "meta nfproto" with the table's
// own family, not the packet's, so a rule cannot tell IPv4 from IPv6 by it there. The reader says
// so, as an unknown; what does tell them apart in a netdev table still reads as it always did.
func TestNfprotoInANetdevTable(t *testing.T) {
	const (
		nfproto = `{"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}`
		unknown = "the meta nfproto match does not tell IPv4 from IPv6 in a netdev table, which seaward does not model"
	)
	for _, tc := range []struct {
		name, family string
		exprs        []string
		want         []string // the rule, one dumpExpr line per expression
	}{
		{"meta nfproto", "netdev", []string{nfproto, xDrop}, []string{"UNKNOWN " + unknown, "drop"}},
		{"meta nfproto in an inet table", "inet", []string{nfproto, xDrop}, []string{"match nfproto in {4}", "drop"}},
		// The frame's own protocol field, and a header only one IP version has.
		{"meta protocol", "netdev", []string{`{"match": {"op": "==", "left": {"meta": {"key": "protocol"}}, "right": "ip"}}`, xDrop},
			[]string{"match nfproto in {4}", "drop"}},
		{"ip saddr", "netdev", []string{xFrom, xDrop}, []string{"match nfproto in {4}", "match saddr in {198.51.100.7}", "drop"}},
		// As one part of a key it is no better.
		{"in a concatenation", "netdev", []string{`{"match": {"op": "==", "left": {"concat": [{"meta": {"key": "nfproto"}}, {"payload": {"protocol": "tcp", "field": "dport"}}]}, "right": {"set": [{"concat": ["ipv4", 22]}]}}}`, xDrop},
			[]string{"match l4proto in {6}", "UNKNOWN " + unknown, "drop"}},
		{"as the key of a verdict map", "netdev", []string{`{"vmap": {"key": {"meta": {"key": "nfproto"}}, "data": {"set": [["ipv4", {"drop": null}]]}}}`},
			[]string{"UNKNOWN-STMT this rule picks its verdict from a map keyed on meta nfproto, which seaward cannot follow"}},
	} {
		rs := listing(t, tbl(tc.family, "early"), hooked(tc.family, "early", "ingress", "ingress", -500, "accept", "eth0"),
			ruleIn(tc.family, "early", "ingress", tc.exprs...))
		c := tableOf(t, rs, tc.family, "early").Chains["ingress"]
		if c == nil || len(c.Rules) != 1 {
			t.Fatalf("%s: the rule was not read:\n%s", tc.name, dump(rs))
		}
		var got []string
		for _, x := range c.Rules[0].Exprs {
			got = append(got, dumpExpr(x))
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n  got  %s\n  want %s", tc.name, strings.Join(got, "\n       "), strings.Join(tc.want, "\n       "))
		}
	}

	// What that means for a packet: "meta nfproto ipv4 drop" on an interface's ingress hook may
	// or may not drop it, IPv4 or IPv6, and the answer says what it hangs on.
	rs := listing(t, tbl("netdev", "early"), hooked("netdev", "early", "ingress", "ingress", -500, "accept", "eth0"),
		ruleIn("netdev", "early", "ingress", nfproto, xDrop))
	h := labHost()
	for _, pr := range []engine.Probe{
		{Iif: "eth0", Src: addr("198.51.100.7"), Dst: addr("203.0.113.10"), Proto: "tcp", Dport: 22},
		{Iif: "eth0", Src: addr("2001:db8:99::7"), Dst: addr("2001:db8:1::10"), Proto: "tcp", Dport: 22},
	} {
		r := engine.Run(rs, h, pr)
		if r.Class != engine.Undecided || !reflect.DeepEqual(r.Possible, []engine.Class{engine.Open, engine.Filtered}) ||
			!reflect.DeepEqual(r.Unknowns, []string{unknown}) {
			t.Errorf("from %s: %s, one of %v, hanging on %q", pr.Src, r.Class, r.Possible, r.Unknowns)
		}
	}
}

// addrOn is the first address of one of a machine's interfaces.
func addrOn(t *testing.T, h *host.Host, name string) netip.Addr {
	t.Helper()
	for _, in := range h.Interfaces {
		if in.Name == name && len(in.Addrs) > 0 {
			return in.Addrs[0].Addr()
		}
	}
	t.Fatalf("the machine has no interface %s with an address", name)
	return netip.Addr{}
}

// TestIngressListingsAgainstTheEngine puts three rulesets the kernel lab has run (scenarios
// nft-ingress-order, nft-netdev-ingress-drop and nft-inet-ingress) through the reader and the
// engine together, with the probes the lab sends and the answers the kernel gave. The listings
// are written by hand in the shape nft gives them.
func TestIngressListingsAgainstTheEngine(t *testing.T) {
	const (
		filtered, open, rejected = engine.Filtered, engine.Open, engine.Rejected
		v4, v6                   = "198.51.100.7", "2001:db8:99::7"
		inner                    = "192.0.2.50" // a machine behind eth1
	)
	h := labHost()
	for _, port := range []uint16{80, 443, 7070, 8080, 9090} {
		h.Listeners = append(h.Listeners, host.Listener{Proto: "tcp", Addr: addr("::"), DualStack: true, Port: port, Process: "web"})
	}
	me := map[string]netip.Addr{
		v4: addr("203.0.113.10"), "198.51.100.200": addr("203.0.113.10"), v6: addr("2001:db8:1::10"), inner: addrOn(t, h, "eth1"),
	}
	type shot struct {
		iif, src, proto string
		port            uint16
		want            engine.Class
		by              string // "table/chain" of the step that decides, when a rule or policy stops it
	}
	for _, tc := range []struct {
		name  string
		items []string
		want  string // what outside prints
		shots []shot
	}{
		{
			// Several ingress chains on one interface run in order of priority, whatever table
			// they sit in and wherever the listing has them. An accept only ends its own chain.
			name: "nft-ingress-order",
			items: []string{
				tbl("netdev", "third"), hooked("netdev", "third", "ingress", "ingress", 100, "accept", "eth1"),
				ruleIn("netdev", "third", "ingress", toPort("tcp", 8080), xDrop),
				tbl("inet", "second"), hooked("inet", "second", "ingress", "ingress", 0, "accept", "eth0"),
				ruleIn("inet", "second", "ingress", toPort("tcp", 22), xDrop),
				ruleIn("inet", "second", "ingress", toPort("tcp", 8080), xAccept),
				tbl("netdev", "first"), hooked("netdev", "first", "ingress", "ingress", -300, "accept", "eth0", "eth1"), unhooked("netdev", "first", "web"),
				ruleIn("netdev", "first", "ingress", toPort("tcp", 22), xAccept),
				ruleIn("netdev", "first", "ingress", toPort("tcp", 80), jumpTo("web")),
				ruleIn("netdev", "first", "web", `{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eth1"}}`, `{"return": null}`),
				ruleIn("netdev", "first", "web", xDrop),
			},
			want: "unfollowed: in eth1 only-stops walked: the chain ingress of table netdev third acts on packets as they pass eth1" + underneath + "\n" +
				"unfollowed: in eth0 only-stops walked: the chain ingress of table inet second acts on packets as they pass eth0" + underneath + "\n" +
				// Its jump makes this one more than a chain that only stops.
				"unfollowed: in eth0,eth1 walked: the chain ingress of table netdev first acts on packets as they pass eth0 and eth1" + underneath + "\n",
			shots: []shot{
				{"eth0", v4, "tcp", 22, filtered, "second/ingress"},
				{"eth0", v4, "tcp", 80, filtered, "first/web"},
				{"eth0", v4, "tcp", 8080, open, ""},
				{"eth1", inner, "tcp", 22, open, ""},
				{"eth1", inner, "tcp", 80, open, ""},
				{"eth1", inner, "tcp", 8080, filtered, "third/ingress"},
			},
		},
		{
			// A netdev ingress chain that drops by default lets in only what its rules accept,
			// for IPv4 and IPv6 alike, and what it lets in still has to pass the input chain.
			name: "nft-netdev-ingress-drop",
			items: []string{
				tbl("netdev", "guard"), hooked("netdev", "guard", "ingress", "ingress", -500, "drop", "eth0"),
				ruleIn("netdev", "guard", "ingress", toPort("tcp", 22, 443), xAccept),
				ruleIn("netdev", "guard", "ingress", `{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "2001:db8:99::7"}}`, toPort("udp", 53), xAccept),
				tbl("inet", "filter"), hooked("inet", "filter", "input", "input", 0, "accept"),
				ruleIn("inet", "filter", "input", toPort("tcp", 443), xDrop),
			},
			want: "note: the chain ingress of table netdev guard drops by default every frame that arrives on eth0" + arpNote + "\n" +
				"unfollowed: in eth0 only-stops walked: the chain ingress of table netdev guard acts on packets as they pass eth0" + underneath + "\n",
			shots: []shot{
				{"eth0", v4, "tcp", 22, open, ""},
				{"eth0", v6, "tcp", 22, open, ""},
				{"eth0", v4, "tcp", 80, filtered, "guard/ingress"},
				{"eth0", v6, "tcp", 80, filtered, "guard/ingress"},
				{"eth0", v4, "tcp", 443, filtered, "filter/input"},
				{"eth0", v6, "udp", 53, open, ""},
				{"eth0", v4, "udp", 53, filtered, "guard/ingress"},
				{"eth1", inner, "tcp", 80, open, ""},
			},
		},
		{
			// An inet table may hook a chain in at ingress too. It runs before connection
			// tracking, so every packet reads as "ct state invalid" there and none as new, and a
			// reject is answered from there.
			name: "nft-inet-ingress",
			items: []string{
				tbl("inet", "early"), hooked("inet", "early", "ingress", "ingress", -500, "drop", "eth0"),
				ruleIn("inet", "early", "ingress", `{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "198.51.100.0", "len": 28}}}}`, toPort("tcp", 22), xDrop),
				ruleIn("inet", "early", "ingress", `{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "new"}}`, toPort("tcp", 7070), xDrop),
				ruleIn("inet", "early", "ingress", `{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "invalid"}}`, toPort("tcp", 9090), xDrop),
				ruleIn("inet", "early", "ingress", toPort("tcp", 8080), `{"reject": {"type": "tcp reset"}}`),
				ruleIn("inet", "early", "ingress", toPort("tcp", 22, 7070, 8080, 9090), xAccept),
				ruleIn("inet", "early", "ingress", `{"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "nexthdr"}}, "right": "tcp"}}`, xAccept),
				tbl("inet", "filter"), hooked("inet", "filter", "input", "input", 0, "accept"),
				ruleIn("inet", "filter", "input", toPort("tcp", 443), xDrop),
			},
			// Its reject makes it more than a chain that only stops.
			want: "unfollowed: in eth0 walked: the chain ingress of table inet early acts on packets as they pass eth0" + underneath + "\n",
			shots: []shot{
				{"eth0", v4, "tcp", 22, filtered, "early/ingress"},
				{"eth0", "198.51.100.200", "tcp", 22, open, ""},
				{"eth0", "198.51.100.200", "tcp", 7070, open, ""},
				{"eth0", "198.51.100.200", "tcp", 9090, filtered, "early/ingress"},
				{"eth0", "198.51.100.200", "tcp", 8080, rejected, "early/ingress"},
				{"eth0", "198.51.100.200", "tcp", 80, filtered, "early/ingress"},
				{"eth0", v6, "tcp", 80, open, ""},
				{"eth0", v6, "tcp", 443, filtered, "filter/input"},
				{"eth1", inner, "tcp", 80, open, ""},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := listing(t, tc.items...)
			if got := outside(rs); got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
			for _, s := range tc.shots {
				pr := engine.Probe{Iif: s.iif, Src: addr(s.src), Dst: me[s.src], Proto: s.proto, Dport: s.port}
				r := engine.Run(rs, h, pr)
				what := fmt.Sprintf("%s port %d from %s on %s", s.proto, s.port, s.src, s.iif)
				if r.Class != s.want || len(r.Unknowns) != 0 {
					t.Errorf("%s: %s %q, want %s", what, r.Class, r.Unknowns, s.want)
					continue
				}
				if d := r.Deciding(); s.by != "" && (d == nil || d.Table+"/"+d.Chain != s.by) {
					t.Errorf("%s: decided by %+v, want a step of %s", what, d, s.by)
				}
			}
		})
	}
}
