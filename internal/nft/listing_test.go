package nft

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/engine"
	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// The tests of this file are about the text listing, "nft list ruleset", which a snapshot holds
// beside the JSON one. It is read for the interfaces of the base chains, which the JSON of an
// older nft leaves out. testdata/old-nft-ingress.json and .txt are what nft 1.0.9 printed for
// the kernel lab's scenario nft-ingress-order: three ingress chains, and not one "dev" in the
// JSON.

// declared is every base chain a text listing declares, one a line, sorted.
func declared(text string) string {
	var out []string
	for k, c := range textChains(text) {
		out = append(out, fmt.Sprintf("%s hook %s on %q", strings.ReplaceAll(k, "\x00", " "), c.hook, c.devs))
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

func TestTextChains(t *testing.T) {
	for _, c := range []struct {
		name, text, want string
	}{
		{"one interface, as nft 1.0.9 writes it",
			"table netdev early {\n\tchain ingress {\n\t\ttype filter hook ingress device \"eth0\" priority -500; policy accept;\n\t\ttcp dport 80 drop\n\t}\n}\n",
			`netdev early ingress hook ingress on ["eth0"]`},
		{"several, as nft 1.0.9 writes them",
			"table netdev first {\n\tchain ingress {\n\t\ttype filter hook ingress devices = { eth0, eth1 } priority -300; policy accept;\n\t}\n}\n",
			`netdev first ingress hook ingress on ["eth0" "eth1"]`},
		{"several, in quotes, and a name that stands for many",
			"table inet t {\n\tchain c {\n\t\ttype filter hook ingress devices = { \"eth0\", \"wl*\" } priority filter; policy drop;\n\t}\n}\n",
			`inet t c hook ingress on ["eth0" "wl*"]`},
		{"an egress chain",
			"table netdev nd {\n\tchain out {\n\t\ttype filter hook egress device \"eth0\" priority 0; policy accept;\n\t}\n}\n",
			`netdev nd out hook egress on ["eth0"]`},
		// The declaration is there and names nothing: the chain is attached to nothing.
		{"no interface",
			"table netdev nd {\n\tchain loose {\n\t\ttype filter hook ingress priority 0; policy accept;\n\t\tdrop\n\t}\n}\n",
			`netdev nd loose hook ingress on []`},
		{"the hooks of the packet path, and a chain with none",
			"table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport { 22, 80 } accept\n\t}\n\n\tchain side {\n\t\tdrop\n\t}\n}\n",
			`inet filter input hook input on []`},
		{"a comment before the declaration, and handles",
			"table netdev nd { # handle 4\n\tchain c { # handle 1\n\t\tcomment \"the uplink\"\n\t\ttype filter hook ingress device \"eth0\" priority 0; policy accept; # handle 2\n\t}\n}\n",
			`netdev nd c hook ingress on ["eth0"]`},
		// What a rule says is never taken for a declaration, whatever words and braces it holds.
		{"words of a declaration inside a rule, a set and a flowtable",
			"table inet t {\n\tset s {\n\t\ttype ifname\n\t\telements = { \"eth7\",\n\t\t\t     \"eth8\" }\n\t}\n\n" +
				"\tflowtable f {\n\t\thook ingress priority filter\n\t\tdevices = { eth5, eth6 }\n\t}\n\n" +
				"\tchain a {\n\t\tiifname \"eth9\" counter comment \"type filter hook ingress device eth9 priority 0; }\" accept\n\t\tiifname { \"eth3\", \"eth4\" } drop\n\t}\n\n" +
				"\tchain b {\n\t\ttype filter hook ingress device \"eth1\" priority filter; policy accept;\n\t\tip saddr { 198.51.100.7, 203.0.113.9 } drop comment \"devices = { eth9 }\"\n\t}\n}\n",
			`inet t b hook ingress on ["eth1"]`},
		{"two tables of one name in two families",
			"table netdev t {\n\tchain c {\n\t\ttype filter hook ingress device \"eth0\" priority 0; policy accept;\n\t}\n}\ntable inet t {\n\tchain c {\n\t\ttype filter hook ingress device \"eth1\" priority 0; policy accept;\n\t}\n}\n",
			"inet t c hook ingress on [\"eth1\"]\nnetdev t c hook ingress on [\"eth0\"]"},
		// A listing that breaks off keeps what was whole before the break.
		{"cut short",
			"table netdev a {\n\tchain c {\n\t\ttype filter hook ingress device \"eth0\" priority 0; policy accept;\n\t}\n}\ntable netdev b {\n\tchain c {\n\t\ttype filter hook ingress devi",
			`netdev a c hook ingress on ["eth0"]`},
		{"cut short inside a list of interfaces",
			"table netdev b {\n\tchain c {\n\t\ttype filter hook ingress devices = { eth0, ",
			""},
		{"cut short after the declaration",
			"table netdev b {\n\tchain c {\n\t\ttype filter hook ingress device \"eth0\" priority 0; policy acc",
			`netdev b c hook ingress on ["eth0"]`},
		{"not a listing", "Error: Operation not permitted\n{ } } { ; = , \"", ""},
		{"nothing", "", ""},
	} {
		if got := declared(c.text); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

// A text listing that breaks off anywhere never says less of a chain than the whole one does:
// whatever chain a piece of it declares, it declares on the same interfaces. A chain made to
// look attached to nothing by a cut would be left out of the walk, and its drops with it.
func TestTextListingCutAnywhere(t *testing.T) {
	for _, name := range append([]string{"old-nft-ingress"}, fixtures...) {
		text := string(readFile(t, name+".txt"))
		whole := textChains(text)
		for cut := 0; cut <= len(text); cut++ {
			for k, c := range textChains(text[:cut]) {
				if w, ok := whole[k]; !ok || w.hook != c.hook || !reflect.DeepEqual(w.devs, c.devs) {
					t.Fatalf("%s cut at %d: %s on %q, the whole listing has %q", name, cut, strings.ReplaceAll(k, "\x00", " "), c.devs, w.devs)
				}
			}
		}
	}
	// And the whole listing of each fixture declares the base chains its JSON has, no more.
	for _, name := range fixtures {
		p, err := read(readFile(t, name+".json"), nil)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{}
		for _, tb := range p.tables {
			for _, cn := range tb.order {
				if c := tb.chains[cn].c; c.Hook != "" {
					want[textKey(tb.family, tb.name, cn)] = true
				}
			}
		}
		// with the chains kept aside: those of a bridge table, an egress chain
		for _, a := range p.aside {
			want[textKey(a.family, a.table, a.name)] = true
		}
		got := textChains(string(readFile(t, name+".txt")))
		for k := range want {
			if _, ok := got[k]; !ok {
				t.Errorf("%s: the text listing does not declare %s", name, strings.ReplaceAll(k, "\x00", " "))
			}
		}
		for k := range got {
			// An arp table is left out by the reader of the JSON, with a note.
			if !want[k] && !strings.HasPrefix(k, "arp\x00") {
				t.Errorf("%s: the text listing declares %s, which the JSON does not have as a base chain", name, strings.ReplaceAll(k, "\x00", " "))
			}
		}
	}
}

// with reads a document with a text listing beside it.
func with(t *testing.T, text string, items ...string) *rules.Ruleset {
	t.Helper()
	rs, err := ParseListing(doc(items...), text, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkShape(t, rs)
	return rs
}

// TestInterfacesFromTheTextListing: where the JSON names no interface for an ingress or egress
// chain, the text listing settles it. A chain it declares with an interface is on that one; a
// chain it declares with none is attached to nothing and sees no packet; a chain it does not
// declare is on an interface nobody names, and may be on any.
func TestInterfacesFromTheTextListing(t *testing.T) {
	const (
		head   = "table netdev nd {\n\tchain c {\n\t\ttype filter hook "
		tail   = " priority 0; policy accept;\n\t\tip saddr 198.51.100.7 drop\n\t}\n}\n"
		nobody = " an interface neither of nft's two listings settles: the JSON gives none, and the text does not declare the chain as the JSON has it\n"
	)
	one := func(hook string, devs ...string) []string {
		return []string{tbl("netdev", "nd"), hooked("netdev", "nd", "c", hook, 0, "accept", devs...), ruleIn("netdev", "nd", "c", xFrom, xDrop)}
	}
	for _, c := range []struct {
		name, text string
		items      []string
		devs       []string // of the walked chain; nil when the chain is not walked
		want       string   // what outside prints
	}{
		{"ingress, one interface", head + `ingress device "eth0"` + tail, one("ingress"), []string{"eth0"},
			"unfollowed: in eth0 only-stops walked: the chain c of table netdev nd acts on packets as they pass eth0" + underneath + "\n"},
		{"ingress, two interfaces", head + "ingress devices = { eth0, eth1 }" + tail, one("ingress"), []string{"eth0", "eth1"},
			"unfollowed: in eth0,eth1 only-stops walked: the chain c of table netdev nd acts on packets as they pass eth0 and eth1" + underneath + "\n"},
		{"ingress, declared with no interface", head + "ingress" + tail, one("ingress"), nil,
			"note: the chain c of table netdev nd was left out: it is attached to no interface, so it sees no packets\n"},
		{"ingress, not declared in the text", "table inet other {\n}\n", one("ingress"), nil,
			"unfollowed: in * only-stops: the chain c of table netdev nd acts on packets as they arrive on" + nobody},
		// The two listings are two commands. A chain the text has on another hook is not the
		// chain the JSON has: neither its interface nor its lack of one is taken from there.
		{"ingress in the JSON, egress in the text", head + `egress device "eth0"` + tail, one("ingress"), nil,
			"unfollowed: in * only-stops: the chain c of table netdev nd acts on packets as they arrive on" + nobody},
		{"egress in the JSON, an ingress chain with no interface in the text", head + "ingress" + tail, one("egress"), nil,
			"unfollowed: out * only-stops: the chain c of table netdev nd acts on packets as they leave through" + nobody},
		{"ingress, no text at all", "", one("ingress"), nil,
			"unfollowed: in * only-stops: the chain c of table netdev nd acts on packets as they arrive on" + notNamed + "\n"},
		{"ingress, a text of blanks is no text", " \n\t\n", one("ingress"), nil,
			"unfollowed: in * only-stops: the chain c of table netdev nd acts on packets as they arrive on" + notNamed + "\n"},
		// Where the JSON does name the interface, that is what the kernel was asked a moment
		// earlier, and it stands.
		{"ingress, named by both", head + `ingress device "eth1"` + tail, one("ingress", "eth0"), []string{"eth0"},
			"unfollowed: in eth0 only-stops walked: the chain c of table netdev nd acts on packets as they pass eth0" + underneath + "\n"},
		{"egress, one interface", head + `egress device "eth0"` + tail, one("egress"), nil,
			"unfollowed: out eth0 only-stops: the chain c of table netdev nd acts on packets as they leave through eth0, after the packet path seaward follows\n"},
		{"egress, declared with no interface", head + "egress" + tail, one("egress"), nil,
			"note: the chain c of table netdev nd was left out: it is attached to no interface, so it sees no packets\n"},
		{"egress, not declared in the text", "table inet other {\n}\n", one("egress"), nil,
			"unfollowed: out * only-stops: the chain c of table netdev nd acts on packets as they leave through" + nobody},
	} {
		rs := with(t, c.text, c.items...)
		if got := outside(rs); got != c.want {
			t.Errorf("%s:\n got %swant %s", c.name, got, c.want)
		}
		walked := tableOf(t, rs, "netdev", "nd").Chains["c"]
		switch {
		case c.devs == nil && walked != nil:
			t.Errorf("%s: the chain is walked: %+v", c.name, walked)
		case c.devs != nil && (walked == nil || !walked.Base || walked.Hook != rules.HookIngress || !reflect.DeepEqual(walked.Devs, c.devs)):
			t.Errorf("%s: the chain is not walked on %q: %+v", c.name, c.devs, walked)
		}
	}
}

// TestIngressChainsOfAnOlderNft reads what nft 1.0.9 printed for three ingress chains. With the
// text listing beside the JSON every chain is walked on its own interfaces and the answers are
// the ones the kernel gave in the lab. With the JSON alone no chain can be placed, and the
// answer for every packet they might stop is "not decided": never "open", which is what the
// reader said while it took such a chain for one attached to nothing.
func TestIngressChainsOfAnOlderNft(t *testing.T) {
	data, text := readFile(t, "old-nft-ingress.json"), string(readFile(t, "old-nft-ingress.txt"))
	if strings.Contains(string(data), `"dev"`) || !strings.Contains(string(data), `"version": "1.0.9"`) {
		t.Fatal("the fixture is no longer what nft 1.0.9 printed: its JSON names no interface")
	}
	h := labHost()
	for _, port := range []uint16{80, 8080} {
		h.Listeners = append(h.Listeners, host.Listener{Proto: "tcp", Addr: addr("::"), DualStack: true, Port: port, Process: "web"})
	}
	type packet struct {
		iif, src, dst string
		port          uint16
		want          engine.Class // what the kernel did, as the lab's scenario has it
	}
	packets := []packet{
		{"eth0", "198.51.100.7", "203.0.113.10", 22, engine.Filtered},
		{"eth0", "198.51.100.7", "203.0.113.10", 80, engine.Filtered},
		{"eth0", "198.51.100.7", "203.0.113.10", 8080, engine.Open},
		{"eth1", "192.0.2.50", "10.20.0.1", 22, engine.Open},
		{"eth1", "192.0.2.50", "10.20.0.1", 80, engine.Open},
		{"eth1", "192.0.2.50", "10.20.0.1", 8080, engine.Filtered},
	}
	run := func(rs *rules.Ruleset, p packet) engine.Result {
		return engine.Run(rs, h, engine.Probe{Iif: p.iif, Src: addr(p.src), Dst: addr(p.dst), Proto: "tcp", Dport: p.port})
	}

	// With the text: the three chains, each on its interfaces.
	rs, err := ParseListing(data, text, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkShape(t, rs)
	for _, c := range []struct {
		family, table string
		devs          []string
	}{{"netdev", "first", []string{"eth0", "eth1"}}, {"inet", "second", []string{"eth0"}}, {"netdev", "third", []string{"eth1"}}} {
		ch := tableOf(t, rs, c.family, c.table).Chains["ingress"]
		if ch == nil || !ch.Base || ch.Hook != rules.HookIngress || !reflect.DeepEqual(ch.Devs, c.devs) {
			t.Errorf("table %s %s: the ingress chain is not walked on %q: %+v", c.family, c.table, c.devs, ch)
		}
	}
	for _, p := range packets {
		if r := run(rs, p); r.Class != p.want || len(r.Unknowns) != 0 {
			t.Errorf("with the text, %s tcp %d: %s %q, want %s", p.iif, p.port, r.Class, r.Unknowns, p.want)
		}
	}

	// The JSON alone, as a snapshot taken before the text was kept has it.
	rs, err = ParseJSON(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkShape(t, rs)
	// The first chain jumps, so it may do more than stop a packet; the other two cannot.
	want := "unfollowed: in *: the chain ingress of table netdev first acts on packets as they arrive on" + notNamed + "\n" +
		"unfollowed: in * only-stops: the chain ingress of table inet second acts on packets as they arrive on" + notNamed + "\n" +
		"unfollowed: in * only-stops: the chain ingress of table netdev third acts on packets as they arrive on" + notNamed + "\n"
	if got := outside(rs); got != want {
		t.Errorf("the JSON alone:\n got %swant %s", got, want)
	}
	for _, tb := range rs.Tables {
		if c := tb.Chains["ingress"]; c != nil && c.Base {
			t.Errorf("table %s %s: an ingress chain is walked although nothing names its interface", tb.Family, tb.Name)
		}
	}
	for _, p := range packets {
		r := run(rs, p)
		if r.Class != engine.Undecided || len(r.Unknowns) != 3 || !strings.Contains(r.Unknowns[0], "the chain ingress of table netdev first") {
			t.Errorf("the JSON alone, %s tcp %d: %s %q, want it not decided and all three chains named", p.iif, p.port, r.Class, r.Unknowns)
		}
	}
}
