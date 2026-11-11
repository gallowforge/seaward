// Package nft reads "nft -j list ruleset" output into the rules model.
//
// The listing is a flat list of tables, chains, sets, maps and rules. ParseJSON keeps the ip, ip6
// and inet tables, since those are the ones an IP packet walks, and says in a note what it left
// out. Inside a rule every expression becomes model expressions in the order written; whatever
// the model has no word for becomes an Unknown (a condition) or an UnknownStmt (a statement) with
// one sentence saying why, never nothing.
//
// A table that iptables made on the nf_tables backend is listed twice on a machine: once by
// iptables-save and once here. Neither listing is complete. The nft listing shows most of what
// iptables wrote as bare "xt" expressions that carry a name and nothing else, and iptables-save
// misprints rules that the nft tool added (a set lookup comes out as a rule with no condition).
// settle.go picks, rule by rule, the listing that can be trusted.
package nft

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// ParseJSON parses one "nft -j list ruleset" document.
//
// Shared holds the tables iptables-save and ip6tables-save printed on the nf_tables backend.
// Those are nf_tables tables, so the document lists them a second time. For such a table the
// result holds one settled table: see the package's notes on which listing wins for each rule.
// A table in the result replaces the caller's copy of the same family and name.
//
// The error is only for a document that is not JSON of this shape. Anything else it cannot
// represent becomes a note, an Unknown or an UnknownStmt.
func ParseJSON(data []byte, shared []*rules.Table) (*rules.Ruleset, error) {
	return guarded(func() (*rules.Ruleset, error) { return parse(data, shared) })
}

// guarded turns a panic into an error. The parser is written, and fuzzed, not to panic; this is
// the last line of defence for a tool that reads whatever a machine prints.
func guarded(run func() (*rules.Ruleset, error)) (rs *rules.Ruleset, err error) {
	defer func() {
		if r := recover(); r != nil {
			rs, err = nil, fmt.Errorf("nft: the listing could not be read (%v)", r)
		}
	}()
	return run()
}

// parser holds one document while it is read.
type parser struct {
	rs     *rules.Ruleset
	tables []*table
	byName map[string]*table
	noted  map[string]bool
}

// table is one ip, ip6 or inet table of the document.
type table struct {
	family, name string
	dormant      bool
	chains       map[string]*chain
	order        []string
	left         map[string]bool // chains left out: an ingress or egress hook
	sets         map[string]*setInfo
	limits       map[string]bool // named limits: true when it matches over the rate
}

// chain is a chain with its rules as the document wrote them.
type chain struct {
	c   *rules.Chain
	raw []*node
}

// setInfo is what the parser knows about a named set or map beyond what the model keeps.
type setInfo struct {
	set     *rules.Set
	kinds   []kind
	isMap   bool
	verdict bool
	data    []*node // maps that hold values: one per element of set.Elems
}

func parse(data []byte, shared []*rules.Table) (*rules.Ruleset, error) {
	p, err := read(data)
	if err != nil {
		return nil, err
	}
	for _, t := range p.tables {
		if t.dormant {
			p.note(fmt.Sprintf("the table %s %s is switched off (flags dormant): the kernel runs none of its chains, so seaward does not either", t.family, clip(t.name)))
		}
		var sh *rules.Table
		for _, s := range shared {
			if s != nil && s.Family == t.family && s.Name == t.name {
				sh = s
				break
			}
		}
		if sh != nil {
			p.rs.Tables = append(p.rs.Tables, p.settle(t, sh))
			continue
		}
		out := &rules.Table{Family: t.family, Name: t.name, Origin: "nft", Chains: map[string]*rules.Chain{}}
		for _, name := range t.order {
			c := t.chains[name]
			nc := *c.c
			nc.Rules = p.rulesOf(t, c.raw)
			out.Chains[name] = &nc
			out.Order = append(out.Order, name)
		}
		p.rs.Tables = append(p.rs.Tables, out)
	}
	return p.rs, nil
}

// read takes the document apart: tables, chains with their rules still as the document wrote
// them, sets and maps. Nothing in a rule is translated yet.
func read(data []byte) (*parser, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var top any
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("nft: the listing is not JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("nft: the listing has something after its JSON document")
	}
	doc, ok := top.(map[string]any)
	if !ok {
		return nil, errors.New(`nft: the listing is not a JSON object with an "nftables" list`)
	}
	list, ok := doc["nftables"].([]any)
	if !ok {
		return nil, errors.New(`nft: the listing is not a JSON object with an "nftables" list`)
	}

	p := &parser{
		rs:     &rules.Ruleset{Sets: map[string]*rules.Set{}},
		byName: map[string]*table{},
		noted:  map[string]bool{},
	}
	// The listing is read by kind, so that a rule may come before its chain or its set.
	var tables, chains, sets, maps, limits, flows, ruleList []*object
	for _, item := range list {
		kind, n := build(item).obj().one()
		o := n.obj()
		if kind == "" || (o == nil && kind != "metainfo") {
			p.note("the nft listing has an entry that is not written the way nft writes them; it was left out")
			continue
		}
		switch kind {
		case "metainfo":
			if v, ok := o.get("json_schema_version").num(); ok && v != 1 {
				p.note(fmt.Sprintf("the nft listing uses version %d of its format; seaward knows version 1 and read it as that", v))
			}
		case "table":
			tables = append(tables, o)
		case "chain":
			chains = append(chains, o)
		case "set":
			sets = append(sets, o)
		case "map":
			maps = append(maps, o)
		case "limit":
			limits = append(limits, o)
		case "flowtable":
			flows = append(flows, o)
		case "rule":
			ruleList = append(ruleList, o)
		case "counter", "quota", "ct helper", "ct timeout", "ct expectation", "secmark", "synproxy", "element":
			// Named objects that do nothing until a rule uses them.
		default:
			p.note(fmt.Sprintf("the nft listing has an entry of a kind seaward does not know (%s); it was left out", clip(kind)))
		}
	}
	for _, o := range tables {
		if t := p.table(o.text("family"), o.text("name")); t != nil {
			for _, f := range o.get("flags").strs() {
				if f == "dormant" {
					t.dormant = true
				}
			}
		}
	}
	for _, o := range chains {
		p.addChain(o)
	}
	for _, o := range limits {
		if t := p.table(o.text("family"), o.text("table")); t != nil {
			over, _ := o.get("inv").boolean()
			t.limits[o.text("name")] = over
		}
	}
	for _, o := range sets {
		p.addSet(o, false)
	}
	for _, o := range maps {
		p.addSet(o, true)
	}
	for _, o := range flows {
		if t := p.table(o.text("family"), o.text("table")); t != nil {
			p.note(fmt.Sprintf("the flowtable %s of table %s %s was left out: it only speeds up connections that the rules already let through", clip(o.text("name")), t.family, clip(t.name)))
		}
	}
	for _, o := range ruleList {
		t := p.table(o.text("family"), o.text("table"))
		if t == nil {
			continue
		}
		name := o.text("chain")
		if t.left[name] {
			continue
		}
		c := t.chains[name]
		if c == nil {
			c = t.chain(name)
		}
		c.raw = append(c.raw, &node{v: o})
	}
	return p, nil
}

// note adds a note once.
func (p *parser) note(s string) {
	if p.noted[s] {
		return
	}
	p.noted[s] = true
	p.rs.Notes = append(p.rs.Notes, s)
}

// clip keeps a name from the listing short enough to print in a sentence.
func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}

// table finds a table of the document, making it when a chain or rule names one the document did
// not declare. Tables of the families seaward does not follow give nil and one note each.
func (p *parser) table(family, name string) *table {
	switch family {
	case "ip", "ip6", "inet":
	default:
		what := "a family seaward does not know"
		switch family {
		case "arp":
			what = "ARP packets"
		case "bridge":
			what = "frames crossing a bridge"
		case "netdev":
			what = "packets on one interface, before the kernel's normal packet path"
		}
		p.note(fmt.Sprintf("the %s table %s was left out: it filters %s, which seaward does not follow", clip(family), clip(name), what))
		return nil
	}
	key := family + "\x00" + name
	if t := p.byName[key]; t != nil {
		return t
	}
	t := &table{
		family: family,
		name:   name,
		chains: map[string]*chain{},
		left:   map[string]bool{},
		sets:   map[string]*setInfo{},
		limits: map[string]bool{},
	}
	p.byName[key] = t
	p.tables = append(p.tables, t)
	return t
}

// chain finds or makes a chain of the table.
func (t *table) chain(name string) *chain {
	if c := t.chains[name]; c != nil {
		return c
	}
	c := &chain{c: &rules.Chain{Name: name}}
	t.chains[name] = c
	t.order = append(t.order, name)
	return c
}

func (p *parser) addChain(o *object) {
	t := p.table(o.text("family"), o.text("table"))
	if t == nil {
		return
	}
	name := o.text("name")
	hook := o.text("hook")
	switch hook {
	case "", rules.HookPrerouting, rules.HookInput, rules.HookForward, rules.HookOutput, rules.HookPostrouting:
	default:
		t.left[name] = true
		p.note(fmt.Sprintf("the chain %s of table %s %s was left out: it hooks in at %s, outside the packet path seaward follows", clip(name), t.family, clip(t.name), clip(hook)))
		return
	}
	c := t.chain(name).c
	if hook == "" {
		return
	}
	c.Hook = hook
	switch c.Type = o.text("type"); c.Type {
	case "filter", "nat", "route":
	default:
		// The kernel has had these three kinds since nftables began. A fourth would be news;
		// until then the chain is read as the kind that only lets through or stops.
		p.note(fmt.Sprintf("the chain %s of table %s %s is of a kind seaward does not know (type %s); it was read as a filter chain", clip(name), t.family, clip(t.name), clip(c.Type)))
		c.Type = "filter"
	}
	if v, ok := o.get("prio").i64(); ok && v >= -1<<31 && v < 1<<31 {
		c.Priority = int(v)
	}
	c.Policy = rules.Accept
	if o.text("policy") == "drop" {
		c.Policy = rules.Drop
	}
	// A dormant table keeps its chains and the kernel calls none of them.
	c.Base = !t.dormant
}

// typeKinds reads the key type of a set or map: a type name, a list of them for a concatenation,
// or "typeof" with the expression the keys are compared against.
func typeKinds(n *node, family string) (kinds []kind, words string) {
	if s, ok := n.str(); ok {
		return []kind{typeKind[s]}, s
	}
	if n.isArr() {
		var names []string
		for _, x := range n.arr() {
			s, _ := x.str()
			kinds = append(kinds, typeKind[s])
			names = append(names, s)
		}
		return kinds, strings.Join(names, " . ")
	}
	if key, v := n.obj().one(); key == "typeof" {
		parts := []*node{v}
		if k, c := v.obj().onePeek(); k == "concat" {
			parts = c.arr()
		}
		var names []string
		for _, x := range parts {
			kp := keyOf(x, family)
			if kp.k == kCtStatus {
				kp.k = kNone
			}
			kinds = append(kinds, kp.k)
			names = append(names, kp.name)
		}
		return kinds, strings.Join(names, " . ")
	}
	return []kind{kNone}, "unreadable"
}

// addSet reads a named set or map into Ruleset.Sets.
func (p *parser) addSet(o *object, isMap bool) {
	t := p.table(o.text("family"), o.text("table"))
	if t == nil {
		return
	}
	name := o.text("name")
	set := &rules.Set{Name: name}
	si := &setInfo{set: set, isMap: isMap}
	t.sets[name] = si
	p.rs.Sets[rules.SetKey(t.family, t.name, name)] = set

	what := "set"
	if isMap {
		what = "map"
		if s, ok := o.get("map").str(); ok && s == "verdict" {
			si.verdict = true
		}
	}
	if o.has("timeout") {
		set.Dynamic = true
	}
	for _, f := range o.get("flags").strs() {
		if f == "timeout" || f == "dynamic" {
			set.Dynamic = true
		}
	}
	kinds, words := typeKinds(o.get("type"), t.family)
	si.kinds = kinds
	for _, k := range kinds {
		if k == kNone {
			set.Incomplete = true
			set.Why = fmt.Sprintf("the %s %s holds values of a kind seaward does not model (%s)", what, clip(name), clip(typeWords(words)))
			return
		}
	}
	if len(kinds) == 0 {
		set.Incomplete = true
		set.Why = fmt.Sprintf("the %s %s does not say what kind of values it holds", what, clip(name))
		return
	}
	bad := func() {
		set.Elems, set.Verdicts, si.data = nil, nil, nil
		set.Incomplete = true
		set.Why = fmt.Sprintf("the %s %s has an entry seaward cannot read", what, clip(name))
	}
	// A catch-all entry ("*") goes last: the kernel uses it only when nothing else matches, and
	// the engine takes the first entry that does.
	var star rules.Elem
	var starVerdict rules.Verdict
	var starData *node
	for _, e := range o.get("elem").arr() {
		keyN, valN := e, (*node)(nil)
		if isMap {
			pair := e.arr()
			if len(pair) != 2 {
				bad()
				return
			}
			keyN, valN = pair[0], pair[1]
		}
		var v rules.Verdict
		if si.verdict {
			var ok bool
			if v, ok = verdictOf(valN); !ok {
				bad()
				return
			}
		}
		if s, ok := unwrap(keyN).str(); ok && s == "*" && isMap {
			star = make(rules.Elem, len(kinds))
			starVerdict, starData = v, valN
			continue
		}
		el, ok := elemOf(kinds, keyN)
		if !ok {
			bad()
			return
		}
		set.Elems = append(set.Elems, el)
		if si.verdict {
			set.Verdicts = append(set.Verdicts, v)
		} else if isMap {
			si.data = append(si.data, valN)
		}
	}
	if star != nil {
		set.Elems = append(set.Elems, star)
		if si.verdict {
			set.Verdicts = append(set.Verdicts, starVerdict)
		} else {
			si.data = append(si.data, starData)
		}
	}
}

// typeWords says an nft type name in plain words where there are any.
func typeWords(s string) string {
	switch s {
	case "ether_addr":
		return "hardware (MAC) addresses"
	case "ifname", "iface_index":
		return "interface names"
	}
	return s
}

// rulesOf translates a chain's rules.
func (p *parser) rulesOf(t *table, raw []*node) []*rules.Rule {
	var out []*rules.Rule
	for _, r := range raw {
		out = append(out, p.rule(t, r)...)
	}
	return out
}
