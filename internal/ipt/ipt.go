// Package ipt reads iptables-save, ip6tables-save and ipset save output into the rules model.
//
// Each rule becomes one expression per condition, in the order written, followed by the
// statement its target stands for. Anything the model cannot express exactly becomes
// rules.Unknown or rules.UnknownStmt with one plain sentence, so no condition is ever dropped.
//
// Set dimensions, as ParseIPSet returns them and ParseSave reads them from Options.SetDims:
//
//	"ip", "net"   one address field: FSaddr for the flag src, FDaddr for dst
//	"port"        two fields, FL4Proto then FSport or FDport; the element holds two atoms
//	"port-only"   one port field and no protocol (bitmap:port)
//	"iface"       FIifName for src, FOifName for dst
//	"mark"        FMark; "mark/0xMASK" when the set has a markmask other than all ones
//	"mac"         hardware addresses, which the model has no field for
package ipt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// Options says what the text is.
type Options struct {
	Family string // "ip" for iptables-save, "ip6" for ip6tables-save
	Legacy bool   // true when it came from the legacy (x_tables) backend
	// SetDims gives, for each ipset by name, the dimensions of its type as ParseIPSet returned
	// them: hash:ip,port is ["ip", "port"].
	SetDims map[string][]string
}

// baseChain is where a built-in chain of an iptables table hooks in.
type baseChain struct {
	hook, typ string
	prio      int
}

var baseChains = map[string]map[string]baseChain{
	"raw": {
		"PREROUTING": {rules.HookPrerouting, "filter", -300},
		"OUTPUT":     {rules.HookOutput, "filter", -300},
	},
	"mangle": {
		"PREROUTING":  {rules.HookPrerouting, "filter", -150},
		"INPUT":       {rules.HookInput, "filter", -150},
		"FORWARD":     {rules.HookForward, "filter", -150},
		"OUTPUT":      {rules.HookOutput, "route", -150},
		"POSTROUTING": {rules.HookPostrouting, "filter", -150},
	},
	"nat": {
		"PREROUTING":  {rules.HookPrerouting, "nat", -100},
		"OUTPUT":      {rules.HookOutput, "nat", -100},
		"INPUT":       {rules.HookInput, "nat", 100},
		"POSTROUTING": {rules.HookPostrouting, "nat", 100},
	},
	"filter": {
		"INPUT":   {rules.HookInput, "filter", 0},
		"FORWARD": {rules.HookForward, "filter", 0},
		"OUTPUT":  {rules.HookOutput, "filter", 0},
	},
	"security": {
		"INPUT":   {rules.HookInput, "filter", 50},
		"FORWARD": {rules.HookForward, "filter", 50},
		"OUTPUT":  {rules.HookOutput, "filter", 50},
	},
}

// pendingTable collects one table's lines; rules are parsed at COMMIT, once every chain name is
// known, so a jump can be told apart from an unknown target.
type pendingTable struct {
	name  string
	line  int
	skip  bool
	table *rules.Table
	rules []pendingRule
}

type pendingRule struct {
	line  int
	chain string
	text  string
	toks  []token
}

// ParseSave parses the output of iptables-save or ip6tables-save. Notes are plain sentences about
// things it saw and could not represent as a whole (a table marked incompatible, say).
func ParseSave(text string, o Options) (tables []*rules.Table, notes []string, err error) {
	family := o.Family
	if family == "" {
		family = "ip"
	}
	if family != "ip" && family != "ip6" {
		return nil, nil, fmt.Errorf("ipt: family %q is neither ip nor ip6", o.Family)
	}
	origin := "iptables"
	if o.Legacy {
		origin = "iptables-legacy"
	}
	tool := "iptables"
	if family == "ip6" {
		tool = "ip6tables"
	}

	incompatible := map[string]bool{}
	var cur, pending = (*pendingTable)(nil), []*pendingTable(nil)
	for n, raw := range strings.Split(text, "\n") {
		ln := n + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			if name, ok := incompatibleTable(line); ok {
				incompatible[name] = true
				notes = append(notes, fmt.Sprintf("the %s table %s uses nftables features %s cannot show, so it is left to the nftables reader", tool, name, tool))
			} else if strings.Contains(line, "legacy tables present") {
				notes = append(notes, "iptables-save says legacy iptables tables are also loaded; they are in the legacy save output")
			}
			continue
		case strings.HasPrefix(line, "*"):
			if cur != nil {
				return nil, notes, fmt.Errorf("ipt: line %d: table %s starts before table %s was committed", ln, line[1:], cur.name)
			}
			name := strings.TrimSpace(line[1:])
			if name == "" {
				return nil, notes, fmt.Errorf("ipt: line %d: table line without a name", ln)
			}
			cur = &pendingTable{name: name, line: ln, skip: incompatible[name],
				table: &rules.Table{Family: family, Name: name, Origin: origin, Chains: map[string]*rules.Chain{}}}
			if _, known := baseChains[name]; !known && !cur.skip {
				notes = append(notes, fmt.Sprintf("the %s table %s is not a standard table, so none of its chains is treated as attached to a hook", tool, name))
			}
			continue
		}
		if cur == nil {
			return nil, notes, fmt.Errorf("ipt: line %d: %q is outside any table", ln, clip(line))
		}
		switch {
		case line == "COMMIT":
			if !cur.skip {
				pending = append(pending, cur)
				tables = append(tables, cur.table)
			}
			cur = nil
		case strings.HasPrefix(line, ":"):
			if cur.skip {
				continue
			}
			f := strings.Fields(line[1:])
			if len(f) < 2 {
				return nil, notes, fmt.Errorf("ipt: line %d: chain line %q has no policy", ln, clip(line))
			}
			name, pol := f[0], f[1]
			if _, dup := cur.table.Chains[name]; dup {
				return nil, notes, fmt.Errorf("ipt: line %d: chain %s is declared twice", ln, name)
			}
			ch := &rules.Chain{Name: name}
			if bc, ok := baseChains[cur.name][name]; ok && pol != "-" {
				ch.Base, ch.Hook, ch.Type, ch.Priority = true, bc.hook, bc.typ, bc.prio
				switch pol {
				case "ACCEPT":
					ch.Policy = rules.Accept
				case "DROP":
					ch.Policy = rules.Drop
				default:
					// The kernel only allows ACCEPT and DROP; keep going but say so.
					ch.Policy = rules.Accept
					notes = append(notes, fmt.Sprintf("the chain %s in table %s has the policy %s, which seaward does not know, so it is read as ACCEPT", name, cur.name, pol))
				}
			}
			cur.table.Chains[name] = ch
			cur.table.Order = append(cur.table.Order, name)
		default:
			if cur.skip {
				continue
			}
			toks, terr := tokenize(line)
			if terr != nil {
				return nil, notes, fmt.Errorf("ipt: line %d: %v", ln, terr)
			}
			text := line
			// iptables-save -c puts the counters in front: "[pkts:bytes] -A CHAIN ...".
			if len(toks) > 0 && strings.HasPrefix(toks[0].s, "[") && !toks[0].quoted {
				toks = toks[1:]
				if i := strings.Index(text, "]"); i >= 0 {
					text = strings.TrimSpace(text[i+1:])
				}
			}
			if len(toks) < 2 || (toks[0].s != "-A" && toks[0].s != "--append") {
				return nil, notes, fmt.Errorf("ipt: line %d: %q is not a rule, a chain or COMMIT", ln, clip(line))
			}
			chain := toks[1].s
			if _, ok := cur.table.Chains[chain]; !ok {
				return nil, notes, fmt.Errorf("ipt: line %d: rule for chain %s, which the table does not declare", ln, chain)
			}
			cur.rules = append(cur.rules, pendingRule{line: ln, chain: chain, text: text, toks: toks[2:]})
		}
	}
	if cur != nil {
		return nil, notes, fmt.Errorf("ipt: table %s (line %d) has no COMMIT; the output looks cut short", cur.name, cur.line)
	}
	// Rules are parsed once the whole text is read, so each rule can know what the others do.
	w := scanWalk(pending)
	for _, pt := range pending {
		pt.finish(o.SetDims, w)
	}
	return tables, notes, nil
}

// walkFacts are things other rules do that change what a rule means for the same packet.
type walkFacts struct {
	recentSets map[string]int  // recent list name -> how many rules add the sender to it
	setFilled  map[string]bool // ipsets that a SET target adds to
}

// scanWalk notes every "-m recent --set" and "-j SET --add-set" in the text. A first packet can
// pass such a rule earlier in its walk and then be found by a later check.
func scanWalk(pending []*pendingTable) walkFacts {
	w := walkFacts{recentSets: map[string]int{}, setFilled: map[string]bool{}}
	for _, pt := range pending {
		for _, pr := range pt.rules {
			mod, target, name, set := "", "", "DEFAULT", false
			for i, t := range pr.toks {
				next := ""
				if i+1 < len(pr.toks) {
					next = pr.toks[i+1].s
				}
				switch {
				case t.quoted:
				case t.s == "-m" || t.s == "--match":
					if mod == "recent" && set {
						w.recentSets[name]++
					}
					mod, name, set = next, "DEFAULT", false
				case t.s == "-j" || t.s == "--jump":
					target = next
				case mod == "recent" && t.s == "--name":
					name = next
				case mod == "recent" && t.s == "--set":
					set = true
				case target == "SET" && (t.s == "--add-set" || t.s == "--map-set"):
					w.setFilled[next] = true
				}
			}
			if mod == "recent" && set {
				w.recentSets[name]++
			}
		}
	}
	return w
}

// finish turns the collected rule lines into rules.
func (pt *pendingTable) finish(setDims map[string][]string, w walkFacts) {
	for _, pr := range pt.rules {
		p := &ruleParser{
			toks:    pr.toks,
			family:  pt.table.Family,
			table:   pt.table,
			chain:   pr.chain,
			setDims: setDims,
			walk:    w,
		}
		exprs := p.parse()
		ch := pt.table.Chains[pr.chain]
		ch.Rules = append(ch.Rules, &rules.Rule{Text: pr.text, Exprs: exprs})
	}
}

// Incompatible lists the tables an iptables-save listing says it cannot show: tables holding
// rules only the nft tool can list.
func Incompatible(text string) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if !strings.HasPrefix(line, "#") {
			continue
		}
		if name, ok := incompatibleTable(line); ok {
			out = append(out, name)
		}
	}
	return out
}

// incompatibleTable recognises both forms iptables-nft prints: "# Table `filter' is incompatible,
// use 'nft' tool." and "# Table `filter' contains incompatible base-chains, use 'nft' tool to
// list them.". Either way the text shows only part of the table.
func incompatibleTable(line string) (string, bool) {
	if !strings.Contains(line, "incompatible") {
		return "", false
	}
	i := strings.IndexAny(line, "`'")
	if i < 0 {
		return "", false
	}
	rest := line[i+1:]
	j := strings.IndexAny(rest, "'`")
	if j <= 0 {
		return "", false
	}
	return rest[:j], true
}

func clip(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

// token is one word of a rule line. A quoted word is never an option name.
type token struct {
	s      string
	quoted bool
}

// tokenize splits a line the way iptables-restore does: whitespace separates words, double
// quotes group words, and inside quotes a backslash makes the next character literal.
func tokenize(line string) ([]token, error) {
	var out []token
	var b strings.Builder
	inWord, quoted, inQuote, esc := false, false, false, false
	for _, r := range line {
		switch {
		case inQuote && esc:
			b.WriteRune(r)
			esc = false
		case inQuote && r == '\\':
			esc = true
		case inQuote && r == '"':
			inQuote = false
		case inQuote:
			b.WriteRune(r)
		case r == '"':
			inQuote, inWord, quoted = true, true, true
		case r == ' ' || r == '\t':
			if inWord {
				out = append(out, token{s: b.String(), quoted: quoted})
				b.Reset()
				inWord, quoted = false, false
			}
		default:
			b.WriteRune(r)
			inWord = true
		}
	}
	if inQuote {
		return nil, errors.New("a quoted string is not closed")
	}
	if inWord {
		out = append(out, token{s: b.String(), quoted: quoted})
	}
	return out, nil
}
