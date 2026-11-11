package nft

import (
	"encoding/json"
	"strings"
	"testing"
)

// listed reads the rules out of an "nft list ruleset" text listing, by "family table chain".
func listed(text string) map[string][]string {
	out := map[string][]string{}
	var table, chain string
	depth, skip := 0, 0
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		opens := strings.Count(s, "{") - strings.Count(s, "}")
		switch {
		case skip > 0:
			// inside a set, map or another named object
			skip += opens
			if skip == 0 {
				depth--
			}
			continue
		case depth == 0 && strings.HasPrefix(s, "table "):
			table = strings.TrimSuffix(strings.TrimPrefix(s, "table "), " {")
			depth = 1
			continue
		case depth == 1 && strings.HasPrefix(s, "chain ") && strings.HasSuffix(s, "{"):
			chain = strings.TrimSuffix(strings.TrimPrefix(s, "chain "), " {")
			depth = 2
			continue
		case depth == 1 && strings.HasSuffix(s, "{"):
			depth, skip = 2, 1
			continue
		case s == "}":
			depth--
			continue
		case depth == 1:
			continue // "flags dormant" and the like
		}
		if strings.HasPrefix(s, "type ") && strings.Contains(s, " hook ") || strings.HasPrefix(s, "comment ") {
			continue
		}
		key := table + " " + chain
		out[key] = append(out[key], s)
	}
	return out
}

// TestTextMatchesNft checks that the rule text seaward shows is the text nft itself prints for
// the same rule, for every rule of every fixture. The differences it allows are listed here.
func TestTextMatchesNft(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			want := listed(string(readFile(t, name+".txt")))
			var doc struct {
				Nftables []map[string]any `json:"nftables"`
			}
			dec := json.NewDecoder(strings.NewReader(string(readFile(t, name+".json"))))
			dec.UseNumber()
			if err := dec.Decode(&doc); err != nil {
				t.Fatal(err)
			}
			got := map[string][]string{}
			for _, item := range doc.Nftables {
				r, ok := item["rule"]
				if !ok {
					continue
				}
				o := build(r).obj()
				key := o.text("family") + " " + o.text("table") + " " + o.text("chain")
				got[key] = append(got[key], ruleText(o, o.text("family")))
			}
			rulesSeen := 0
			for key, lines := range want {
				if len(got[key]) != len(lines) {
					t.Errorf("%s: the listing has %d rules and the JSON %d", key, len(lines), len(got[key]))
					continue
				}
				for i, line := range lines {
					rulesSeen++
					if g := got[key][i]; g != line && !allowedTextDifference(g, line) {
						t.Errorf("%s rule %d:\n  nft:     %s\n  seaward: %s", key, i+1, line, g)
					}
				}
			}
			for key := range got {
				if _, ok := want[key]; !ok {
					t.Errorf("%s: rules in the JSON and none in the listing", key)
				}
			}
			if rulesSeen == 0 {
				t.Error("no rules compared")
			}
		})
	}
}

// allowedTextDifference names the places where seaward's text is deliberately not nft's.
func allowedTextDifference(got, want string) bool {
	return false
}
