package ipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/rules"
)

// This file checks, independently of the parser's own tables, that no option is ever dropped
// without a trace: every option of a rule is either one the model represents (listed here by
// hand) or the rule carries an Unknown or UnknownStmt.

var modeledMatchOpts = map[string]string{
	"tcp":       "sport source-port dport destination-port tcp-flags syn",
	"udp":       "sport source-port dport destination-port",
	"udplite":   "sport source-port dport destination-port",
	"sctp":      "sport source-port dport destination-port",
	"dccp":      "sport source-port dport destination-port",
	"multiport": "dports destination-ports sports source-ports ports",
	"conntrack": "ctstate ctproto ctorigdst ctorigdstport ctdir ctstatus",
	"state":     "state",
	"addrtype":  "src-type dst-type",
	"mark":      "mark",
	"connmark":  "mark",
	"set":       "match-set update-counters update-subcounters",
	"iprange":   "src-range dst-range",
	"pkttype":   "pkt-type",
	"icmp":      "icmp-type",
	"icmp6":     "icmpv6-type",
	"ipv6-icmp": "icmpv6-type",
	"rpfilter":  "invert",
	"policy":    "dir pol",
	"limit":     "limit limit-burst",
	"hashlimit": "hashlimit hashlimit-upto hashlimit-above hashlimit-burst hashlimit-mode hashlimit-srcmask hashlimit-dstmask hashlimit-name hashlimit-htable-size hashlimit-htable-max hashlimit-htable-expire hashlimit-htable-gcinterval hashlimit-rate-match hashlimit-rate-interval",
	"comment":   "comment",
	"recent":    "set rcheck update remove seconds reap hitcount rttl name rsource rdest mask",
	"connlimit": "connlimit-upto connlimit-above connlimit-mask connlimit-saddr connlimit-daddr",
}

var modeledTargetOpts = map[string]string{
	"ACCEPT": "", "DROP": "", "RETURN": "", "REJECT": "reject-with",
	"DNAT": "to-destination random persistent", "REDIRECT": "to-ports random",
	"MARK":     "set-xmark set-mark and-mark or-mark xor-mark",
	"CONNMARK": "set-xmark set-mark and-mark or-mark xor-mark save-mark restore-mark nfmask ctmask mask",
	"NOTRACK":  "", "CT": "*", "LOG": "*", "NFLOG": "*", "ULOG": "*", "MASQUERADE": "*", "SNAT": "*",
	"NETMAP": "*", "TCPMSS": "*", "TOS": "*", "DSCP": "*", "TTL": "*", "HL": "*", "CHECKSUM": "*",
	"CLASSIFY": "*", "SECMARK": "*", "CONNSECMARK": "*", "AUDIT": "*", "TRACE": "*", "SET": "*",
	"RATEEST": "*", "IDLETIMER": "*", "LED": "*", "TEE": "*",
}

var implicitModule = map[string]string{"tcp": "tcp", "6": "tcp", "udp": "udp", "17": "udp", "sctp": "sctp",
	"dccp": "dccp", "udplite": "udplite", "icmp": "icmp", "1": "icmp", "ipv6-icmp": "icmp6", "icmpv6": "icmp6", "58": "icmp6"}

func hasWord(list, w string) bool {
	if list == "*" {
		return true
	}
	for _, x := range strings.Fields(list) {
		if x == w {
			return true
		}
	}
	return false
}

// checkRule fails the test when the rule has an option outside the lists above and no Unknown.
func checkRule(t *testing.T, tbl *rules.Table, r *rules.Rule) {
	t.Helper()
	toks, err := tokenize(r.Text)
	if err != nil {
		t.Errorf("%s: %v", r.Text, err)
		return
	}
	hasUnknown := false
	for _, e := range r.Exprs {
		if e == nil {
			t.Errorf("%s: nil expression", r.Text)
		}
		switch e.(type) {
		case *rules.Unknown, *rules.UnknownStmt:
			hasUnknown = true
		}
	}
	need := func(why string) {
		if !hasUnknown {
			t.Errorf("%s: %s, yet no Unknown in:\n%s", r.Text, why, dumpList(r.Exprs))
		}
	}
	ctx, proto := "", ""
	for i := 2; i < len(toks); i++ {
		tk := toks[i]
		if tk.quoted || !strings.HasPrefix(tk.s, "-") || len(tk.s) < 2 || (tk.s[1] >= '0' && tk.s[1] <= '9') {
			continue
		}
		next := ""
		if i+1 < len(toks) {
			next = toks[i+1].s
		}
		switch tk.s {
		case "-s", "-d", "-i", "-o", "-f", "-4", "-6", "-c", "--source", "--destination", "--in-interface", "--out-interface":
			continue
		case "-p":
			proto = next
			continue
		case "-m":
			ctx = "m:" + next
			if _, ok := modeledMatchOpts[next]; !ok {
				need("unmodelled match " + next)
			}
			i++
			continue
		case "-j", "-g":
			ctx = "j:" + next
			if _, ok := modeledTargetOpts[next]; !ok {
				if _, chain := tbl.Chains[next]; !chain || tbl.Chains[next].Base {
					need("unmodelled target " + next)
				}
			}
			i++
			continue
		}
		opt := strings.TrimLeft(tk.s, "-")
		switch {
		case strings.HasPrefix(ctx, "m:"):
			if list, ok := modeledMatchOpts[ctx[2:]]; ok && !hasWord(list, opt) {
				need("unmodelled option --" + opt)
			}
		case strings.HasPrefix(ctx, "j:"):
			if list, ok := modeledTargetOpts[ctx[2:]]; ok && !hasWord(list, opt) {
				need("unmodelled target option --" + opt)
			}
		default:
			if m, ok := implicitModule[proto]; ok {
				if !hasWord(modeledMatchOpts[m], opt) {
					need("unmodelled option --" + opt)
				}
			} else {
				need("option --" + opt + " outside any match")
			}
		}
	}
}

func TestNoSilentLoss(t *testing.T) {
	files := map[string]string{"docker-ufw.save": "ip", "plain.save": "ip", "ip6.save": "ip6", "incompatible.save": "ip", "extensions.save": "ip"}
	for f, fam := range files {
		in, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		tables, _, err := ParseSave(string(in), Options{Family: fam})
		if err != nil {
			t.Fatal(err)
		}
		for _, tbl := range tables {
			for _, c := range tbl.Chains {
				for _, r := range c.Rules {
					checkRule(t, tbl, r)
				}
			}
		}
	}
	// Options the model does not know must surface, wherever they appear.
	for _, rest := range []string{
		"-p tcp -m tcp --dport 22 --tcp-option 5 -j ACCEPT",
		"-p tcp --dport 22 --frob -j ACCEPT",
		"-m conntrack --ctstate NEW --ctreplsrc 192.0.2.1 -j ACCEPT",
		"-m addrtype --dst-type LOCAL --limit-iface-out -j ACCEPT",
		"-m rpfilter --validmark -j DROP",
		"-m policy --dir in --pol ipsec --reqid 3 -j ACCEPT",
		"-m set --match-set blocklist src --bytes-lt 9 -j DROP",
		"-j CONNMARK --set-xmark 0x1/0x1 --right-shift-mark 2",
		"-j MARK --set-xmark 0x1/0x1 --bogus 1",
		"-m frobnicate --x 1 -j ACCEPT",
		"-j NFQUEUE --queue-bypass",
	} {
		text := header("filter") + "-A INPUT " + rest + "\nCOMMIT\n"
		tables, _, err := ParseSave(text, Options{SetDims: testDims})
		if err != nil {
			t.Fatal(err)
		}
		r := tables[0].Chains["INPUT"].Rules[0]
		hasUnknown := false
		for _, e := range r.Exprs {
			switch e.(type) {
			case *rules.Unknown, *rules.UnknownStmt:
				hasUnknown = true
			}
		}
		if !hasUnknown {
			t.Errorf("%s: no Unknown:\n%s", rest, dumpList(r.Exprs))
		}
		checkRule(t, tables[0], r)
	}
}
