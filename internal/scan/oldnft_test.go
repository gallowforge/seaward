package scan_test

import (
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/scan"
)

// An ingress chain as nft 1.0.9 lists it in JSON: no "dev" at all. Ubuntu 24.04 ships that nft.
// The chain drops port 80 as it arrives on eth0; sshd and nginx listen, and nothing else filters.
const (
	oldNftJSON = `{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, ` +
		`{"table": {"family": "netdev", "name": "early", "handle": 1}}, ` +
		`{"chain": {"family": "netdev", "table": "early", "name": "ingress", "handle": 1, "type": "filter", "hook": "ingress", "prio": -500, "policy": "accept"}}, ` +
		`{"rule": {"family": "netdev", "table": "early", "chain": "ingress", "handle": 2, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 80}}, {"drop": null}]}}]}`
	oldNftText = "table netdev early {\n\tchain ingress {\n\t\ttype filter hook ingress device \"eth0\" priority -500; policy accept;\n\t\ttcp dport 80 drop\n\t}\n}\n"
)

// oldNft is a snapshot of that machine: with the text listing a current collector takes beside
// the JSON, or, with text "", as a snapshot taken before the text was kept has it.
func oldNft(text string) string {
	rules := "### nft-json\n" + oldNftJSON + "\n"
	if text != "" {
		rules += "### nft-text\n" + text
	}
	return strings.Replace(machine(true, "", []string{sshd, nginx}, ""), "### ss\n", rules+"### ss\n", 1)
}

// TestIngressChainOfAnOlderNft: the report for a machine whose nft leaves the interface of a
// chain out of its JSON. 0.1.0, and 0.1.1 until its own CI ran on such a machine, took the chain
// for one attached to nothing, said so in a note, and called port 80 open.
func TestIngressChainOfAnOlderNft(t *testing.T) {
	// The text listing names the interface: the chain is walked, and port 80 is stopped by it.
	r := report(t, oldNft(oldNftText))
	eq(t, "with the text listing", findings(r), "open tcp 22, blocked tcp 80")
	eq(t, "with the text listing, headline", r.Headline, "1 port can be reached from outside.")
	if len(r.Unfollowed) != 0 {
		t.Errorf("with the text listing, not followed: %q", r.Unfollowed)
	}
	if web := port(t, r, "tcp", 80); web.Deciding == nil || web.Deciding.Chain != "ingress" || web.Deciding.Rule != "tcp dport 80 drop" {
		t.Errorf("with the text listing, port 80 is decided by %+v", web.Deciding)
	}

	// No text listing: the chain may be on any interface, and nothing it could stop is decided.
	r = report(t, oldNft(""))
	eq(t, "the JSON alone", findings(r), "undecided tcp 22, undecided tcp 80")
	eq(t, "the JSON alone, headline", r.Headline, "2 ports could not be decided.")
	const why = "The chain ingress of table netdev early acts on packets as they arrive on an interface the snapshot does not name: " +
		"nft's JSON listing gives none (nft 1.0.9, for one, never does), and the snapshot has no text listing, " +
		"which seaward 0.1.1 and later save beside it and which settles the question."
	if len(r.Unfollowed) != 1 || r.Unfollowed[0] != why {
		t.Errorf("the JSON alone, not followed: %q", r.Unfollowed)
	}
	for _, n := range r.Notes {
		if strings.Contains(n, "attached to no interface") {
			t.Errorf("the chain is called attached to nothing: %q", n)
		}
	}
	for _, p := range r.Ports {
		if p.Finding == scan.Open || p.Finding == scan.Exposed || p.Reach != "not known" {
			t.Errorf("the JSON alone, tcp %d: %s, reached by %q", p.Port, p.Finding, p.Reach)
		}
	}
	out := scan.Text(r, scan.TextOptions{})
	if !strings.Contains(out, "\nnot followed  The chain ingress of table netdev early acts on packets as they arrive on an interface") ||
		strings.Contains(out, "  open ") {
		t.Errorf("the JSON alone, as text:\n%s", out)
	}

	// The text declares the chain with no interface: then it is attached to nothing, the note
	// says so, and both ports are as open as the rest of the rules leave them.
	r = report(t, oldNft(strings.Replace(oldNftText, ` device "eth0"`, "", 1)))
	eq(t, "declared with no interface", findings(r), "open tcp 22, open tcp 80")
	if len(r.Unfollowed) != 0 || len(notesWith(r, "it is attached to no interface, so it sees no packets")) != 1 {
		t.Errorf("declared with no interface: not followed %q, notes %q", r.Unfollowed, r.Notes)
	}
	// On another interface than the one packets arrive on, the chain sees none of them.
	r = report(t, oldNft(strings.Replace(oldNftText, `"eth0"`, `"eth7"`, 1)))
	eq(t, "on another interface", findings(r), "open tcp 22, open tcp 80")
}
