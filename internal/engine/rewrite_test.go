package engine

import (
	"testing"

	"github.com/gallowforge/seaward/internal/rules"
)

// TestRewriteBehindAJump: the rule that names a port and the rule that rewrites the destination
// are often two rules. The first jumps, or goes to, or looks the port up in a verdict map, and a
// chain further on does the rewriting. The packet is rewritten all the same, and the trace names
// the rule that did it in its own chain. The kernel lab proves the same (scenarios
// dnat-behind-jump and nft-dnat-behind-jump).
func TestRewriteBehindAJump(t *testing.T) {
	h := twoArmed(lis("0.0.0.0", 9000, "app"))
	span := func(lo, hi uint32) *rules.Match { return rules.Eq(rules.FDport, rules.NumRange(lo, hi)) }
	byPort := &rules.VerdictMap{Key: []rules.Field{{Name: rules.FDport}}, Entries: []rules.VmapEntry{
		{Key: rules.Elem{rules.Num(8200)}, Verdict: *jump("FWD")},
		{Key: rules.Elem{rules.Num(8201)}, Verdict: *gotoc("DEEP")},
		{Key: rules.Elem{rules.Num(8202)}, Verdict: *v(rules.Accept)},
	}}
	rs := ruleset(tbl("ip", "nat",
		base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
			rule("-A PREROUTING -p tcp --dport 8000:8010 -j FWD", tcp(), span(8000, 8010), jump("FWD")),
			rule("-A PREROUTING -p tcp --dport 8100 -g DEEP", tcp(), dport(8100), gotoc("DEEP")),
			rule("tcp dport vmap { 8200 : jump FWD, 8201 : goto DEEP, 8202 : accept }", tcp(), byPort),
			rule("-A PREROUTING -p tcp --dport 8300:8310 -j NARROW", tcp(), span(8300, 8310), jump("NARROW"))),
		sub("FWD",
			rule("-A FWD -p tcp --dport 8005 -j RETURN", tcp(), dport(8005), v(rules.Return)),
			rule("-A FWD -j DNAT --to-destination 192.0.2.50", &rules.DNAT{Addr: ip(inside)})),
		sub("DEEP",
			rule("-A DEEP -j LAST", jump("LAST"))),
		sub("LAST",
			rule("-A LAST -p tcp -j REDIRECT --to-ports 9000", tcp(), &rules.Redirect{Port: 9000})),
		// The port is named a second time in the chain jumped to: both have to hold.
		sub("NARROW",
			rule("-A NARROW -p tcp --dport 8305 -j DNAT --to-destination 192.0.2.50:9000", tcp(), dport(8305), &rules.DNAT{Addr: ip(inside), Port: 9000}),
			rule("-A NARROW -p tcp --dport 8400 -j DNAT --to-destination 192.0.2.50:9000", tcp(), dport(8400), &rules.DNAT{Addr: ip(inside), Port: 9000})),
	))
	for _, c := range []struct {
		port  uint16
		want  Class
		chain string // the chain of the rule that rewrote it; "" when nothing did
		to    uint16 // the port it ends on
	}{
		{8000, Forwarded, "FWD", 8000},
		{8010, Forwarded, "FWD", 8010},
		{8005, Closed, "", 8005}, // returned from the chain before its rewrite
		{8011, Closed, "", 8011}, // the calling rule does not hold
		{7999, Closed, "", 7999},
		{8100, Open, "LAST", 9000}, // by goto, and one jump further
		{8200, Forwarded, "FWD", 8200},
		{8201, Open, "LAST", 9000},
		{8202, Closed, "", 8202}, // the map's verdict for it is accept, in a nat chain: nothing changes
		{8203, Closed, "", 8203}, // no entry in the map
		{8305, Forwarded, "NARROW", 9000},
		{8304, Closed, "", 8304},
		{8400, Closed, "", 8400}, // named in the chain, and no packet for it comes that way
	} {
		r := Run(rs, h, probe(world, me, c.port))
		rw := r.Rewrite()
		got := ""
		if rw != nil {
			got = rw.Chain
		}
		if r.Class != c.want || got != c.chain || r.FinalPort != c.to || r.Rewritten != (c.chain != "") {
			t.Errorf("port %d: %v, rewritten in %q, ends on port %d; want %v, %q, %d\n%s", c.port, r.Class, got, r.FinalPort, c.want, c.chain, c.to, trace(r))
		}
	}
	// The way there is in the trace: the jump, then the rewrite.
	r := Run(rs, h, probe(world, me, 8000))
	if len(r.Steps) < 2 || r.Steps[0].Kind != StepJump || r.Steps[0].Chain != "PREROUTING" || r.Steps[0].Effect != "to chain FWD" ||
		r.Steps[1].Chain != "FWD" || r.Steps[1].Effect != "destination becomes 192.0.2.50:8000" {
		t.Errorf("the trace of port 8000:\n%s", trace(r))
	}
	if r.FinalDst != ip(inside) || r.Out != "eth1" {
		t.Errorf("port 8000 ends at %v and leaves through %q", r.FinalDst, r.Out)
	}
}

// TestRewriteToARangeFromALongRange: of the packets one rule rewrites to a range of ports, those
// that came for a port of the range keep it and all the others get its first port. The ports
// just below the range, the ports in it and the ports just above it therefore fare three ways
// (scenario nat-range-in-a-long-range of the kernel lab).
func TestRewriteToARangeFromALongRange(t *testing.T) {
	h := twoArmed()
	rs := ruleset(
		tbl("ip", "nat", base("PREROUTING", rules.HookPrerouting, "nat", -100, rules.Accept,
			rule("-A PREROUTING -p tcp --dport 8000:9500 -j DNAT --to-destination 192.0.2.50:9000-9100",
				tcp(), rules.Eq(rules.FDport, rules.NumRange(8000, 9500)), &rules.DNAT{Addr: ip(inside), Port: 9000, PortHi: 9100}))),
		tbl("ip", "filter", base("FORWARD", rules.HookForward, "filter", 0, rules.Drop,
			rule("-A FORWARD -p tcp --dport 9000 -j ACCEPT", tcp(), dport(9000), v(rules.Accept)))),
	)
	for _, c := range []struct {
		port, to uint16
		want     Class
	}{
		{8000, 9000, Forwarded}, {8999, 9000, Forwarded}, {9000, 9000, Forwarded},
		{9001, 9001, Filtered}, {9100, 9100, Filtered},
		{9101, 9000, Forwarded}, {9500, 9000, Forwarded},
		{9501, 9501, Closed}, // not rewritten at all
	} {
		r := Run(rs, h, probe(world, me, c.port))
		if r.Class != c.want || r.FinalPort != c.to {
			t.Errorf("port %d: %v on port %d, want %v on port %d\n%s", c.port, r.Class, r.FinalPort, c.want, c.to, trace(r))
		}
	}
}
