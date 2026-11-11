package engine

import (
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/rules"
)

// The report shows one rule per port as "decided by". These are the cases it is picked from.
func TestDeciding(t *testing.T) {
	h := withContainer(machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 25, "smtpd")), lis("0.0.0.0", 80, "nginx"))
	rs := dockerRules()

	// Let through to a container: the rewrite, and the forward rule that accepted it.
	r := Run(rs, h, probe(world, me, 8080))
	want(t, r, Open)
	rw, d := r.Rewrite(), r.Deciding()
	if rw == nil || rw.Table != "nat" || !strings.HasPrefix(rw.Effect, "destination becomes 172.17.0.2:80") {
		t.Fatalf("rewrite: %+v\n%s", rw, trace(r))
	}
	if d == nil || d.Kind != StepRule || d.Effect != "accept" || d.Hook != rules.HookForward {
		t.Fatalf("deciding: %+v\n%s", d, trace(r))
	}

	// Stopped by a policy: the policy is the answer, and nothing was rewritten.
	r = Run(rs, h, probe(world, me, 25))
	want(t, r, Filtered)
	if d = r.Deciding(); d == nil || d.Kind != StepPolicy || !strings.HasPrefix(d.Effect, "policy drop") || !d.Decisive {
		t.Fatalf("deciding: %+v\n%s", d, trace(r))
	}
	if r.Rewrite() != nil {
		t.Fatalf("a rewrite on a packet nothing rewrote:\n%s", trace(r))
	}

	// Stopped by a rule, refused by a rule, accepted by a rule with nothing listening.
	fw := ruleset(tbl("ip", "filter", base("INPUT", rules.HookInput, "filter", 0, rules.Accept,
		rule("-A INPUT -p tcp --dport 25 -j DROP", tcp(), dport(25), v(rules.Drop)),
		rule("-A INPUT -p tcp --dport 22 -j REJECT", tcp(), dport(22), v(rules.Reject)),
		rule("-A INPUT -p tcp --dport 9000 -j ACCEPT", tcp(), dport(9000), v(rules.Accept)),
	)))
	for _, c := range []struct {
		port  uint16
		class Class
		rule  string
	}{
		{25, Filtered, "-A INPUT -p tcp --dport 25 -j DROP"},
		{22, Rejected, "-A INPUT -p tcp --dport 22 -j REJECT"},
		{9000, Closed, "-A INPUT -p tcp --dport 9000 -j ACCEPT"},
	} {
		r = Run(fw, h, probe(world, me, c.port))
		want(t, r, c.class)
		if d = r.Deciding(); d == nil || d.Rule != c.rule {
			t.Errorf("port %d: deciding %+v\n%s", c.port, d, trace(r))
		}
	}

	// No rules at all: nothing in the rules had a say.
	r = Run(ruleset(), h, probe(world, me, 22))
	want(t, r, Open)
	if r.Deciding() != nil || r.Rewrite() != nil {
		t.Fatalf("no rules, yet deciding %+v, rewrite %+v", r.Deciding(), r.Rewrite())
	}

	// An accept policy with no matching rule is the answer for a packet that got in.
	r = Run(fw, h, probe(world, me, 80))
	want(t, r, Closed)
	if d = r.Deciding(); d == nil || d.Kind != StepPolicy || !strings.HasPrefix(d.Effect, "policy accept") {
		t.Fatalf("deciding: %+v\n%s", d, trace(r))
	}

	// Undecided: no single rule is named.
	un := ruleset(tbl("ip", "filter", base("INPUT", rules.HookInput, "filter", 0, rules.Drop,
		rule("-A INPUT -m frobnicate -j ACCEPT", &rules.Unknown{Why: "the frobnicate match is not one seaward knows"}, v(rules.Accept)),
	)))
	r = Run(un, h, probe(world, me, 22))
	want(t, r, Undecided)
	if r.Deciding() != nil {
		t.Fatalf("an undecided packet with a deciding rule: %+v", r.Deciding())
	}
}

// A verdict map with no entry for the packet ends its rule, as the kernel's lookup does; an entry
// that says continue goes on with the rest of the rule.
func TestVerdictMapMiss(t *testing.T) {
	h := machine(lis("0.0.0.0", 22, "sshd"), lis("0.0.0.0", 80, "nginx"), lis("0.0.0.0", 443, "caddy"))
	key := []rules.Field{{Name: rules.FDport}}
	rs := ruleset(tbl("inet", "fw", base("input", rules.HookInput, "filter", 0, rules.Drop,
		rule("tcp dport vmap { 22 : continue, 80 : drop } accept",
			&rules.VerdictMap{Key: key, Entries: []rules.VmapEntry{
				{Key: rules.Elem{rules.Num(22)}, Verdict: rules.Verdict{Kind: rules.Continue}},
				{Key: rules.Elem{rules.Num(80)}, Verdict: rules.Verdict{Kind: rules.Drop}},
			}},
			v(rules.Accept)),
	)))
	want(t, Run(rs, h, probe(world, me, 22)), Open)      // continue, then the accept
	want(t, Run(rs, h, probe(world, me, 80)), Filtered)  // the map's own drop
	want(t, Run(rs, h, probe(world, me, 443)), Filtered) // no entry: the accept is never reached
	if d := decisive(t, Run(rs, h, probe(world, me, 443))); d.Kind != StepPolicy {
		t.Fatalf("a miss should fall to the policy, got %+v", d)
	}
}
