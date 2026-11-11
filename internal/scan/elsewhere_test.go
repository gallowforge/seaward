package scan_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

// The machine of the small cases, with more addresses than eth0's own: a spare public address on
// the loopback, one on a dummy interface, and a Docker bridge.
const (
	loVIP     = `,{"family":"inet","local":"203.0.113.99","prefixlen":32,"scope":"global"}`
	ifLo      = `{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}%s]}`
	ifEth0    = `{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"link_type":"ether","addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global"}]}`
	ifDocker  = `{"ifindex":3,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"link_type":"ether","linkinfo":{"info_kind":"bridge"},"addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"}]}`
	ifDummy   = `{"ifindex":4,"ifname":"dummy0","flags":["BROADCAST","NOARP","UP","LOWER_UP"],"link_type":"ether","linkinfo":{"info_kind":"dummy"},"addr_info":[{"family":"inet","local":"203.0.113.98","prefixlen":32,"scope":"global"}]}`
	acceptAll = ":INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n"
)

func lo(more string) string { return strings.Replace(ifLo, "%s", more, 1) }

// wider writes a snapshot of that machine with the interfaces given.
func wider(ifaces []string, filter string, listeners ...string) string {
	return "# seaward snapshot 1\n### meta\nhost box\nseaward test\ncollector cli\nroot yes\n" +
		"### iptables-version\niptables v1.8.10 (nf_tables)\n### iptables-save\n*filter\n" + filter + "COMMIT\n" +
		"### ss\n" + strings.Join(listeners, "\n") + "\n### ip-addr\n[" + strings.Join(ifaces, ",") + "]\n" +
		"### ip-route-4\n" + route4 + "\n### sysctl\nnet.ipv4.ip_forward = 0\n"
}

func cellTo(p *scan.Port, vantage, dst string) *scan.Cell {
	for i := range p.Cells {
		if p.Cells[i].Vantage == vantage && p.Cells[i].Dst == dst {
			return &p.Cells[i]
		}
	}
	return nil
}

// A service bound to a spare address on the loopback or on a dummy interface is reached through
// eth0: Linux takes a packet for any address it holds.
func TestAddressElsewhere(t *testing.T) {
	for _, c := range []struct{ name, iface, on, addr string }{
		{"loopback", lo(loVIP), "lo", "203.0.113.99"},
		{"dummy", ifDummy, "dummy0", "203.0.113.98"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ifaces := []string{lo(""), ifEth0, c.iface}
			if c.on == "lo" {
				ifaces = []string{c.iface, ifEth0}
			}
			r := report(t, wider(ifaces, acceptAll, `tcp LISTEN 0 511 `+c.addr+`:80 0.0.0.0:* users:(("nginx",pid=1012,fd=6))`))
			eq(t, "headline", r.Headline, "1 port can be reached from outside.")
			eq(t, "findings", findings(r), "open tcp 80")
			p := port(t, r, "tcp", 80)
			eq(t, "reach", p.Reach, "the internet")
			eq(t, "service", p.Service, "nginx")
			eq(t, "why", p.Why, "No rule stops it: chain INPUT ends with policy accept. The packet is for "+c.addr+", an address on "+c.on+
				": Linux takes packets for any address it holds, whichever interface they arrive on.")
			if len(r.Vantages) != 2 {
				t.Errorf("the interface that only holds the address became a place to look from: %+v", r.Vantages)
			}
			if far := cellTo(p, "internet", c.addr); far == nil || far.Class != "open" {
				t.Errorf("from the internet to %s: %+v", c.addr, far)
			}
			if own := cellTo(p, "internet", "203.0.113.10"); own == nil || own.Class != "closed" {
				t.Errorf("from the internet to eth0's own address: %+v", own)
			}
		})
	}
}

// A bridge's private address cannot be routed from the wide world, but a neighbour on eth0's
// network can send to it through this machine.
func TestBridgeAddressFromTheLocalNetwork(t *testing.T) {
	r := report(t, wider([]string{lo(""), ifEth0, ifDocker}, acceptAll, `tcp LISTEN 0 128 172.17.0.1:9000 0.0.0.0:* users:(("minio",pid=7,fd=3))`))
	eq(t, "findings", findings(r), "limited tcp 9000")
	p := port(t, r, "tcp", 9000)
	eq(t, "title", p.Title, "Reachable from the local network only.")
	if !strings.Contains(p.Why, "The packet is for 172.17.0.1, an address on docker0") {
		t.Errorf("why: %q", p.Why)
	}
	if c := cellTo(p, "internet", "172.17.0.1"); c != nil {
		t.Errorf("a private address was asked about from the internet: %+v", c)
	}
	if c := cellTo(p, "lan:eth0", "172.17.0.1"); c == nil || c.Class != "open" {
		t.Errorf("from the local network to the bridge: %+v", c)
	}
	// A rule that looks at the arriving interface keeps the service to the containers.
	r = report(t, wider([]string{lo(""), ifEth0, ifDocker}, acceptAll+"-A INPUT -d 172.17.0.1/32 ! -i docker0 -j DROP\n",
		`tcp LISTEN 0 128 172.17.0.1:9000 0.0.0.0:* users:(("minio",pid=7,fd=3))`))
	eq(t, "findings, guarded", findings(r), "blocked tcp 9000")
	p = port(t, r, "tcp", 9000)
	if p.Deciding == nil || p.Deciding.Rule != "-A INPUT -d 172.17.0.1/32 ! -i docker0 -j DROP" {
		t.Errorf("deciding: %+v", p.Deciding)
	}
}

// Addresses elsewhere add nothing to a report when they say nothing new: a service on every
// address is told once, and "nothing listens there" is not repeated per address.
func TestAddressElsewhereIsQuiet(t *testing.T) {
	ifaces := []string{lo(loVIP), ifEth0, ifDocker, ifDummy}
	for _, l := range []string{sshd, `tcp LISTEN 0 128 203.0.113.10:22 0.0.0.0:* users:(("sshd",pid=830,fd=3))`} {
		r := report(t, wider(ifaces, acceptAll, l))
		p := port(t, r, "tcp", 22)
		eq(t, "finding", p.Finding, scan.Open)
		eq(t, "why", p.Why, "No rule stops it: chain INPUT ends with policy accept.")
		for _, c := range p.Cells {
			if c.Dst != "203.0.113.10" {
				t.Errorf("%s: a line for %s, which says nothing new: %s", l, c.Dst, c.Why)
			}
		}
		if len(p.Cells) != 2 {
			t.Errorf("%s: %d cells, want one from the internet and one from the local network", l, len(p.Cells))
		}
	}
	// Nothing listens anywhere outside: closed is said once per place, at eth0's own address.
	r := report(t, wider(ifaces, acceptAll, `tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=9,fd=3))`))
	p := port(t, r, "tcp", 5432)
	eq(t, "finding", p.Finding, scan.Local)
	if len(p.Cells) != 2 {
		t.Errorf("loopback-only service: %d cells", len(p.Cells))
	}
}

// A rule that names the spare address decides for it, and is named.
func TestAddressElsewhereDecidedByItsRule(t *testing.T) {
	r := report(t, wider([]string{lo(loVIP), ifEth0}, acceptAll+"-A INPUT -d 203.0.113.99/32 -p tcp -m tcp --dport 80 -j DROP\n",
		`tcp LISTEN 0 511 203.0.113.99:80 0.0.0.0:* users:(("nginx",pid=1012,fd=6))`))
	eq(t, "headline", r.Headline, "Nothing can be reached from outside.")
	p := port(t, r, "tcp", 80)
	eq(t, "finding", p.Finding, scan.Blocked)
	if p.Deciding == nil || !strings.Contains(p.Deciding.Rule, "-d 203.0.113.99/32") {
		t.Errorf("deciding: %+v", p.Deciding)
	}
}

// The loopback range itself is never aimed at from outside: the kernel drops such a packet.
func TestLoopbackRangeIsNotAsked(t *testing.T) {
	r := report(t, wider([]string{lo(loVIP), ifEth0}, acceptAll, `tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=9,fd=3))`))
	for _, p := range r.Ports {
		for _, c := range p.Cells {
			if a, err := netip.ParseAddr(c.Dst); err != nil || a.IsLoopback() {
				t.Errorf("%s %d: a packet was sent to %s", p.Proto, p.Port, c.Dst)
			}
		}
	}
}

// "seaward why PORT --from ADDR": a sender far away is followed to the public addresses the
// machine holds elsewhere, one on eth0's network to every address, where the answer is another.
func TestTraceElsewhere(t *testing.T) {
	text := wider([]string{lo(loVIP), ifEth0, ifDocker}, acceptAll,
		`tcp LISTEN 0 511 203.0.113.99:80 0.0.0.0:* users:(("nginx",pid=1012,fd=6))`,
		`tcp LISTEN 0 128 172.17.0.1:9000 0.0.0.0:* users:(("minio",pid=7,fd=3))`)
	b, err := snapshot.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		t.Fatal(err)
	}
	dsts := func(port uint16, from string) string {
		var out []string
		for _, c := range scan.Trace(rs, h, "tcp", port, netip.MustParseAddr(from)) {
			out = append(out, c.Dst+" "+c.Class)
		}
		return strings.Join(out, ", ")
	}
	eq(t, "far sender, port 80", dsts(80, "198.51.100.7"), "203.0.113.10 closed, 203.0.113.99 open")
	eq(t, "far sender, port 9000", dsts(9000, "198.51.100.7"), "203.0.113.10 closed")
	eq(t, "neighbour, port 9000", dsts(9000, "203.0.113.50"), "203.0.113.10 closed, 172.17.0.1 open")
	cells := scan.Trace(rs, h, "tcp", 9000, netip.MustParseAddr("203.0.113.50"))
	if got := cells[len(cells)-1].Why; !strings.HasSuffix(got, "an address on docker0: Linux takes packets for any address it holds, whichever interface they arrive on.") {
		t.Errorf("why: %q", got)
	}
}
