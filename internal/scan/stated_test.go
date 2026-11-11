package scan

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

// What the firewall manager "says" about a port, on a machine with two interfaces facing outside
// and Docker's bridge behind them.
func TestStatedByZone(t *testing.T) {
	ifaces := []host.Interface{
		{Name: "lo", Up: true, Loopback: true},
		{Name: "eth0", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.10/24")}},
		{Name: "eth1", Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.10/24")}},
		{Name: "docker0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "veth1a2b3c4", Up: true, Kind: "veth"},
	}
	zone := func(name, proto string, port uint16, to string, on ...string) []host.FrontendRule {
		var out []host.FrontendRule
		for _, i := range on {
			r := host.FrontendRule{Action: "allow", Proto: proto, PortLo: port, PortHi: port, Iface: i, Zone: name}
			if to != "" {
				r.To = netip.MustParsePrefix(to)
				r.IPv6 = true
			}
			out = append(out, r)
		}
		return out
	}
	var rules []host.FrontendRule
	// The default zone takes every interface no other zone names: one rule per interface.
	rules = append(rules, zone("public", "tcp", 22, "", "eth0", "eth1", "veth1a2b3c4")...)
	// A zone bound to one interface.
	rules = append(rules, zone("internal", "tcp", 5432, "", "eth1")...)
	// The stock dhcpv6-client service: link-local destinations only.
	rules = append(rules, zone("public", "udp", 546, "fe80::/64", "eth0", "eth1", "veth1a2b3c4")...)
	// An opening that only exists on a container's side: no packet from outside arrives there, so it
	// is neither "allowed" nor in the list.
	rules = append(rules, zone("public", "tcp", 9000, "", "veth1a2b3c4")...)

	b := newBuilder(nil, &host.Host{Interfaces: ifaces,
		Frontend: &host.Frontend{Tool: "firewalld", Active: true, DefaultIncoming: "reject", Rules: rules}})
	for _, c := range []struct {
		proto string
		port  uint16
		want  string
	}{
		{"tcp", 22, "allowed"},
		{"tcp", 5432, "allowed only on eth1"},
		{"udp", 546, "allowed only to fe80::/64"},
		{"tcp", 9000, "not allowed"},
		{"tcp", 80, "not allowed"},
	} {
		if got := b.stated(portKey{c.proto, c.port}); got != c.want {
			t.Errorf("%s %d: got %q, want %q", c.proto, c.port, got, c.want)
		}
	}
	if got, want := strings.Join(b.allows(), "; "), "22/tcp; 5432/tcp on eth1; 546/udp to fe80::/64"; got != want {
		t.Errorf("allows:\n got  %s\n want %s", got, want)
	}
	// The dhcpv6 opening is in the list and is no reason to ask about port 546.
	for _, k := range b.candidates() {
		if k.port == 546 {
			t.Errorf("port 546 is asked about, though only link-local packets are allowed to it")
		}
	}

	// ufw names an interface because its owner wrote one: that stays as written.
	u := newBuilder(nil, &host.Host{Interfaces: ifaces[:2], Frontend: &host.Frontend{Tool: "ufw", Active: true, DefaultIncoming: "deny",
		Rules: []host.FrontendRule{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, Iface: "eth0"}}}})
	if got := u.stated(portKey{"tcp", 22}); got != "allowed only on eth0" {
		t.Errorf("ufw: got %q", got)
	}
	if got := strings.Join(u.allows(), "; "); got != "22/tcp on eth0" {
		t.Errorf("ufw allows: got %q", got)
	}
}
