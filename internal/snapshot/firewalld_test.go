package snapshot

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

// These samples follow the documented output of firewall-cmd: zone blocks with two-space
// indented keys, rich rules and forward ports on tab-indented lines below their key.
const fwZones = `block
  target: %%REJECT%%
  icmp-block-inversion: no
  interfaces:
  sources:
  services:
  ports:
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

docker (active)
  target: ACCEPT
  icmp-block-inversion: no
  interfaces: docker0 br-7d1e0c2a9b44
  sources:
  services:
  ports:
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

internal (active)
  target: DROP
  icmp-block-inversion: no
  interfaces:
  sources: 203.0.113.0/24 ipset:office
  services: ssh
  ports: 9100/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

public (default, active)
  target: default
  ingress-priority: 0
  egress-priority: 0
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: dhcpv6-client http ssh web-extra
  ports: 8080/tcp 60000-61000/udp 5060/sctp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
	port=80:proto=tcp:toport=8080:toaddr=
  source-ports:
  icmp-blocks:
  rich rules:
	rule family="ipv4" source address="198.51.100.0/24" service name="ssh" accept
	rule family="ipv4" source address="192.0.2.66" drop

trusted
  target: ACCEPT
  icmp-block-inversion: no
  interfaces:
  sources:
  services:
  ports:
`

const fwActive = `docker
  interfaces: docker0 br-7d1e0c2a9b44
internal
  sources: 203.0.113.0/24 ipset:office
public (default)
  interfaces: eth0
`

var fwServices = map[string]string{
	"ssh":           "ssh\n  ports: 22/tcp\n  protocols: \n  source-ports: \n  modules: \n  destination: \n  includes: \n  helpers: \n",
	"http":          "http\n  ports: 80/tcp\n  protocols: \n  source-ports: \n  modules: \n  destination: \n  includes: \n  helpers: \n",
	"dhcpv6-client": "dhcpv6-client\n  ports: 546/udp\n  protocols: \n  source-ports: \n  modules: \n  destination: ipv6:fe80::/64\n  includes: \n  helpers: \n",
	"web-extra":     "web-extra\n  ports: \n  protocols: \n  includes: https\n",
	"https":         "https\n  ports: 443/tcp\n",
}

func TestBuildFirewalld(t *testing.T) {
	f, notes := buildFirewalld("running\n", fwZones, fwActive, true, fwServices, nil)
	if f.Tool != "firewalld" || !f.Active {
		t.Fatalf("got %+v", f)
	}
	if f.DefaultIncoming != "reject" {
		t.Errorf("default incoming from the default zone: got %q", f.DefaultIncoming)
	}
	type key struct {
		zone, iface, from, to, proto string
		lo, hi                       uint16
		v6                           bool
	}
	var got []key
	for _, r := range f.Rules {
		if r.Action != "allow" || r.Text == "" {
			t.Errorf("bad rule %+v", r)
		}
		from, to := "", ""
		if r.From.IsValid() {
			from = r.From.String()
		}
		if r.To.IsValid() {
			to = r.To.String()
		}
		got = append(got, key{r.Zone, r.Iface, from, to, r.Proto, r.PortLo, r.PortHi, r.IPv6})
	}
	want := []key{
		// internal: bound by source; the ipset source cannot be read.
		{"internal", "", "203.0.113.0/24", "", "tcp", 9100, 9100, false},
		{"internal", "", "203.0.113.0/24", "", "tcp", 22, 22, false},
	}
	for _, v6 := range []bool{false, true} {
		want = append(want,
			key{"public", "eth0", "", "", "tcp", 8080, 8080, v6},
			key{"public", "eth0", "", "", "udp", 60000, 61000, v6},
			key{"public", "eth0", "", "", "tcp", 80, 80, v6},
			key{"public", "eth0", "", "", "tcp", 22, 22, v6},
			key{"public", "eth0", "", "", "tcp", 443, 443, v6},
		)
	}
	want = append(want, key{"public", "eth0", "", "fe80::/64", "udp", 546, 546, true})
	sortKeys := func(ks []key) {
		slices.SortFunc(ks, func(a, b key) int { return strings.Compare(fmt.Sprint(a), fmt.Sprint(b)) })
	}
	sortKeys(got)
	sortKeys(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	for _, w := range []string{"Rich rules in firewalld zone public", "Port forwarding in firewalld zone public", "ipset:office"} {
		if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, w) }) {
			t.Errorf("no note about %q in %q", w, notes)
		}
	}
	// The docker zone accepts everything by target and opens no port of its own.
	for _, r := range f.Rules {
		if r.Zone == "docker" || r.Zone == "block" || r.Zone == "trusted" {
			t.Errorf("rule from a zone with no openings or not active: %+v", r)
		}
	}
}

func TestBuildFirewalldWithoutActiveSection(t *testing.T) {
	// Without --get-active-zones the "(active)" marks decide.
	f, notes := buildFirewalld("running", fwZones, "", false, map[string]string{"ssh": fwServices["ssh"]}, nil)
	zones := map[string]bool{}
	for _, r := range f.Rules {
		zones[r.Zone] = true
	}
	if !zones["public"] || !zones["internal"] || zones["block"] {
		t.Errorf("zones: %v", zones)
	}
	if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, "http") && strings.Contains(n, "not in the snapshot") }) {
		t.Errorf("missing-service note: %q", notes)
	}
}

func TestBuildFirewalldNotRunning(t *testing.T) {
	f, _ := buildFirewalld("not running\n", "", "", false, nil, nil)
	if f.Active || len(f.Rules) != 0 {
		t.Errorf("got %+v", f)
	}
}

func TestFirewalldServiceConditionsNoted(t *testing.T) {
	zones := "public (default, active)\n  target: default\n  interfaces: eth0\n  services: odd\n"
	svc := map[string]string{"odd": "odd\n  ports: 7000/tcp\n  source-ports: 1000/tcp\n  destination: ipv4:not-an-address\n"}
	f, notes := buildFirewalld("running", zones, "", false, svc, nil)
	if len(f.Rules) != 2 || !slices.ContainsFunc(notes, func(n string) bool {
		return strings.Contains(n, "source ports") && strings.Contains(n, "destination ipv4:not-an-address")
	}) {
		t.Errorf("rules %+v notes %q", f.Rules, notes)
	}
}

func TestFirewalldTargets(t *testing.T) {
	for in, want := range map[string]string{"default": "reject", "%%REJECT%%": "reject", "DROP": "deny", "ACCEPT": "allow"} {
		if got := firewalldTarget(in); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
}

func TestFirewalldOneZoneOnly(t *testing.T) {
	zones := "home (active)\n  target: DROP\n  interfaces: wg0\n  sources: 2001:db8:5::/48\n  services: \n  ports: 51820/udp\n  protocols: tcp\n"
	f, _ := buildFirewalld("running", zones, "", false, nil, nil)
	if f.DefaultIncoming != "deny" {
		t.Errorf("default: %q", f.DefaultIncoming)
	}
	want := []host.FrontendRule{
		{Action: "allow", Proto: "udp", PortLo: 51820, PortHi: 51820, Iface: "wg0", Zone: "home"},
		{Action: "allow", Proto: "udp", PortLo: 51820, PortHi: 51820, Iface: "wg0", Zone: "home", IPv6: true},
		{Action: "allow", Proto: "tcp", Iface: "wg0", Zone: "home"},
		{Action: "allow", Proto: "tcp", Iface: "wg0", Zone: "home", IPv6: true},
		{Action: "allow", Proto: "udp", PortLo: 51820, PortHi: 51820, From: netip.MustParsePrefix("2001:db8:5::/48"), Zone: "home", IPv6: true},
		{Action: "allow", Proto: "tcp", From: netip.MustParsePrefix("2001:db8:5::/48"), Zone: "home", IPv6: true},
	}
	for i := range f.Rules {
		f.Rules[i].Text = ""
	}
	if !reflect.DeepEqual(f.Rules, want) {
		t.Errorf("got  %+v\nwant %+v", f.Rules, want)
	}
}

func TestFirewalldServiceNames(t *testing.T) {
	got := firewalldServiceNames(fwZones)
	want := []string{"ssh", "dhcpv6-client", "http", "web-extra"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
}
