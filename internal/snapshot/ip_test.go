package snapshot

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

func TestParseIPAddr(t *testing.T) {
	p := netip.MustParsePrefix
	tests := []struct {
		name    string
		in      string
		want    []host.Interface
		wantErr bool
	}{
		{"loopback", `[{"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN",
			"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128}]}]`,
			[]host.Interface{{Name: "lo", Up: true, Loopback: true, Addrs: []netip.Prefix{p("127.0.0.1/8"), p("::1/128")}}}, false},
		{"ethernet with link-local", `[{"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
			"addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24},{"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"},
			{"family":"inet6","local":"fe80::5054:ff:fe12:3456","prefixlen":64,"scope":"link"}]}]`,
			[]host.Interface{{Name: "eth0", Up: true, Addrs: []netip.Prefix{p("192.0.2.10/24"), p("2001:db8::10/64"), p("fe80::5054:ff:fe12:3456/64")}}}, false},
		{"bridge without carrier is still up", `[{"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"operstate":"DOWN",
			"linkinfo":{"info_kind":"bridge","info_data":{}},"addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16}]}]`,
			[]host.Interface{{Name: "docker0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{p("172.17.0.1/16")}}}, false},
		{"down veth, no addresses, lifetime-only entry", `[{"ifname":"veth1a2b","flags":["BROADCAST","MULTICAST"],"operstate":"DOWN",
			"linkinfo":{"info_kind":"veth"},"addr_info":[{}, {"family":"inet","local":"bogus","prefixlen":24}]}]`,
			[]host.Interface{{Name: "veth1a2b", Kind: "veth"}}, false},
		{"wireguard point to point", `[{"ifname":"wg0","flags":["POINTOPOINT","NOARP","UP","LOWER_UP"],"linkinfo":{"info_kind":"wireguard"},
			"addr_info":[{"family":"inet","local":"10.8.0.1","prefixlen":24}]}]`,
			[]host.Interface{{Name: "wg0", Up: true, Kind: "wireguard", Addrs: []netip.Prefix{p("10.8.0.1/24")}}}, false},
		{"missing prefixlen means a host address", `[{"ifname":"dummy0","flags":["UP"],"addr_info":[{"family":"inet","local":"192.0.2.99"}]}]`,
			[]host.Interface{{Name: "dummy0", Up: true, Addrs: []netip.Prefix{p("192.0.2.99/32")}}}, false},
		{"empty list", `[]`, nil, false},
		{"not json", `1: lo: <LOOPBACK,UP>`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPAddr(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseIPRoute(t *testing.T) {
	p := netip.MustParsePrefix
	a := netip.MustParseAddr
	tests := []struct {
		name    string
		in      string
		six     bool
		want    []host.Route
		wantErr bool
	}{
		{"ipv4 main table", `[{"dst":"default","gateway":"192.0.2.1","dev":"eth0","protocol":"dhcp","metric":100,"flags":[]},
			{"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]},
			{"dst":"192.0.2.53","dev":"eth0","scope":"link"},
			{"type":"blackhole","dst":"198.51.100.0/24","flags":[]},
			{"type":"unreachable","dst":"203.0.113.0/24","flags":[]}]`, false,
			[]host.Route{
				{Dst: p("0.0.0.0/0"), Dev: "eth0", Gateway: a("192.0.2.1"), Type: "unicast"},
				{Dst: p("172.17.0.0/16"), Dev: "docker0", Type: "unicast"},
				{Dst: p("192.0.2.53/32"), Dev: "eth0", Type: "unicast"},
				{Dst: p("198.51.100.0/24"), Type: "blackhole"},
				{Dst: p("203.0.113.0/24"), Type: "unreachable"},
			}, false},
		{"ipv6 with link-local gateway", `[{"dst":"2001:db8::/64","dev":"eth0","metric":256},
			{"dst":"fe80::/64","dev":"eth0"},{"dst":"default","gateway":"fe80::1","dev":"eth0","metric":1024}]`, true,
			[]host.Route{
				{Dst: p("2001:db8::/64"), Dev: "eth0", Type: "unicast"},
				{Dst: p("fe80::/64"), Dev: "eth0", Type: "unicast"},
				{Dst: p("::/0"), Dev: "eth0", Gateway: a("fe80::1"), Type: "unicast"},
			}, false},
		{"multipath", `[{"dst":"default","nexthops":[{"gateway":"192.0.2.1","dev":"eth0","weight":1},{"gateway":"198.51.100.1","dev":"eth1","weight":1}]}]`, false,
			[]host.Route{{Dst: p("0.0.0.0/0"), Dev: "eth0", Gateway: a("192.0.2.1"), Type: "unicast"}}, false},
		{"unmasked destination is masked", `[{"dst":"192.0.2.77/24","dev":"eth0"}]`, false,
			[]host.Route{{Dst: p("192.0.2.0/24"), Dev: "eth0", Type: "unicast"}}, false},
		{"empty output", "", true, nil, false},
		{"bad destination skipped", `[{"dst":"nonsense","dev":"eth0"}]`, false, nil, false},
		{"missing destination is not a default route", `[{"dev":"eth0"}]`, false, nil, false},
		{"not json", "default via 192.0.2.1 dev eth0", false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIPRoute(tt.in, tt.six)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseSysctl(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		f4, f6   bool
		localnet map[string]bool
		seen4    bool
	}{
		{"forwarding on, no localnet", "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 0\nnet.ipv4.conf.all.route_localnet = 0\n",
			true, false, nil, true},
		{"localnet on two interfaces", "net.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 1\n" +
			"net.ipv4.conf.all.route_localnet = 0\nnet.ipv4.conf.docker0.route_localnet = 1\nnet.ipv4.conf.eth0/100.route_localnet = 1\n" +
			"net.ipv4.conf.default.route_localnet = 1\n",
			false, true, map[string]bool{"docker0": true, "eth0.100": true}, true},
		{"all", "net.ipv4.conf.all.route_localnet = 1", false, false, map[string]bool{"all": true}, false},
		{"no spaces and junk", "net.ipv4.ip_forward=1\nsysctl: cannot stat /proc/sys/net/ipv6/conf/all/forwarding\n", true, false, nil, true},
		{"empty", "", false, false, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := parseSysctl(tt.in)
			if s.Forward4 != tt.f4 || s.Forward6 != tt.f6 || s.seen4 != tt.seen4 || !reflect.DeepEqual(s.RouteLocalnet, tt.localnet) {
				t.Errorf("got %+v", s)
			}
		})
	}
}
