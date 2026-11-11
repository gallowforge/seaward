package snapshot

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strings"
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

// maskCases are texts for the hardware mask. In each, << and >> stand around everything that must
// be masked: a hardware address, the digits of a name made from one, a device id. Whatever is
// outside them must come through byte for byte. The addresses are invented, from the range kept
// for documentation (00:00:5e:00:53:xx).
var maskCases = []struct{ name, marked string }{
	// One of everything ip prints, as it prints it: on one line, no spaces.
	{"a whole machine", `[` +
		`{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","link_type":"loopback",` +
		`"address":"<<00:00:00:00:00:00>>","broadcast":"<<00:00:00:00:00:00>>",` +
		`"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},` +
		// A card: its address, the one it was made with, the slot it sits in, its other names
		// (one of them built from the address, as udev builds them), a virtual function.
		`{"ifindex":2,"ifname":"enp1s0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","link_type":"ether",` +
		`"address":"<<00:00:5e:00:53:10>>","broadcast":"<<ff:ff:ff:ff:ff:ff>>","permaddr":"<<00:00:5e:00:53:11>>",` +
		`"parentbus":"pci","parentdev":"0000:01:00.0","altnames":["eno1","enx<<00005e005311>>"],` +
		`"vfinfo_list":[{"vf":0,"link_type":"ether","address":"<<00:00:5e:00:53:71>>","broadcast":"<<ff:ff:ff:ff:ff:ff>>","spoofchk":true}],` +
		`"addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"broadcast":"192.0.2.255","scope":"global","label":"enp1s0:1"},` +
		`{"family":"inet6","local":"2001:db8:10:11:12:13:14:15","prefixlen":64,"scope":"global","valid_life_time":2591999},` +
		`{"family":"inet6","local":"fe80::200:5eff:fe00:5310","prefixlen":64,"scope":"link"}]},` +
		// A bridge: its id carries its address, printed without leading zeros.
		`{"ifindex":3,"ifname":"br0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","link_type":"ether",` +
		`"address":"<<00:00:5e:00:53:20>>","broadcast":"<<ff:ff:ff:ff:ff:ff>>",` +
		`"linkinfo":{"info_kind":"bridge","info_data":{"forward_delay":1500,"hello_timer":0.00,"priority":32768,` +
		`"bridge_id":"8000.<<0:0:5e:0:53:20>>","root_id":"8000.<<0:0:5e:0:53:20>>","group_addr":"<<01:80:c2:00:00:00>>","vlan_protocol":"802.1Q"}},` +
		`"addr_info":[{"family":"inet","local":"198.51.100.1","prefixlen":24}]},` +
		// A port of that bridge.
		`{"ifindex":4,"ifname":"veth7c1d","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"master":"br0","operstate":"UP","link_type":"ether",` +
		`"address":"<<00:00:5e:00:53:31>>","broadcast":"<<ff:ff:ff:ff:ff:ff>>","link_netnsid":0,` +
		`"linkinfo":{"info_kind":"veth","info_slave_kind":"bridge","info_slave_data":{"state":"forwarding","priority":32,"cost":2,` +
		`"root_id":"8000.<<0:0:5e:0:53:20>>","bridge_id":"8000.<<0:0:5e:0:53:20>>","id":"0x8001","no":"0x1"}},"addr_info":[]},` +
		// A VLAN on the card, and a bond with the addresses bonds add.
		`{"ifindex":5,"ifname":"enp1s0.100","link":"enp1s0","flags":["BROADCAST","UP"],"link_type":"ether","address":"<<00:00:5e:00:53:10>>",` +
		`"linkinfo":{"info_kind":"vlan","info_data":{"protocol":"802.1Q","id":100}},"addr_info":[{"family":"inet","local":"203.0.113.5","prefixlen":24}]},` +
		`{"ifindex":6,"ifname":"bond0","flags":["BROADCAST","MASTER","UP"],"link_type":"ether","address":"<<00:00:5E:00:53:40>>",` +
		`"linkinfo":{"info_kind":"bond","info_data":{"mode":"802.3ad","ad_actor_system":"<<00:00:5e:00:53:40>>","ad_info":{"partner_mac":"<<00:00:5e:00:53:41>>"}}},"addr_info":[]},` +
		// InfiniBand: twenty bytes.
		`{"ifindex":7,"ifname":"ib0","flags":["BROADCAST","UP"],"link_type":"infiniband",` +
		`"address":"<<80:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:ff:fe:00:53:50>>","broadcast":"<<00:ff:ff:ff:ff:12:40:1b:ff:ff:00:00:00:00:00:00:ff:ff:ff:ff>>",` +
		`"addr_info":[{"family":"inet","local":"198.51.100.65","prefixlen":26}]},` +
		// Tunnels: their "address" is an IP address, and so is a peer's; those stay.
		`{"ifindex":8,"ifname":"tun0","flags":["POINTOPOINT","UP"],"link_type":"none","linkinfo":{"info_kind":"tun"},` +
		`"addr_info":[{"family":"inet","local":"198.51.100.129","address":"198.51.100.130","prefixlen":32}]},` +
		`{"ifindex":9,"ifname":"sit1","flags":["POINTOPOINT","UP"],"link_type":"sit","address":"192.0.2.10","link_pointtopoint":true,"broadcast":"192.0.2.99","addr_info":[]},` +
		`{"ifindex":10,"ifname":"ip6tnl1","flags":["POINTOPOINT","UP"],"link_type":"tunnel6","address":"2001:db8:10::10","broadcast":"2001:db8:20::20","addr_info":[]},` +
		// Eight bytes: left as it is, see hardwareMasks.
		`{"ifindex":11,"ifname":"wpan0","flags":["UP"],"link_type":"ieee802.15.4","address":"00:00:5e:ff:fe:00:53:60","addr_info":[]},` +
		// An adapter the system named after its address. The name is what rules and routes
		// say, so it stays, here and where another interface points at it; only the copy among
		// the alternative names goes.
		`{"ifindex":12,"ifname":"enx00005e005381","flags":["BROADCAST","UP"],"link_type":"ether","address":"<<00:00:5e:00:53:81>>",` +
		`"parentbus":"usb","parentdev":"2-1:1.0","altnames":["enx<<00005e005381>>","enp0s20f0u1"],"addr_info":[{"family":"inet","local":"203.0.113.81","prefixlen":24}]},` +
		`{"ifindex":13,"ifname":"mv0","link":"enx00005e005381","flags":["BROADCAST","UP"],"link_type":"ether","address":"<<00:00:5e:00:53:82>>",` +
		`"linkinfo":{"info_kind":"macvlan","info_data":{"mode":"source","macaddr_count":1,"macaddr_data":["<<00:00:5e:00:53:83>>"]}},"addr_info":[]},` +
		// A card on an Azure machine: its device id is made from its address.
		`{"ifindex":14,"ifname":"eth1","flags":["BROADCAST","UP"],"link_type":"ether","address":"<<00:00:5e:00:53:90>>",` +
		`"parentbus":"vmbus","parentdev":"<<00005e00-5390-0000-5e00-539000005e00>>","addr_info":[{"family":"inet","local":"203.0.113.90","prefixlen":24}]}]`},

	{"nothing", ``},
	{"an empty list", `[]`},
	{"capital letters", `["<<00:00:5E:00:53:AB>>","<<FF:FF:FF:FF:FF:FF>>"]`},
	{"side by side", `{"a":"<<00:00:5e:00:53:01>>","b":"<<00:00:5e:00:53:02>>","c":["<<00:00:5e:00:53:03>>","<<00:00:5e:00:53:04>>"]}`},
	{"printed with spaces and line ends", "[\n  {\n    \"address\": \"<<00:00:5e:00:53:01>>\",\n    \"ifname\": \"eth0\"\n  }\n]"},
	{"as a key", `{"<<00:00:5e:00:53:01>>":1}`},
	{"already masked", `["xx:xx:xx:xx:xx:xx","8000.xx:xx:xx:xx:xx:xx"]`},
	// How many pairs: six and more, but not eight, which can be an IPv6 address.
	{"fewer than six pairs", `["00","00:00","00:00:5e","00:00:5e:00","00:00:5e:00:53"]`},
	{"seven pairs", `["<<00:00:5e:00:53:01:02>>"]`},
	{"eight pairs", `["00:00:5e:ff:fe:00:53:01","10:11:12:13:14:15:16:17"]`},
	{"nine pairs", `["<<00:00:5e:00:53:01:02:03:04>>"]`},
	{"thirty-two pairs", `["<<00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f>>"]`},
	// IP addresses are never touched, in any spelling.
	{"IPv6", `["2001:db8::1","2001:db8:1:2:3:4:5:6","fe80::200:5eff:fe00:5301","::","::1","::ffff:192.0.2.1","2001:db8::","ab:cd:ef:12:34:56:78:9a","a:b:c:d:e:f:1:2"]`},
	{"IPv4", `["192.0.2.1","0.0.0.0","255.255.255.255"]`},
	// A pair is two digits, except inside a bridge id.
	{"one digit to a group", `["0:0:5e:0:53:1","be:a:b:c:d:e","00:00:5e:00:53:1","0:00:5e:00:53:01"]`},
	{"three digits to a group", `["000:00:5e:00:53:01","00:00:5e:00:53:001"]`},
	{"not hex", `["00:00:5g:00:53:01","zz:zz:zz:zz:zz:zz","00-00-5e-00-53-01","00005e005301","0000.5e00.5301"]`},
	// Only a whole string is a hardware address.
	{"part of a longer string", `["mac 00:00:5e:00:53:01","00:00:5e:00:53:01 ","x00:00:5e:00:53:01","00:00:5e:00:53:01/48","00:00:5e:00:53:01,00:00:5e:00:53:02",":00:00:5e:00:53:01","00:00:5e:00:53:01:"]`},
	{"not in a string at all", `00:00:5e:00:53:01 [00:00:5e:00:53:01] 8000.0:0:5e:0:53:1`},
	{"an unfinished string", `["00:00:5e:00:53:01`},
	// The end of a string after a quote inside it reads as a string too. No interface name can
	// hold a colon, so nothing that matters ends this way, and the JSON stays whole.
	{"after a quote inside a string", `["alt\"<<00:00:5e:00:53:01>>","a\\\"<<00:00:5e:00:53:02>>","b\\00:00:5e:00:53:03"]`},
	// Bridge ids: four digits, a dot, six groups of one or two.
	{"bridge ids", `["8000.<<0:0:5e:0:53:1>>","8000.<<00:00:5e:00:53:01>>","7fff.<<a:b:c:d:e:f>>","FFFF.<<AA:B:CC:D:EE:F>>","0000.<<0:0:0:0:0:0>>"]`},
	{"not bridge ids", `["800.0:0:5e:0:53:1","80000.0:0:5e:0:53:1","8000.0:0:5e:0:53","8000.0:0:5e:0:53:1:2","8000.000:0:5e:0:53:1","8000:0:0:5e:0:53:1","8000..0:0:5e:0:53:1","8000.0:0:5e:0:53:","8000.:0:5e:0:53:1","800g.0:0:5e:0:53:1","8000.0.0.5e.0.53.1","x8000.0:0:5e:0:53:1"]`},
	// A name made from the address: two letters, x, twelve digits, where it stands in a list.
	{"names in a list", `{"altnames":["enx<<00005e005301>>","wlx<<00005E0053AB>>"],"other":["eno1","wwx<<00005e005302>>","enp1s0"]}`},
	{"names that are the value of a key", `{"ifname":"enx00005e005301","master":"enx00005e005301","link":"wlx00005e005302","label":"enx00005e005301"}`},
	{"not such names", `["enx00005e00530","enx00005e0053011","ENX00005e005301","enxx0005e005301","e1x00005e005301","nx00005e005301","enp00005e005301","enx00005e00530g","penx00005e005301","enx00005e005301 "]`},
	{"a name in a list printed with spaces", "[\n  \"enx00005e005301\"\n]"},
	// A device id: the five groups of a UUID, and nothing around them.
	{"device ids", `{"parentdev":"<<00005e00-5301-0000-5e00-530100005e00>>","x":["<<00005E00-5301-4000-8000-00005E005301>>"]}`},
	{"not device ids", `["00005e00-5301-0000-5e00-530100005e0","00005e00-5301-0000-5e00-530100005e000","00005e005301-0000-5e00-530100005e00","00005e00-5301-0000-5e00","g0005e00-5301-0000-5e00-530100005e00","{00005e00-5301-0000-5e00-530100005e00}","00005e00-5301-0000-5e00-530100005e00 ","0000:01:00.0","2-1:1.0","virtio0"]`},
	{"other bytes", "[\"\xff\xfe\",\"<<00:00:5e:00:53:01>>\",\"caf\u00e9 00:00:5e:00:53:02\",\"\u00e900:00:5e:00:53:03\"]"},
}

// unmark splits a marked text into what goes in and what must come out.
func unmark(marked string) (in, want string) {
	var a, b strings.Builder
	for {
		before, rest, ok := strings.Cut(marked, "<<")
		a.WriteString(before)
		b.WriteString(before)
		if !ok {
			return a.String(), b.String()
		}
		was, after, _ := strings.Cut(rest, ">>")
		a.WriteString(was)
		if strings.Contains(was, ":") {
			b.WriteString(maskedMAC)
		} else {
			// The digits of a name, or a device id: an x for each, the dashes kept.
			for _, c := range was {
				if c != '-' {
					c = 'x'
				}
				b.WriteRune(c)
			}
		}
		marked = after
	}
}

func TestMaskHardware(t *testing.T) {
	for _, tt := range maskCases {
		t.Run(tt.name, func(t *testing.T) {
			in, want := unmark(tt.marked)
			got := maskHardware(in)
			if got != want {
				t.Errorf("masked:\n got %s\nwant %s", got, want)
			}
			if again := maskHardware(got); again != got {
				t.Errorf("masking twice changes it again:\n%s", again)
			}
			if json.Valid([]byte(in)) != json.Valid([]byte(got)) {
				t.Errorf("JSON before: %v, after: %v", json.Valid([]byte(in)), json.Valid([]byte(got)))
			}
		})
	}
}

// The reader gets from the masked list exactly what it got from the list as ip printed it.
func TestMaskHardwareKeepsWhatIsRead(t *testing.T) {
	in, _ := unmark(maskCases[0].marked)
	masked := maskHardware(in)
	before, err := parseIPAddr(in)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseIPAddr(masked)
	if err != nil {
		t.Fatalf("the masked list no longer reads: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("interfaces read from the masked list:\n got %+v\nwant %+v", after, before)
	}
	// The fixture is not hollow: the reader finds the interfaces, and what ties them together.
	p := netip.MustParsePrefix
	if len(after) != 14 {
		t.Fatalf("%d interfaces, want 14", len(after))
	}
	for i, want := range map[int]host.Interface{
		1:  {Name: "enp1s0", Up: true, Addrs: []netip.Prefix{p("192.0.2.10/24"), p("2001:db8:10:11:12:13:14:15/64"), p("fe80::200:5eff:fe00:5310/64")}},
		2:  {Name: "br0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{p("198.51.100.1/24")}},
		3:  {Name: "veth7c1d", Up: true, Kind: "veth", Master: "br0"},
		4:  {Name: "enp1s0.100", Up: true, Kind: "vlan", Lower: "enp1s0", Addrs: []netip.Prefix{p("203.0.113.5/24")}},
		11: {Name: "enx00005e005381", Up: true, Addrs: []netip.Prefix{p("203.0.113.81/24")}},
		12: {Name: "mv0", Up: true, Kind: "macvlan", Lower: "enx00005e005381"},
	} {
		if !reflect.DeepEqual(after[i], want) {
			t.Errorf("interface %d:\n got %+v\nwant %+v", i, after[i], want)
		}
	}
	// No hardware address of the machine is left: not as ip prints an address, not as it prints
	// one inside a bridge id, not in a name or a device id made from one.
	for _, gone := range []string{"00:00:5e:00:53", "0:0:5e:0:53", "02:00:5e:ff:fe:00:53:50", "01:80:c2", "ff:ff:ff", "00005e005311", "00005e00-5390"} {
		if strings.Contains(strings.ToLower(masked), gone) {
			t.Errorf("%q is still in the masked list", gone)
		}
	}
	// What stays, and SECURITY.md says so: the other names, the slot a card sits in, every IP
	// address (the kernel built the link-local one from the hardware address), an interface's own
	// name even when the system built it from the address, and an address eight bytes long.
	for _, kept := range []string{`"altnames":["eno1","enxxxxxxxxxxxxx"]`, `"altnames":["enxxxxxxxxxxxxx","enp0s20f0u1"]`, `"parentbus":"pci","parentdev":"0000:01:00.0"`,
		`"parentbus":"usb","parentdev":"2-1:1.0"`, `"parentbus":"vmbus","parentdev":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`, `"local":"fe80::200:5eff:fe00:5310"`,
		`"ifname":"enx00005e005381"`, `"link":"enx00005e005381"`, `"address":"00:00:5e:ff:fe:00:53:60"`, `"address":"192.0.2.10"`, `"address":"198.51.100.130"`} {
		if !strings.Contains(masked, kept) {
			t.Errorf("%s is no longer in the masked list", kept)
		}
	}
}

// wantMasked says what the mask should make of one JSON string, worked out by hand, without a
// regular expression: the test of the expressions must not be the expressions. Listed says that
// the string stands in a list, which is where a name made from an address is masked.
func wantMasked(s string, listed bool) string {
	hex := func(g string, lo, hi int) bool {
		if len(g) < lo || len(g) > hi {
			return false
		}
		return strings.Trim(g, "0123456789abcdefABCDEF") == ""
	}
	if listed && len(s) == 15 && strings.Trim(s[:2], "abcdefghijklmnopqrstuvwxyz") == "" && s[2] == 'x' && hex(s[3:], 12, 12) {
		return s[:3] + "xxxxxxxxxxxx"
	}
	// After a quote inside the string, the rest reads as a string of its own.
	head, tail := "", s
	if i := strings.LastIndexByte(s, '"'); i >= 0 {
		head, tail = s[:i+1], s[i+1:]
	}
	if id := strings.Split(tail, "-"); len(id) == 5 && hex(id[0], 8, 8) && hex(id[1], 4, 4) && hex(id[2], 4, 4) && hex(id[3], 4, 4) && hex(id[4], 12, 12) {
		return head + maskedID
	}
	groups := strings.Split(tail, ":")
	lo, prio := 2, ""
	if p, first, ok := strings.Cut(groups[0], "."); ok && hex(p, 4, 4) {
		// A bridge id: the priority, then six groups that may have lost a leading zero.
		if len(groups) != 6 {
			return s
		}
		groups[0], lo, prio = first, 1, p+"."
	} else if len(groups) < 6 || len(groups) == 8 {
		return s
	}
	for _, g := range groups {
		if !hex(g, lo, 2) {
			return s
		}
	}
	return head + prio + maskedMAC
}

// TestMaskHardwareOnAnyList masks generated interface lists and checks each against wantMasked:
// the JSON still reads, every string in it is what wantMasked says, nothing else moved, and the
// reader gets the same interfaces from it. No key here has the make of a name built from an
// address, so a key is masked only as any other string would be.
func TestMaskHardwareOnAnyList(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 2026))
	pick := func(list ...string) string { return list[r.IntN(len(list))] }
	digits := func(n int) string {
		var sb strings.Builder
		for range n {
			sb.WriteByte("0123456789abcdefABCDEF"[r.IntN(22)])
		}
		return sb.String()
	}
	// colons is n groups of hex digits, each as wide as width says.
	colons := func(n int, width func() int) string {
		gs := make([]string, n)
		for i := range gs {
			gs[i] = digits(width())
		}
		return strings.Join(gs, ":")
	}
	two := func() int { return 2 }
	oneOrTwo := func() int { return 1 + r.IntN(2) }
	loose := func() int { return 1 + r.IntN(4) }
	text := func() string {
		switch r.IntN(14) {
		case 0:
			return colons(6, two) // a MAC
		case 1:
			return colons(1+r.IntN(22), two) // any number of pairs
		case 2:
			return digits(4) + "." + colons(6, oneOrTwo) // a bridge id
		case 3:
			return digits(3+r.IntN(3)) + "." + colons(5+r.IntN(3), loose) // nearly one
		case 4:
			return colons(1+r.IntN(10), loose) // an IPv6 address written out, or nothing at all
		case 5:
			return pick("2001:db8::1", "fe80::200:5eff:fe00:5301", "::1", "::", "192.0.2.7", "203.0.113.255", "::ffff:198.51.100.4")
		case 6:
			return pick("alt\"", "a\\\"", "\\", "é", " ", "x", "<", "8000.", ":") + colons(6, two) // something in front
		case 7:
			return colons(6, two) + pick("\"", "\\", " ", "/64", ":", "x", "\n") // something behind
		case 8:
			return pick("eth0", "enx00005e005301", "br-7d1e0c2a9b44", "wlp2s0", "veth1a2b3c4", "lo", "docker0", "eth0.100", "eth0:1")
		case 9:
			return pick("", "UP", "ether", "pci", "0000:01:00.0", "0x8001", "forwarding", "802.1Q", "xx:xx:xx:xx:xx:xx", "enxxxxxxxxxxxxx")
		case 10:
			return digits(4) + "." + colons(6, two)
		case 11:
			return pick("en", "wl", "ww", "EN", "e", "enp", "x1") + pick("x", "x", "x", "p") + digits(11+r.IntN(3)) // a name made from an address, or nearly
		case 12:
			return pick("", "", "", "{", " ", "a\"") + digits(8) + "-" + digits(4) + "-" + digits(4) + "-" + digits(4) + "-" + digits(10+r.IntN(4)) // a device id, or nearly
		}
		return digits(r.IntN(14))
	}
	name := func() string {
		return pick("lo", "eth0", "enp1s0", "enx00005e005301", "br0", "docker0", "veth1a2b3c4", "eth0.100", "wg0", "")
	}
	addr := func() string {
		return pick("192.0.2.10", "198.51.100.1", "203.0.113.77", "2001:db8::10", "2001:db8:1:2:3:4:5:6", "10:11:12:13:14:15:16:17",
			"fe80::200:5eff:fe00:5310", "::1", "bogus", "", colons(8, loose), colons(8, two))
	}
	hidden, left := 0, 0 // strings that were masked, and strings of the same make that were not
	for n := 0; n < 400; n++ {
		var list []map[string]any
		for range r.IntN(5) {
			link := map[string]any{
				"ifname": name(), "flags": []string{pick("UP", "BROADCAST", "LOOPBACK"), pick("UP", "LOWER_UP", "NO-CARRIER")},
				"operstate": pick("UP", "DOWN", "UNKNOWN"), "address": text(), "broadcast": text(), "kz" + text(): text(), "ab": text(),
				"altnames": []string{text(), text()}, "parentdev": text(), "mtu": r.IntN(9000), "timer": r.Float64(),
				"linkinfo": map[string]any{"info_kind": pick("bridge", "veth", "vlan", "macvlan", "bond", "tun"),
					"info_data":       map[string]any{"bridge_id": text(), "root_id": text(), "group_addr": text(), "macaddr_data": []string{text(), text(), text()}},
					"info_slave_data": map[string]any{"bridge_id": text(), "perm_hwaddr": text(), "id": text()}},
			}
			if r.IntN(2) == 0 {
				link["master"], link["link"] = name(), name()
			}
			var addrs []map[string]any
			for range r.IntN(4) {
				addrs = append(addrs, map[string]any{"family": pick("inet", "inet6"), "local": addr(), "address": addr(), "prefixlen": r.IntN(129), "label": text()})
			}
			link["addr_info"] = addrs
			list = append(list, link)
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(list); err != nil {
			t.Fatal(err)
		}
		in := buf.String()
		masked := maskHardware(in)

		var before, after any
		if err := json.Unmarshal([]byte(in), &before); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(masked), &after); err != nil {
			t.Fatalf("the masked list is not JSON any more: %v\nbefore %.700s\nafter  %.700s", err, in, masked)
		}
		// expect is the list as it should be after masking: the same shape, each string masked or not.
		var expect func(v any, listed bool) any
		expect = func(v any, listed bool) any {
			switch v := v.(type) {
			case string:
				w := wantMasked(v, listed)
				if w != v {
					hidden++
				} else if strings.ContainsAny(v, ":-") || len(v) == 15 {
					left++
				}
				return w
			case []any:
				out := make([]any, len(v))
				for i := range v {
					out[i] = expect(v[i], true)
				}
				return out
			case map[string]any:
				out := map[string]any{}
				for k, x := range v {
					out[wantMasked(k, false)] = expect(x, false)
				}
				return out
			}
			return v
		}
		if want := expect(before, false); !reflect.DeepEqual(after, want) {
			t.Fatalf("list %d, masked:\n got  %.700v\nwant %.700v", n, after, want)
		}
		ifBefore, err1 := parseIPAddr(in)
		ifAfter, err2 := parseIPAddr(masked)
		if err1 != nil || err2 != nil || !reflect.DeepEqual(ifAfter, ifBefore) {
			t.Fatalf("list %d, interfaces read:\n got %+v, %v\nwant %+v, %v", n, ifAfter, err2, ifBefore, err1)
		}
	}
	if hidden < 2000 || left < 2000 {
		t.Errorf("the generated lists should hold plenty of both kinds; %d strings were masked and %d were not", hidden, left)
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
