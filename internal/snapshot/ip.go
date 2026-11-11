package snapshot

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
)

// hardwareMasks take the hardware (MAC) addresses out of "ip -j -d addr show" before a snapshot
// keeps it. A snapshot is made to be handed on, and the reader takes nothing from them.
//
// Each mask is one substitution, written once: as the POSIX basic regular expression the
// collector script hands to sed. The collector here runs the same expressions in the same order
// (see goMask), so the two cannot drift apart. What a mask rewrites is always the inside of one
// JSON string, x's for digits between the same two quotes, so the JSON stays valid whatever is
// masked. And no mask can touch what the reader needs. An IP address is never six, seven or nine
// groups (IPv4 has dots; IPv6 is eight groups, or has a "::"). An interface name has no colon
// and at most fifteen characters, too few for any mask but the fourth, and the fourth looks only
// in lists, while the reader takes names from the value of a key.
//
//  1. Six pairs of hex digits, or seven: a MAC, under whatever key ip prints it ("address",
//     "permaddr", "broadcast", a bond's "perm_hwaddr", a virtual function's "address").
//  2. Nine pairs or more: the long hardware addresses, such as InfiniBand's twenty bytes.
//  3. A bridge id ("bridge_id", "root_id"): four hex digits of priority, a dot, and the bridge's
//     MAC printed without leading zeros. The priority stays.
//  4. An alternative name made from the MAC, which recent versions of systemd give a card: two
//     letters, an x and the twelve digits ("enx00005e005301"). Alternative names are a list, so
//     the string stands after a "[" or a ","; the interface's own name stands after a colon and
//     is never touched, even when the system built that from the MAC as well. The rules and the
//     routes are written in terms of it.
//  5. A device id in the shape of a UUID ("parentdev" on an Azure virtual machine, where the id
//     of a network card is made from its MAC).
//
// Eight pairs are left alone: an IPv6 address can be written that way, and the rare eight-byte
// hardware address (an IEEE 802.15.4 radio's) cannot be told from one by its shape. So are fewer
// than six: nothing a server has is that short, and a pair or two of hex digits could be anything.
var hardwareMasks = []struct{ bre, with string }{
	{`"[0-9a-fA-F]\{2\}\(:[0-9a-fA-F]\{2\}\)\{5,6\}"`, `"` + maskedMAC + `"`},
	{`"[0-9a-fA-F]\{2\}\(:[0-9a-fA-F]\{2\}\)\{8,\}"`, `"` + maskedMAC + `"`},
	{`"\([0-9a-fA-F]\{4\}\)\.[0-9a-fA-F]\{1,2\}\(:[0-9a-fA-F]\{1,2\}\)\{5\}"`, `"\1.` + maskedMAC + `"`},
	{`\([,[]"[a-z][a-z]x\)[0-9a-fA-F]\{12\}"`, `\1xxxxxxxxxxxx"`},
	{`"[0-9a-fA-F]\{8\}\(-[0-9a-fA-F]\{4\}\)\{3\}-[0-9a-fA-F]\{12\}"`, `"` + maskedID + `"`},
}

// maskedMAC stands where a hardware address was, and maskedID where a device id was. An x is not
// a hex digit, so nobody takes either for the real thing, and masking twice changes nothing.
const (
	maskedMAC = "xx:xx:xx:xx:xx:xx"
	maskedID  = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
)

// goMask spells a basic regular expression, or its replacement, the way Go's regexp package
// reads it. For the masks above the two notations differ only in the backslashes: groups and
// counts take none in Go, and the first group is ${1}, not \1.
var goMask = strings.NewReplacer(`\(`, `(`, `\)`, `)`, `\{`, `{`, `\}`, `}`, `\1`, `${1}`)

var hardwareREs = func() []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, m := range hardwareMasks {
		res = append(res, regexp.MustCompile(goMask.Replace(m.bre)))
	}
	return res
}()

// maskHardware returns the output of "ip -j -d addr show" with its hardware addresses masked,
// byte for byte what the script's mask function makes of the same text.
func maskHardware(text string) string {
	for i, m := range hardwareMasks {
		text = hardwareREs[i].ReplaceAllString(text, goMask.Replace(m.with))
	}
	return text
}

// maskSed is the masks as the arguments the script gives to sed, one expression to a line.
func maskSed() string {
	var args []string
	for _, m := range hardwareMasks {
		args = append(args, "-e 's/"+m.bre+"/"+m.with+"/g'")
	}
	return strings.Join(args, " \\\n\t\t")
}

// ipLink is the part of one "ip -j -d addr show" entry that matters here.
type ipLink struct {
	Ifname   string   `json:"ifname"`
	Flags    []string `json:"flags"`
	Master   string   `json:"master"`
	Link     string   `json:"link"`
	Linkinfo *struct {
		InfoKind string `json:"info_kind"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen *int   `json:"prefixlen"`
	} `json:"addr_info"`
}

// parseIPAddr reads "ip -j -d addr show". Up follows the administrative UP flag rather than
// operstate: an address on a bridge with no cable (NO-CARRIER) still belongs to the machine.
func parseIPAddr(text string) ([]host.Interface, error) {
	var links []ipLink
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return nil, fmt.Errorf("the interface list is not the JSON ip prints: %v", err)
	}
	var out []host.Interface
	for _, l := range links {
		if l.Ifname == "" {
			continue
		}
		in := host.Interface{
			Name:     l.Ifname,
			Up:       slices.Contains(l.Flags, "UP"),
			Loopback: slices.Contains(l.Flags, "LOOPBACK"),
			Master:   l.Master,
		}
		if l.Linkinfo != nil {
			in.Kind = l.Linkinfo.InfoKind
		}
		// "link" is the interface underneath only for these kinds; for a veth pair it names the
		// other end, which is a different road.
		switch in.Kind {
		case "vlan", "macvlan", "macvtap", "ipvlan", "ipvtap":
			in.Lower = l.Link
		}
		for _, a := range l.AddrInfo {
			// ip prints lifetime-only entries without an address; those carry nothing.
			if a.Local == "" || (a.Family != "inet" && a.Family != "inet6") {
				continue
			}
			ip, err := netip.ParseAddr(a.Local)
			if err != nil {
				continue
			}
			ip = ip.WithZone("")
			bits := ip.BitLen()
			if a.Prefixlen != nil {
				bits = *a.Prefixlen
			}
			p, err := ip.Prefix(bits)
			if err != nil {
				continue
			}
			// Keep the host part: the prefix records the address and its subnet length.
			in.Addrs = append(in.Addrs, netip.PrefixFrom(ip, p.Bits()))
		}
		out = append(out, in)
	}
	return out, nil
}

type ipRoute struct {
	Dst      string `json:"dst"`
	Dev      string `json:"dev"`
	Gateway  string `json:"gateway"`
	Type     string `json:"type"`
	Nexthops []struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
	} `json:"nexthops"`
}

// parseIPRoute reads "ip -j -4|-6 route show table main". Six says which family the text is,
// since "default" alone does not tell.
func parseIPRoute(text string, six bool) ([]host.Route, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var rs []ipRoute
	if err := json.Unmarshal([]byte(text), &rs); err != nil {
		return nil, fmt.Errorf("the route list is not the JSON ip prints: %v", err)
	}
	var out []host.Route
	for _, r := range rs {
		dst, ok := parseRouteDst(r.Dst, six)
		if !ok {
			continue
		}
		rt := host.Route{Dst: dst, Dev: r.Dev, Type: r.Type}
		gw := r.Gateway
		// A multipath route lists its next hops; the first one stands for the route.
		if len(r.Nexthops) > 0 {
			if rt.Dev == "" {
				rt.Dev = r.Nexthops[0].Dev
			}
			if gw == "" {
				gw = r.Nexthops[0].Gateway
			}
		}
		if gw != "" {
			if g, err := netip.ParseAddr(gw); err == nil {
				rt.Gateway = g.WithZone("")
			}
		}
		if rt.Type == "" {
			rt.Type = "unicast"
		}
		out = append(out, rt)
	}
	return out, nil
}

func parseRouteDst(s string, six bool) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	if s == "default" {
		if six {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), true
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), true
}

// sysctlInfo is what the sysctl section says.
type sysctlInfo struct {
	Forward4, Forward6 bool
	RouteLocalnet      map[string]bool
	seen4, seen6       bool
}

// parseSysctl reads "key = value" lines.
func parseSysctl(text string) sysctlInfo {
	var s sysctlInfo
	for _, ln := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		on := v != "" && v != "0"
		switch {
		case k == "net.ipv4.ip_forward":
			s.Forward4, s.seen4 = on, true
		case k == "net.ipv6.conf.all.forwarding":
			s.Forward6, s.seen6 = on, true
		case strings.HasPrefix(k, "net.ipv4.conf.") && strings.HasSuffix(k, ".route_localnet"):
			ifname := strings.TrimSuffix(strings.TrimPrefix(k, "net.ipv4.conf."), ".route_localnet")
			// sysctl writes the dot in a VLAN name such as eth0.100 as a slash.
			ifname = strings.ReplaceAll(ifname, "/", ".")
			if on && ifname != "" && ifname != "default" {
				if s.RouteLocalnet == nil {
					s.RouteLocalnet = map[string]bool{}
				}
				s.RouteLocalnet[ifname] = true
			}
		}
	}
	return s
}
