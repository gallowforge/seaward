package snapshot

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
)

// ipLink is the part of one "ip -j -d addr show" entry that matters here.
type ipLink struct {
	Ifname   string   `json:"ifname"`
	Flags    []string `json:"flags"`
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
		}
		if l.Linkinfo != nil {
			in.Kind = l.Linkinfo.InfoKind
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
