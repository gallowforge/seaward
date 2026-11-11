package snapshot

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
)

// parseSS reads "ss -Htulpn" output. Netns is "" for the host or the container ID the output
// came from. Rows it cannot read are skipped: one odd line must not hide every other listener.
func parseSS(text, netns string) []host.Listener {
	var out []host.Listener
	for _, ln := range strings.Split(text, "\n") {
		l, ok := parseSSLine(ln)
		if !ok {
			continue
		}
		l.Netns = netns
		out = append(out, l)
	}
	return out
}

func parseSSLine(ln string) (host.Listener, bool) {
	var l host.Listener
	f := strings.Fields(ln)
	if len(f) < 5 {
		return l, false
	}
	switch {
	case strings.HasPrefix(f[0], "tcp"):
		l.Proto = "tcp"
		if f[1] != "LISTEN" {
			return l, false
		}
	case strings.HasPrefix(f[0], "udp"):
		l.Proto = "udp"
		// A connected UDP socket (ESTAB) only takes datagrams from its one peer.
		if f[1] != "UNCONN" {
			return l, false
		}
	default:
		// The header line ("Netid State ...") and anything that is not TCP or UDP.
		return l, false
	}
	addr, dev, port, dual, ok := parseSSAddr(f[4])
	if !ok {
		return l, false
	}
	l.Addr, l.Dev, l.Port, l.DualStack = addr, dev, port, dual
	if i := strings.Index(ln, "users:(("); i >= 0 {
		l.Process, l.PID = parseSSUsers(ln[i+len("users:(("):])
	}
	return l, true
}

// parseSSAddr reads the local address column: "0.0.0.0:22", "[::]:22", "*:8080",
// "127.0.0.53%lo:53", "[fe80::1]%eth0:546", and the older ":::22".
func parseSSAddr(s string) (addr netip.Addr, dev string, port uint16, dual, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return addr, "", 0, false, false
	}
	p, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return addr, "", 0, false, false
	}
	port = uint16(p)
	a := s[:i]
	if a == "*" {
		// ss prints "*" for a "::" socket that also takes IPv4.
		return netip.IPv6Unspecified(), "", port, true, true
	}
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return addr, "", 0, false, false
		}
		inner, after := a[1:end], a[end+1:]
		if after != "" {
			if !strings.HasPrefix(after, "%") {
				return addr, "", 0, false, false
			}
			dev = after[1:]
		}
		a = inner
	}
	// "addr%dev": the socket is bound to one interface (or, inside brackets, a scope).
	if j := strings.IndexByte(a, '%'); j >= 0 {
		if dev == "" {
			dev = a[j+1:]
		}
		a = a[:j]
	}
	if a == "*" {
		return netip.IPv6Unspecified(), dev, port, true, true
	}
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return addr, "", 0, false, false
	}
	// A socket on ::ffff:a.b.c.d only ever sees IPv4 traffic for a.b.c.d.
	return ip.Unmap(), dev, port, false, true
}

// parseSSUsers reads `"name",pid=N,fd=N),("name",pid=M,fd=K))` and returns the first process.
// The name sits between the first quote and `",pid=`, so spaces and brackets in it are fine.
func parseSSUsers(s string) (string, int) {
	if !strings.HasPrefix(s, `"`) {
		return "", 0
	}
	end := strings.Index(s[1:], `",pid=`) + 1
	if end < 1 {
		return "", 0
	}
	name := s[1:end]
	rest := s[end+len(`",pid=`):]
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	pid, err := strconv.Atoi(rest[:n])
	if err != nil {
		return name, 0
	}
	return name, pid
}
