package snapshot

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
)

// ufw prints each rule as "%-26s %-12s%-26s%s%s": the To location, the action with its
// direction ("ALLOW IN"), the From location, log attributes such as " (log)", and " # comment".
// A location is built as [address ][ports][/proto][ (app[ (v6)])][ (v6)][ on iface], or
// "Anywhere[/proto][ (v6)]" when it has neither address nor port.

var (
	ufwActionRe  = regexp.MustCompile(`\s(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?(?:\s|$)`)
	ufwDefaultRe = regexp.MustCompile(`^Default:\s*(\w+)\s*\(incoming\)`)
	ufwAttribRe  = regexp.MustCompile(`\s*\((?:log|log-all)(?:, [a-z]+)*\)$`)
	ufwPortsRe   = regexp.MustCompile(`^[0-9]+(?::[0-9]+)?(?:,[0-9]+(?::[0-9]+)?)*$`)
	ufwProtoRe   = regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	ufwOnRe      = regexp.MustCompile(`^(.*\S)\s+on\s+(\S+)$`)
)

// parseUFW reads "ufw status verbose". Notes describe rules it read only in part or not at all.
func parseUFW(text string) (*host.Frontend, []string) {
	f := &host.Frontend{Tool: "ufw"}
	var notes []string
	inTable := false
	for _, raw := range strings.Split(text, "\n") {
		ln := strings.TrimRight(raw, " \t\r")
		trim := strings.TrimSpace(ln)
		switch {
		case trim == "":
			continue
		case strings.HasPrefix(trim, "Status:"):
			f.Active = strings.TrimSpace(strings.TrimPrefix(trim, "Status:")) == "active"
			continue
		case ufwDefaultRe.MatchString(trim):
			f.DefaultIncoming = normalAction(ufwDefaultRe.FindStringSubmatch(trim)[1])
			continue
		case strings.HasPrefix(trim, "To ") && strings.Contains(trim, "Action"):
			inTable = true
			continue
		case strings.Trim(trim, "- ") == "":
			continue
		}
		if !inTable {
			// "Logging: on (low)", "New profiles: skip" and the like.
			continue
		}
		rs, note := parseUFWRule(ln)
		if note != "" {
			notes = append(notes, note)
		}
		f.Rules = append(f.Rules, rs...)
	}
	return f, notes
}

func normalAction(s string) string {
	switch strings.ToLower(s) {
	case "allow", "accept":
		return "allow"
	case "reject":
		return "reject"
	case "limit":
		return "limit"
	default:
		return "deny"
	}
}

// ufwLoc is one parsed location column.
type ufwLoc struct {
	addr  netip.Prefix // invalid for anywhere
	ports [][2]uint16  // empty for every port
	proto string       // "" for any
	iface string
	v6    bool
}

// parseUFWRule turns one rule line into one FrontendRule per port or port range it names.
func parseUFWRule(ln string) ([]host.FrontendRule, string) {
	text := strings.TrimSpace(ln)
	m := ufwActionRe.FindStringSubmatchIndex(ln)
	if m == nil || strings.TrimSpace(ln[:m[0]]) == "" {
		return nil, "A ufw line could not be read: " + text
	}
	action := normalAction(ln[m[2]:m[3]])
	dir := ""
	if m[4] >= 0 {
		dir = ln[m[4]:m[5]]
	}
	// Only incoming rules decide what reaches this machine. Without verbose, ufw leaves the
	// direction out for incoming rules.
	if dir != "" && dir != "IN" {
		return nil, ""
	}
	dstStr := ln[:m[0]]
	srcStr := ln[m[1]:]
	if i := strings.Index(srcStr, "# "); i >= 0 && (i == 0 || srcStr[i-1] == ' ') {
		srcStr = srcStr[:i]
	}
	srcStr = ufwAttribRe.ReplaceAllString(strings.TrimSpace(srcStr), "")

	dst, ok1 := parseUFWLoc(dstStr)
	src, ok2 := parseUFWLoc(srcStr)
	if !ok1 || !ok2 {
		return nil, "A ufw rule could not be read and is left out: " + text
	}
	proto := dst.proto
	if proto == "" {
		proto = src.proto
	}
	if proto != "" && proto != "tcp" && proto != "udp" {
		// A rule for another protocol (esp, gre ...) says nothing about TCP or UDP ports.
		return nil, ""
	}
	note := ""
	if len(src.ports) > 0 {
		note = "A ufw rule also requires a source port, which is not modelled; it is read as if it did not: " + text
	}
	base := host.FrontendRule{
		Action: action,
		Proto:  proto,
		From:   src.addr,
		To:     dst.addr,
		Iface:  dst.iface,
		IPv6:   dst.v6 || src.v6 || (dst.addr.IsValid() && dst.addr.Addr().Is6()) || (src.addr.IsValid() && src.addr.Addr().Is6()),
		Text:   text,
	}
	if len(dst.ports) == 0 {
		return []host.FrontendRule{base}, note
	}
	out := make([]host.FrontendRule, 0, len(dst.ports))
	for _, p := range dst.ports {
		r := base
		r.PortLo, r.PortHi = p[0], p[1]
		out = append(out, r)
	}
	return out, note
}

// parseUFWLoc reads one location column (see the comment at the top of this file).
func parseUFWLoc(s string) (ufwLoc, bool) {
	var l ufwLoc
	s = strings.TrimSpace(s)
	if m := ufwOnRe.FindStringSubmatch(s); m != nil {
		s, l.iface = m[1], m[2]
	}
	if strings.HasSuffix(s, " (v6)") {
		l.v6 = true
		s = strings.TrimSuffix(s, " (v6)")
	}
	// Verbose mode names the application profile after the ports: "22/tcp (OpenSSH)".
	if strings.HasSuffix(s, ")") {
		i := strings.Index(s, " (")
		if i < 0 {
			return l, false
		}
		if strings.HasSuffix(s[i+2:len(s)-1], " (v6)") {
			l.v6 = true
		}
		s = s[:i]
	}
	f := strings.Fields(s)
	if len(f) == 0 || len(f) > 2 {
		return l, false
	}
	last := f[len(f)-1]
	// The protocol is the last "/word" of the last token: "22/tcp", "Anywhere/udp",
	// "203.0.113.10/tcp", "10.0.0.0/8/tcp". A number after the slash is a prefix length.
	if i := strings.LastIndexByte(last, '/'); i >= 0 && ufwProtoRe.MatchString(last[i+1:]) {
		l.proto = last[i+1:]
		last = last[:i]
	}
	f[len(f)-1] = last
	var addrStr, portStr string
	switch {
	case len(f) == 2:
		addrStr, portStr = f[0], f[1]
	case f[0] == "Anywhere":
	case ufwPortsRe.MatchString(f[0]):
		portStr = f[0]
	default:
		addrStr = f[0]
	}
	if addrStr != "" {
		p, ok := parsePrefixOrAddr(addrStr)
		if !ok {
			return l, false
		}
		l.addr = p
	}
	if portStr != "" {
		ps, ok := parsePortList(portStr)
		if !ok {
			return l, false
		}
		l.ports = ps
	}
	return l, true
}

// parsePrefixOrAddr reads "203.0.113.0/24" or a single address as a /32 or /128.
func parsePrefixOrAddr(s string) (netip.Prefix, bool) {
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

// parsePortList reads "22", "80,443", "6000:6007" or a mix such as "22,8000:8010".
func parsePortList(s string) ([][2]uint16, bool) {
	var out [][2]uint16
	for _, part := range strings.Split(s, ",") {
		a, b, isRange := strings.Cut(part, ":")
		lo, err := strconv.ParseUint(a, 10, 16)
		if err != nil {
			return nil, false
		}
		hi := lo
		if isRange {
			if hi, err = strconv.ParseUint(b, 10, 16); err != nil || hi < lo {
				return nil, false
			}
		}
		out = append(out, [2]uint16{uint16(lo), uint16(hi)})
	}
	return out, true
}
