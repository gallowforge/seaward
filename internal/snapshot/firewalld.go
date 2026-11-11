package snapshot

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
)

// fwBlock is one block of firewall-cmd output: a header line (a zone or service name, perhaps
// followed by "(default, active)") and its indented "key: value" lines. A value can carry on
// over deeper-indented lines, as "rich rules:" and "forward-ports:" do.
type fwBlock struct {
	name   string
	marks  string // what was in brackets after the name: "default, active"
	values map[string][]string
	lines  map[string]int // how many continuation lines each key had
}

func parseFWBlocks(text string) []*fwBlock {
	var out []*fwBlock
	var cur *fwBlock
	lastKey := ""
	for _, raw := range strings.Split(text, "\n") {
		ln := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if ln[0] != ' ' && ln[0] != '\t' {
			name, marks, _ := strings.Cut(ln, " ")
			marks = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(marks), "("), ")")
			cur = &fwBlock{name: name, marks: marks, values: map[string][]string{}, lines: map[string]int{}}
			out = append(out, cur)
			lastKey = ""
			continue
		}
		if cur == nil {
			// Output with no header line still has its keys read.
			cur = &fwBlock{values: map[string][]string{}, lines: map[string]int{}}
			out = append(out, cur)
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " \t"))
		body := strings.TrimSpace(ln)
		k, v, ok := strings.Cut(body, ":")
		// A key line has the shallow indent firewall-cmd uses for keys and a plain key name;
		// anything deeper (a rich rule, a forward-port) belongs to the key above it.
		if ok && (indent <= 2 && !strings.HasPrefix(ln, "\t")) && !strings.ContainsAny(k, "=\"") {
			lastKey = k
			cur.values[k] = append(cur.values[k], strings.Fields(v)...)
			continue
		}
		if lastKey != "" {
			cur.lines[lastKey]++
			if lastKey != "rich rules" {
				cur.values[lastKey] = append(cur.values[lastKey], strings.Fields(body)...)
			}
		}
	}
	return out
}

func (b *fwBlock) hasMark(m string) bool {
	for _, x := range strings.Split(b.marks, ",") {
		if strings.TrimSpace(x) == m {
			return true
		}
	}
	return false
}

// fwPort is one entry of a "ports:" or "protocols:" list.
type fwPort struct {
	proto  string
	lo, hi uint16
}

// parseFWPorts reads "22/tcp 60000-61000/udp". Protocols other than TCP and UDP are left out:
// they open no port.
func parseFWPorts(vals []string) []fwPort {
	var out []fwPort
	for _, v := range vals {
		ports, proto, ok := strings.Cut(v, "/")
		if !ok || (proto != "tcp" && proto != "udp") {
			continue
		}
		lo, hi, ok := parseDashRange(ports)
		if !ok {
			continue
		}
		out = append(out, fwPort{proto, lo, hi})
	}
	return out
}

// fwService is what "firewall-cmd --info-service=<name>" said.
type fwService struct {
	ports    []fwPort
	includes []string
	dests    []netip.Prefix // from "destination: ipv4:... ipv6:..."; empty for any
	unread   []string       // conditions it has that are not modelled, as plain phrases
}

func parseFWService(text string) fwService {
	var s fwService
	for _, b := range parseFWBlocks(text) {
		s.ports = append(s.ports, parseFWPorts(b.values["ports"])...)
		s.ports = append(s.ports, fwProtocols(b.values["protocols"])...)
		s.includes = append(s.includes, b.values["includes"]...)
		for _, d := range b.values["destination"] {
			_, addr, _ := strings.Cut(d, ":")
			if p, ok := parsePrefixOrAddr(addr); ok {
				s.dests = append(s.dests, p)
			} else {
				s.unread = append(s.unread, "destination "+d)
			}
		}
		if len(b.values["source-ports"]) > 0 {
			s.unread = append(s.unread, "source ports")
		}
	}
	return s
}

// fwProtocols turns "protocols: tcp" (every TCP port) into port entries.
func fwProtocols(vals []string) []fwPort {
	var out []fwPort
	for _, v := range vals {
		if v == "tcp" || v == "udp" {
			out = append(out, fwPort{proto: v})
		}
	}
	return out
}

// firewalldTargets maps a zone target to what happens to traffic no rule allowed.
func firewalldTarget(t string) string {
	switch t {
	case "ACCEPT":
		return "allow"
	case "DROP":
		return "deny"
	default: // "default", "%%REJECT%%", "REJECT"
		return "reject"
	}
}

// buildFirewalld reads the firewalld sections. Services maps a service name to its
// "firewall-cmd --info-service" output. HostIfaces names the machine's non-loopback interfaces
// (nil when unknown): the default zone covers every one that no other zone names.
func buildFirewalld(state, zones, active string, haveActive bool, services map[string]string, hostIfaces []string) (*host.Frontend, []string) {
	f := &host.Frontend{Tool: "firewalld", Active: strings.TrimSpace(state) == "running"}
	var notes []string

	blocks := parseFWBlocks(zones)
	// The active zones and their bindings, from --get-active-zones when it was captured.
	activeZones := map[string]*fwBlock{}
	if haveActive {
		for _, b := range parseFWBlocks(active) {
			activeZones[b.name] = b
		}
	}

	// A zone is in force when it is active, or when it is the default zone: firewalld gives the
	// default zone every interface no other zone claims, whether or not it lists it as active.
	inForce := func(z *fwBlock) bool {
		if z.hasMark("default") {
			return true
		}
		if haveActive {
			return activeZones[z.name] != nil
		}
		return z.hasMark("active")
	}
	claimed := map[string]bool{}
	for _, z := range blocks {
		if inForce(z) {
			for _, i := range z.values["interfaces"] {
				claimed[i] = true
			}
			if az := activeZones[z.name]; az != nil {
				for _, i := range az.values["interfaces"] {
					claimed[i] = true
				}
			}
		}
	}

	var defaultSet bool
	for _, z := range blocks {
		if !inForce(z) {
			continue
		}
		az := activeZones[z.name]
		ifaces := z.values["interfaces"]
		sources := z.values["sources"]
		if az != nil {
			if len(ifaces) == 0 {
				ifaces = az.values["interfaces"]
			}
			if len(sources) == 0 {
				sources = az.values["sources"]
			}
		}
		if target, ok := z.values["target"]; ok && len(target) > 0 {
			if z.hasMark("default") || (!defaultSet && f.DefaultIncoming == "") {
				f.DefaultIncoming = firewalldTarget(target[0])
				defaultSet = defaultSet || z.hasMark("default")
			}
		}
		if n := z.lines["rich rules"] + len(z.values["rich rules"]); n > 0 {
			notes = append(notes, "Rich rules in firewalld zone "+z.name+" are not read.")
		}
		if len(z.values["forward-ports"]) > 0 {
			notes = append(notes, "Port forwarding in firewalld zone "+z.name+" is not read.")
		}
		if len(z.values["source-ports"]) > 0 {
			notes = append(notes, "Source ports allowed in firewalld zone "+z.name+" are not read.")
		}

		// Every port the zone opens, each with the destinations it is limited to.
		type opening struct {
			port  fwPort
			dests []netip.Prefix
			what  string // "port" or "service ssh"
		}
		var opens []opening
		for _, p := range parseFWPorts(z.values["ports"]) {
			opens = append(opens, opening{port: p, what: "port"})
		}
		for _, p := range fwProtocols(z.values["protocols"]) {
			opens = append(opens, opening{port: p, what: "protocol"})
		}
		for _, name := range z.values["services"] {
			svc, missing := resolveFWService(name, services)
			if len(missing) > 0 {
				notes = append(notes, "The ports of firewalld service "+strings.Join(missing, ", ")+
					" (zone "+z.name+") were not in the snapshot.")
			}
			if len(svc.unread) > 0 {
				notes = append(notes, "Firewalld service "+name+" (zone "+z.name+") also limits by "+
					strings.Join(svc.unread, " and ")+", which is not read; it is taken as open to all.")
			}
			for _, p := range svc.ports {
				opens = append(opens, opening{port: p, dests: svc.dests, what: "service " + name})
			}
		}

		// Where the zone applies: each of its interfaces, and each of its sources.
		type binding struct {
			iface string
			from  netip.Prefix
		}
		var binds []binding
		for _, i := range ifaces {
			binds = append(binds, binding{iface: i})
		}
		for _, s := range sources {
			p, ok := parsePrefixOrAddr(s)
			if !ok {
				notes = append(notes, "Source "+s+" of firewalld zone "+z.name+" is not an address and is not read.")
				continue
			}
			binds = append(binds, binding{from: p})
		}
		if z.hasMark("default") || len(binds) == 0 {
			// The default zone (and an active zone with no binding of its own) takes the
			// interfaces nobody else named.
			n := len(binds)
			for _, i := range hostIfaces {
				if !claimed[i] {
					binds = append(binds, binding{iface: i})
				}
			}
			if hostIfaces == nil && n == 0 {
				binds = append(binds, binding{})
				if len(claimed) > 0 {
					notes = append(notes, "The machine's interfaces are not in the snapshot, so firewalld zone "+z.name+
						" is read as covering every interface, including those another zone names.")
				}
			}
		}

		for _, b := range binds {
			for _, o := range opens {
				for _, v6 := range []bool{false, true} {
					if b.from.IsValid() && b.from.Addr().Is6() != v6 {
						continue
					}
					base := host.FrontendRule{
						Action: "allow", Proto: o.port.proto, PortLo: o.port.lo, PortHi: o.port.hi,
						From: b.from, Iface: b.iface, IPv6: v6, Zone: z.name,
						Text: fwRuleText(z.name, o.what, o.port),
					}
					if len(o.dests) == 0 {
						f.Rules = append(f.Rules, base)
						continue
					}
					for _, d := range o.dests {
						if d.Addr().Is6() == v6 {
							r := base
							r.To = d
							f.Rules = append(f.Rules, r)
						}
					}
				}
			}
		}
	}
	return f, notes
}

// resolveFWService gathers a service's ports, following "includes:" to other services.
func resolveFWService(name string, services map[string]string) (fwService, []string) {
	var out fwService
	var missing []string
	seen := map[string]bool{}
	queue := []string{name}
	for len(queue) > 0 && len(seen) < 64 {
		n := queue[0]
		queue = queue[1:]
		if seen[n] {
			continue
		}
		seen[n] = true
		body, ok := services[n]
		if !ok {
			missing = append(missing, n)
			continue
		}
		s := parseFWService(body)
		out.ports = append(out.ports, s.ports...)
		out.dests = append(out.dests, s.dests...)
		out.unread = append(out.unread, s.unread...)
		queue = append(queue, s.includes...)
	}
	sort.Strings(missing)
	return out, missing
}

// fwRuleText describes a rule the way firewalld lists it, since firewalld has no one line per
// port: "zone public, service ssh: 22/tcp".
func fwRuleText(zone, what string, p fwPort) string {
	port := "every port"
	if p.lo != 0 || p.hi != 0 {
		port = strconv.Itoa(int(p.lo))
		if p.hi != p.lo {
			port += "-" + strconv.Itoa(int(p.hi))
		}
	}
	return "zone " + zone + ", " + what + ": " + port + "/" + p.proto
}

// firewalldServiceNames lists the services the active zones name (every zone's, if none is
// marked active), so the collector can ask for each one.
func firewalldServiceNames(zones string) []string {
	blocks := parseFWBlocks(zones)
	var active []*fwBlock
	for _, b := range blocks {
		if b.hasMark("active") || b.hasMark("default") {
			active = append(active, b)
		}
	}
	if len(active) > 0 {
		blocks = active
	}
	seen := map[string]bool{}
	var out []string
	for _, b := range blocks {
		for _, s := range b.values["services"] {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
