package snapshot

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/ipt"
	"github.com/gallowforge/seaward/internal/nft"
	"github.com/gallowforge/seaward/internal/rules"
)

// ruleSections are the sections that hold packet rules.
var ruleSections = []string{"iptables-save", "ip6tables-save", "iptables-legacy-save", "ip6tables-legacy-save", "nft-json"}

// sectionWhat names what each section holds, for notes the user reads.
var sectionWhat = map[string]string{
	"iptables-version":      "iptables version",
	"iptables-save":         "IPv4 packet rules (iptables)",
	"ip6tables-save":        "IPv6 packet rules (ip6tables)",
	"iptables-legacy-save":  "legacy IPv4 packet rules",
	"ip6tables-legacy-save": "legacy IPv6 packet rules",
	"nft-json":              "nftables packet rules",
	"ipset-save":            "ipsets (named address lists the rules can use)",
	"ss":                    "listening sockets",
	"ip-addr":               "network interfaces and their addresses",
	"ip-route-4":            "IPv4 routes",
	"ip-route-6":            "IPv6 routes",
	"sysctl":                "forwarding settings",
	"docker-version":        "Docker version",
	"docker-ps":             "Docker containers",
	"docker-net":            "Docker container addresses",
	"docker-ss":             "listeners inside a container",
	"ufw-status":            "ufw settings",
	"firewalld-state":       "firewalld state",
	"firewalld-active":      "active firewalld zones",
	"firewalld-zones":       "firewalld zones",
	"firewalld-service":     "ports of a firewalld service",
}

// rootOnly are sections whose command fails without root.
var rootOnly = map[string]bool{
	"iptables-save": true, "ip6tables-save": true, "iptables-legacy-save": true, "ip6tables-legacy-save": true,
	"nft-json": true, "ipset-save": true, "ufw-status": true, "docker-ss": true,
}

func build(b *Bundle) (*rules.Ruleset, *host.Host, error) {
	if b == nil {
		return nil, nil, errors.New("snapshot: no bundle")
	}
	meta := b.Meta()
	h := &host.Host{Name: meta["host"], RouteLocalnet: map[string]bool{}}
	rs := &rules.Ruleset{Sets: map[string]*rules.Set{}}
	notRoot := meta["root"] == "no"

	h.Notes = append(h.Notes, errorNotes(b, notRoot)...)
	buildRules(b, rs, h, notRoot)
	if !anySection(b, ruleSections...) && !anyError(b, ruleSections...) {
		if notRoot {
			const why = "The packet rules were not read: the snapshot was taken without root."
			h.Notes = append(h.Notes, why)
			rs.Unread = append(rs.Unread, rules.Unread{Why: why})
		} else {
			h.Notes = append(h.Notes, "This machine has no packet rules: nothing in the kernel filters traffic.")
		}
	}
	buildHost(b, h, notRoot)
	if meta["root"] == "yes" {
		// Read as root, ss names every program that holds a socket. A socket with no name is held by
		// the kernel itself: a WireGuard tunnel, an NFS server.
		for i := range h.Listeners {
			if l := &h.Listeners[i]; l.Netns == "" && l.Process == "" {
				l.Process = "the kernel"
			}
		}
	}
	return rs, h, nil
}

// ruleFamily is the address family a rule section speaks for; "" is both.
var ruleFamily = map[string]string{
	"iptables-save": "ip", "iptables-legacy-save": "ip",
	"ip6tables-save": "ip6", "ip6tables-legacy-save": "ip6",
	"nft-json": "",
}

func buildRules(b *Bundle, rs *rules.Ruleset, h *host.Host, notRoot bool) {
	// A rule source that could not be read or understood is recorded twice: as a note for the
	// reader, and in rs.Unread so the engine stops short of calling anything let through.
	parseNote := func(section string, err error) {
		why := fmt.Sprintf("The %s could not be understood: %v.", sectionWhat[section], strings.TrimSuffix(err.Error(), "."))
		h.Notes = append(h.Notes, why)
		if fam, isRules := ruleFamily[section]; isRules {
			rs.Unread = append(rs.Unread, rules.Unread{Family: fam, Why: why})
		}
	}
	// A rule listing whose command failed: the sentence is already among the host notes.
	for label, msg := range b.Errors() {
		if fam, isRules := ruleFamily[label]; isRules {
			rs.Unread = append(rs.Unread, rules.Unread{Family: fam, Why: errorSentence(label, msg, notRoot)})
		}
	}
	sort.Slice(rs.Unread, func(i, j int) bool { return rs.Unread[i].Why < rs.Unread[j].Why })

	// ipset first: the iptables rules need each set's dimensions to know what it matches.
	var dims map[string][]string
	if body, ok := b.Get("ipset-save"); ok && strings.TrimSpace(body) != "" {
		sets, d, notes, err := ipt.ParseIPSet(body)
		if err != nil {
			parseNote("ipset-save", err)
		}
		for k, s := range sets {
			rs.Sets[k] = s
		}
		dims = d
		rs.Notes = append(rs.Notes, notes...)
	}

	// Without the version line the backend is taken as nf_tables, the default on current
	// distributions; then an nft table named like an iptables one is the same kernel table.
	ver, _ := b.Get("iptables-version")
	legacy := strings.Contains(ver, "(legacy)")
	// Tables iptables-nft printed are nf_tables tables, so nft lists them again. Legacy tables
	// live apart from nf_tables and are never in nft's output. The nft reader gets the
	// iptables-nft tables and settles, rule by rule, which listing to believe: iptables-save
	// prints a rule made with the nft tool wrongly and without a warning when the rule uses
	// something iptables has no words for (a set, a verdict map).
	var shared []*rules.Table
	var leftToNft [][2]string // family and name of tables iptables-save could not show
	for _, s := range []struct {
		section, family string
		legacy          bool
	}{
		{"iptables-save", "ip", legacy},
		{"ip6tables-save", "ip6", legacy},
		{"iptables-legacy-save", "ip", true},
		{"ip6tables-legacy-save", "ip6", true},
	} {
		body, ok := b.Get(s.section)
		if !ok || strings.TrimSpace(body) == "" {
			continue
		}
		tables, notes, err := ipt.ParseSave(body, ipt.Options{Family: s.family, Legacy: s.legacy, SetDims: dims})
		if err != nil {
			parseNote(s.section, err)
		}
		for _, name := range ipt.Incompatible(body) {
			leftToNft = append(leftToNft, [2]string{s.family, name})
		}
		rs.Tables = append(rs.Tables, tables...)
		rs.Notes = append(rs.Notes, notes...)
		if !s.legacy {
			shared = append(shared, tables...)
		}
	}

	nftRead := false
	defer func() {
		if nftRead || anyError(b, "nft-json") {
			return
		}
		// iptables-save said "use the nft tool" for a table and there is no nft listing to turn to.
		for _, t := range leftToNft {
			tool := "iptables-save"
			if t[0] == "ip6" {
				tool = "ip6tables-save"
			}
			why := fmt.Sprintf("The %s table %s holds rules only the nft tool can list, and the snapshot has no nft listing.", strings.TrimSuffix(tool, "-save"), t[1])
			h.Notes = append(h.Notes, why)
			rs.Unread = append(rs.Unread, rules.Unread{Family: t[0], Why: why})
		}
	}()
	if body, ok := b.Get("nft-json"); ok && strings.TrimSpace(body) != "" {
		n, err := nft.ParseJSON([]byte(body), shared)
		if err != nil {
			parseNote("nft-json", err)
		} else {
			nftRead = true
		}
		if n != nil {
			// A table nft returned replaces the copy iptables-save gave of the same table.
			settled := map[string]bool{}
			for _, t := range n.Tables {
				settled[t.Family+" "+t.Name] = true
			}
			isShared := map[*rules.Table]bool{}
			for _, t := range shared {
				isShared[t] = true
			}
			kept := rs.Tables[:0]
			for _, t := range rs.Tables {
				if isShared[t] && settled[t.Family+" "+t.Name] {
					continue
				}
				kept = append(kept, t)
			}
			rs.Tables = append(kept, n.Tables...)
			for k, s := range n.Sets {
				rs.Sets[k] = s
			}
			rs.Notes = append(rs.Notes, n.Notes...)
		}
	}
}

func buildHost(b *Bundle, h *host.Host, notRoot bool) {
	missing := func(section string) {
		if !b.Has(section) && !anyError(b, section) {
			h.Notes = append(h.Notes, "The snapshot has no "+sectionWhat[section]+".")
		}
	}

	if body, ok := b.Get("ip-addr"); ok {
		ifs, err := parseIPAddr(body)
		if err != nil {
			h.Notes = append(h.Notes, "The "+sectionWhat["ip-addr"]+" could not be understood: "+err.Error()+".")
		}
		h.Interfaces = ifs
	} else {
		missing("ip-addr")
	}
	for _, r := range []struct {
		section string
		six     bool
	}{{"ip-route-4", false}, {"ip-route-6", true}} {
		body, ok := b.Get(r.section)
		if !ok {
			continue
		}
		routes, err := parseIPRoute(body, r.six)
		if err != nil {
			h.Notes = append(h.Notes, "The "+sectionWhat[r.section]+" could not be understood: "+err.Error()+".")
		}
		h.Routes = append(h.Routes, routes...)
	}
	missing("ip-route-4")

	if body, ok := b.Get("sysctl"); ok {
		s := parseSysctl(body)
		h.Forward4, h.Forward6 = s.Forward4, s.Forward6
		for k := range s.RouteLocalnet {
			h.RouteLocalnet[k] = true
		}
		if !s.seen4 {
			h.Notes = append(h.Notes, "Whether this machine forwards IPv4 packets was not in the snapshot; it is taken as off.")
		}
	} else {
		missing("sysctl")
	}

	if body, ok := b.Get("ss"); ok {
		h.Listeners = parseSS(body, "")
		if notRoot {
			h.Notes = append(h.Notes, "The names of the programs behind each port were not read: the snapshot was taken without root.")
		}
	} else {
		// Without the list, "nothing is listening" cannot be said about any port.
		h.NoListenerData = true
		missing("ss")
	}

	if b.Has("docker-ps") || b.Has("docker-version") {
		ver, _ := b.Get("docker-version")
		ps, _ := b.Get("docker-ps")
		net, hasNet := b.Get("docker-net")
		d, notes := buildDocker(ver, ps, net, hasNet)
		h.Docker = d
		h.Notes = append(h.Notes, notes...)
		for _, s := range b.All("docker-ss") {
			id := s.Arg
			for i := range d.Containers {
				if sameContainer(d.Containers[i].ID, id) {
					id = d.Containers[i].ID
					d.Containers[i].ListenersKnown = true
				}
			}
			h.Listeners = append(h.Listeners, parseSS(s.Body, id)...)
		}
		unread := 0
		for _, c := range d.Containers {
			if !c.HostNetwork && !c.ListenersKnown {
				unread++
			}
		}
		if unread > 0 {
			why := "they were not in the snapshot"
			if notRoot {
				why = "that needs root"
			}
			h.Notes = append(h.Notes, fmt.Sprintf("What listens inside %d container(s) was not read: %s. Whether anything answers on their published ports is not known.", unread, why))
		}
	}

	var ufwF, fwF *host.Frontend
	if body, ok := b.Get("ufw-status"); ok {
		var notes []string
		ufwF, notes = parseUFW(body)
		h.Notes = append(h.Notes, notes...)
	}
	if state, ok := b.Get("firewalld-state"); ok {
		zones, _ := b.Get("firewalld-zones")
		active, haveActive := b.Get("firewalld-active")
		services := map[string]string{}
		for _, s := range b.All("firewalld-service") {
			services[s.Arg] = s.Body
		}
		var notes []string
		var ifaces []string
		if b.Has("ip-addr") {
			ifaces = []string{}
			for _, in := range h.Interfaces {
				if !in.Loopback {
					ifaces = append(ifaces, in.Name)
				}
			}
		}
		fwF, notes = buildFirewalld(state, zones, active, haveActive, services, ifaces)
		if fwF.Active {
			h.Notes = append(h.Notes, notes...)
		}
	}
	switch {
	case ufwF != nil && ufwF.Active:
		h.Frontend = ufwF
		if fwF != nil && fwF.Active {
			h.Notes = append(h.Notes, "Both ufw and firewalld are running; the ufw view is shown. The packet rules decide either way.")
		}
	case fwF != nil && fwF.Active:
		h.Frontend = fwF
	case ufwF != nil:
		h.Frontend = ufwF
	case fwF != nil:
		h.Frontend = fwF
	}
}

// errorNotes turns each errors line into one plain sentence.
func errorNotes(b *Bundle, notRoot bool) []string {
	var out []string
	for _, s := range b.All("errors") {
		for _, ln := range strings.Split(s.Body, "\n") {
			label, msg, ok := strings.Cut(ln, ":")
			label = strings.TrimSpace(label)
			if !ok || label == "" {
				continue
			}
			out = append(out, errorSentence(label, strings.TrimSpace(msg), notRoot))
		}
	}
	return out
}

func errorSentence(label, msg string, notRoot bool) string {
	section, arg, _ := strings.Cut(label, " ")
	what := sectionWhat[section]
	if what == "" {
		what = "output of " + section
	}
	if arg != "" {
		what += " (" + arg + ")"
	}
	prog := programOf(section)
	low := strings.ToLower(msg)
	var why string
	switch {
	case strings.Contains(low, "timed out"):
		why = prog + " did not answer in time"
	case section == "docker-ps" || section == "docker-version" || section == "docker-net":
		if strings.Contains(low, "permission denied") {
			why = "docker needs root or membership of the docker group"
		} else if strings.Contains(low, "cannot connect") || strings.Contains(low, "is the docker daemon running") {
			why = "the Docker daemon is not running"
		}
	case strings.Contains(low, "permission denied"), strings.Contains(low, "root"),
		strings.Contains(low, "operation not permitted"), strings.Contains(low, "not permitted"):
		why = prog + " needs root"
	case notRoot && rootOnly[section]:
		why = prog + " needs root"
	}
	if why == "" {
		why = prog + " failed"
		if msg != "" {
			why += " (" + strings.TrimSuffix(msg, ".") + ")"
		}
	}
	return "The " + what + " could not be read: " + why + "."
}

// programOf gives the program a section comes from, from the collector's table.
func programOf(section string) string {
	for _, c := range commands {
		if c.section == section {
			return c.argv[0]
		}
	}
	return section
}

func anySection(b *Bundle, names ...string) bool {
	for _, n := range names {
		if b.Has(n) {
			return true
		}
	}
	return false
}

func anyError(b *Bundle, names ...string) bool {
	errs := b.Errors()
	for _, n := range names {
		for label := range errs {
			if label == n || strings.HasPrefix(label, n+" ") {
				return true
			}
		}
	}
	return false
}
