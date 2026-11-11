//go:build linux

// Package lab is the proof: it loads rulesets into the real Linux kernel inside throwaway network
// namespaces, sends real packets, and compares what really happened with what the engine says.
//
// Ordinary `go test` checks the parts that need no privileges (scenario files, the generator, the
// shell script, the comparison). The real run is `go test -tags kernel ./internal/lab/ -run Kernel`.
package lab

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Outcome is what really happened to a probe.
type Outcome string

const (
	OutOpen    Outcome = "open"    // TCP connected, or the UDP echo came back
	OutRefused Outcome = "refused" // a TCP reset or an ICMP error came back
	OutSilent  Outcome = "silent"  // nothing came back in time
	OutError   Outcome = "error"   // the lab itself failed to send the probe
)

func parseOutcome(s string) (Outcome, bool) {
	switch o := Outcome(s); o {
	case OutOpen, OutRefused, OutSilent:
		return o, true
	}
	return "", false
}

// Listen is one socket the lab opens before the probes are sent.
type Listen struct {
	NS    string // "host", "ctr" or "ctr2"
	Proto string // "tcp" or "udp"
	Addr  netip.Addr
	Port  uint16
	// V6Only is set for an IPv6 socket that must not take IPv4 ("v6only"); an IPv6 wildcard
	// socket is dual-stack otherwise, as on a default Linux.
	V6Only bool
	Dev    string // SO_BINDTODEVICE, "" for none
}

// String is the listen line as written in a scenario file.
func (l Listen) String() string {
	s := fmt.Sprintf("%s %s %s %d", l.NS, l.Proto, l.Addr, l.Port)
	if l.Addr.Is6() {
		if l.V6Only {
			s += " v6only"
		} else if l.Addr.IsUnspecified() {
			s += " dual"
		}
	}
	if l.Dev != "" {
		s += " dev=" + l.Dev
	}
	return s
}

// helperLine is the line handed to the listen helper.
func (l Listen) helperLine() string {
	v6only := "0"
	if l.V6Only {
		v6only = "1"
	}
	dev := "-"
	if l.Dev != "" {
		dev = l.Dev
	}
	return fmt.Sprintf("%s %s %d %s %s", l.Proto, l.Addr, l.Port, v6only, dev)
}

// Probe is one packet to send: the first packet of a new connection from outside.
type Probe struct {
	Iif   string // host interface it arrives on: "eth0" or "eth1"
	Src   netip.Addr
	Dst   netip.Addr
	Proto string
	Dport uint16
	// Want is the outcome the scenario author worked out from the rules; "" for none.
	Want Outcome
	// ExpectUndecided allows the engine to answer Undecided for this probe.
	ExpectUndecided bool
	Line            int // line in the scenario file, 0 for generated probes
}

// String is the probe as written in a scenario file, without annotations.
func (p Probe) String() string {
	return fmt.Sprintf("%s %s %s %s %d", p.Iif, p.Src, p.Dst, p.Proto, p.Dport)
}

// Scenario is one ruleset, its listeners and the probes to send.
type Scenario struct {
	Name  string
	About string
	File  string // where it was read from; empty for generated scenarios
	// Containers is 0, 1 or 2: how many container namespaces sit behind the docker0 bridge.
	Containers int
	// Forward is "yes", "no" or "" (then forwarding is on exactly when there are containers).
	Forward string
	Eth1    bool // add the second outside interface even if no probe uses it
	// Loopback lists spare addresses the host holds on its loopback interface, as a machine with
	// a floating or anycast address does. Each lies in eth0's subnet, so the peer reaches it
	// over the cable without a route.
	Loopback []netip.Addr
	Sysctls  []string // extra "key=value" lines set in the host after the interfaces exist
	// Publish is Docker's view of the published ports, "0.0.0.0:8080->80/tcp", one per entry.
	// The NAT and filter rules themselves are written in the iptables block.
	Publish         []string
	ExpectUndecided bool
	IPTables        string
	IP6Tables       string
	NFT             string
	Listens         []Listen
	Probes          []Probe
	// Seed is set for generated scenarios so a failure can be replayed.
	Seed  uint64
	Index int
}

// Forwarding says whether the host forwards packets between interfaces.
func (s *Scenario) Forwarding() bool {
	switch s.Forward {
	case "yes":
		return true
	case "no":
		return false
	}
	return s.Containers > 0
}

// UsesEth1 says whether the second outside interface is needed.
func (s *Scenario) UsesEth1() bool {
	if s.Eth1 {
		return true
	}
	for _, p := range s.Probes {
		if p.Iif == "eth1" {
			return true
		}
	}
	for _, l := range s.Listens {
		if l.Dev == "eth1" {
			return true
		}
	}
	return false
}

// Topology addresses. They are fixed so scenario files can name them.
var (
	hostEth0v4 = netip.MustParseAddr("203.0.113.10")
	hostEth0v6 = netip.MustParseAddr("2001:db8:1::10")
	peerEth0v4 = netip.MustParseAddr("203.0.113.1")
	peerEth0v6 = netip.MustParseAddr("2001:db8:1::1")
	hostEth1v4 = netip.MustParseAddr("10.20.0.1")
	hostEth1v6 = netip.MustParseAddr("2001:db8:2::1")
	peerEth1v4 = netip.MustParseAddr("10.20.0.50")
	peerEth1v6 = netip.MustParseAddr("2001:db8:2::50")

	// Sources a probe may come from, per arriving interface. The "anyip" ranges are local
	// routes in the peer, so any address in them can be used without configuring it; the
	// "link" ranges share the cable's subnet, and each address used is added to the peer.
	eth0AnyIP = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:99::/64")}
	eth0Link  = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:1::/64")}
	eth1AnyIP = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	eth1Link  = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("2001:db8:2::/64")}
)

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// checkSource says why a probe source cannot be used on an interface, or "" when it can.
func checkSource(iif string, src netip.Addr) string {
	var anyip, link []netip.Prefix
	var reserved []netip.Addr
	switch iif {
	case "eth0":
		anyip, link = eth0AnyIP, eth0Link
		reserved = []netip.Addr{hostEth0v4, hostEth0v6, peerEth0v4, peerEth0v6}
	case "eth1":
		anyip, link = eth1AnyIP, eth1Link
		reserved = []netip.Addr{hostEth1v4, hostEth1v6}
	default:
		return "the interface must be eth0 or eth1"
	}
	for _, r := range reserved {
		if src == r {
			return "the source is one of the lab's own cable addresses"
		}
	}
	if inAny(src, anyip) || inAny(src, link) {
		return ""
	}
	if iif == "eth0" {
		return "a source on eth0 must be in 198.51.100.0/24, 203.0.113.0/24, 2001:db8:99::/64 or 2001:db8:1::/64"
	}
	return "a source on eth1 must be in 192.0.2.0/24, 10.20.0.0/24 or 2001:db8:2::/64"
}

// ParseScenario reads one scenario file.
func ParseScenario(name, text string) (*Scenario, error) {
	sc := &Scenario{File: name}
	block := ""
	var rules = map[string]*strings.Builder{"iptables": {}, "ip6tables": {}, "nft": {}}
	errf := func(n int, format string, a ...any) error {
		return fmt.Errorf("%s:%d: %s", name, n, fmt.Sprintf(format, a...))
	}
	sc2 := bufio.NewScanner(strings.NewReader(text))
	sc2.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc2.Scan() {
		n++
		line := sc2.Text()
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "--- ") {
			block = strings.TrimSpace(trim[4:])
			switch block {
			case "iptables", "ip6tables", "nft", "listen", "probes":
			default:
				return nil, errf(n, "unknown block %q (want iptables, ip6tables, nft, listen or probes)", block)
			}
			continue
		}
		if b, ok := rules[block]; ok {
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		switch block {
		case "":
			key, val, ok := strings.Cut(trim, ":")
			if !ok {
				return nil, errf(n, "header line needs \"key: value\"")
			}
			val = strings.TrimSpace(val)
			switch strings.TrimSpace(key) {
			case "name":
				sc.Name = val
			case "about":
				if sc.About != "" {
					sc.About += " "
				}
				sc.About += val
			case "container":
				switch val {
				case "yes":
					sc.Containers = 1
				case "no":
					sc.Containers = 0
				default:
					return nil, errf(n, "container: yes or no")
				}
			case "containers":
				c, err := strconv.Atoi(val)
				if err != nil || c < 0 || c > 2 {
					return nil, errf(n, "containers: 0, 1 or 2")
				}
				sc.Containers = c
			case "forward":
				if val != "yes" && val != "no" {
					return nil, errf(n, "forward: yes or no")
				}
				sc.Forward = val
			case "eth1":
				sc.Eth1 = val == "yes"
			case "loopback":
				a, err := netip.ParseAddr(val)
				if err != nil || a.Zone() != "" {
					return nil, errf(n, "loopback: an address in 203.0.113.0/24 or 2001:db8:1::/64")
				}
				sc.Loopback = append(sc.Loopback, a)
			case "sysctl":
				k, v, ok := strings.Cut(val, "=")
				if !ok || !validSysctl(strings.TrimSpace(k)) || !validToken(strings.TrimSpace(v)) {
					return nil, errf(n, "sysctl: net.<key>=<value>")
				}
				sc.Sysctls = append(sc.Sysctls, strings.TrimSpace(k)+"="+strings.TrimSpace(v))
			case "publish":
				if !validPublish(val) {
					return nil, errf(n, "publish: <addr>:<port>-><port>/<tcp|udp>")
				}
				sc.Publish = append(sc.Publish, val)
			case "expect-undecided":
				sc.ExpectUndecided = val == "yes"
			default:
				return nil, errf(n, "unknown header %q", key)
			}
		case "listen":
			l, err := parseListen(trim)
			if err != nil {
				return nil, errf(n, "%v", err)
			}
			sc.Listens = append(sc.Listens, l)
		case "probes":
			p, err := parseProbe(trim)
			if err != nil {
				return nil, errf(n, "%v", err)
			}
			p.Line = n
			sc.Probes = append(sc.Probes, p)
		}
	}
	if err := sc2.Err(); err != nil {
		return nil, err
	}
	sc.IPTables = rules["iptables"].String()
	sc.IP6Tables = rules["ip6tables"].String()
	sc.NFT = rules["nft"].String()
	if strings.TrimSpace(sc.IPTables) == "" {
		sc.IPTables = ""
	}
	if strings.TrimSpace(sc.IP6Tables) == "" {
		sc.IP6Tables = ""
	}
	if strings.TrimSpace(sc.NFT) == "" {
		sc.NFT = ""
	}
	if err := sc.validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return sc, nil
}

func (sc *Scenario) validate() error {
	if sc.Name == "" {
		return fmt.Errorf("missing name:")
	}
	if !validToken(sc.Name) {
		return fmt.Errorf("name %q: use letters, digits, dots and dashes", sc.Name)
	}
	if len(sc.Probes) == 0 {
		return fmt.Errorf("no probes")
	}
	seen := map[string]bool{}
	for _, l := range sc.Listens {
		switch l.NS {
		case "ctr":
			if sc.Containers < 1 {
				return fmt.Errorf("listener %q needs container: yes", l)
			}
		case "ctr2":
			if sc.Containers < 2 {
				return fmt.Errorf("listener %q needs containers: 2", l)
			}
		}
		key := fmt.Sprintf("%s %s %d %s", l.NS, l.Proto, l.Port, l.Addr)
		if seen[key] {
			return fmt.Errorf("listener %q twice", l)
		}
		seen[key] = true
	}
	spare := map[netip.Addr]bool{}
	for _, a := range sc.Loopback {
		if !inAny(a, eth0Link) || a == hostEth0v4 || a == hostEth0v6 || a == peerEth0v4 || a == peerEth0v6 || spare[a] {
			return fmt.Errorf("loopback %s: use a free address in 203.0.113.0/24 or 2001:db8:1::/64, once", a)
		}
		spare[a] = true
	}
	for _, p := range sc.Probes {
		if spare[p.Src] {
			return fmt.Errorf("probe %q: the source is one of the host's loopback addresses", p)
		}
		if why := checkSource(p.Iif, p.Src); why != "" {
			return fmt.Errorf("probe %q: %s", p, why)
		}
		if p.Src.Is4() != p.Dst.Is4() {
			return fmt.Errorf("probe %q: source and destination are different families", p)
		}
		if p.Dst.IsLoopback() || p.Dst.IsUnspecified() || p.Dst.IsMulticast() {
			return fmt.Errorf("probe %q: the destination must be an ordinary address", p)
		}
	}
	return nil
}

func parseListen(line string) (Listen, error) {
	f := strings.Fields(line)
	if len(f) < 4 {
		return Listen{}, fmt.Errorf("listen line: <host|ctr|ctr2> <tcp|udp> <addr> <port> [dual|v6only] [dev=IF]")
	}
	l := Listen{NS: f[0], Proto: f[1]}
	if l.NS != "host" && l.NS != "ctr" && l.NS != "ctr2" {
		return l, fmt.Errorf("listen: namespace must be host, ctr or ctr2")
	}
	if l.Proto != "tcp" && l.Proto != "udp" {
		return l, fmt.Errorf("listen: protocol must be tcp or udp")
	}
	a, err := netip.ParseAddr(f[2])
	if err != nil || a.Zone() != "" {
		return l, fmt.Errorf("listen: bad address %q", f[2])
	}
	l.Addr = a
	p, err := strconv.ParseUint(f[3], 10, 16)
	if err != nil || p == 0 {
		return l, fmt.Errorf("listen: bad port %q", f[3])
	}
	l.Port = uint16(p)
	for _, opt := range f[4:] {
		switch {
		case opt == "dual":
			if !a.Is6() || !a.IsUnspecified() {
				return l, fmt.Errorf("listen: dual is for the :: wildcard")
			}
		case opt == "v6only":
			if !a.Is6() {
				return l, fmt.Errorf("listen: v6only is for IPv6 addresses")
			}
			l.V6Only = true
		case strings.HasPrefix(opt, "dev="):
			l.Dev = opt[4:]
			if !validIface(l.Dev) {
				return l, fmt.Errorf("listen: bad interface %q", l.Dev)
			}
		default:
			return l, fmt.Errorf("listen: unknown option %q", opt)
		}
	}
	return l, nil
}

func parseProbe(line string) (Probe, error) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return Probe{}, fmt.Errorf("probe line: <eth0|eth1> <src> <dst> <tcp|udp> <port> [want:open|refused|silent] [expect-undecided]")
	}
	p := Probe{Iif: f[0], Proto: f[3]}
	var err error
	if p.Src, err = netip.ParseAddr(f[1]); err != nil {
		return p, fmt.Errorf("probe: bad source %q", f[1])
	}
	if p.Dst, err = netip.ParseAddr(f[2]); err != nil {
		return p, fmt.Errorf("probe: bad destination %q", f[2])
	}
	if p.Proto != "tcp" && p.Proto != "udp" {
		return p, fmt.Errorf("probe: protocol must be tcp or udp")
	}
	port, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil || port == 0 {
		return p, fmt.Errorf("probe: bad port %q", f[4])
	}
	p.Dport = uint16(port)
	for _, opt := range f[5:] {
		switch {
		case strings.HasPrefix(opt, "want:"):
			o, ok := parseOutcome(opt[5:])
			if !ok {
				return p, fmt.Errorf("probe: want must be open, refused or silent")
			}
			p.Want = o
		case opt == "expect-undecided":
			p.ExpectUndecided = true
		default:
			return p, fmt.Errorf("probe: unknown annotation %q", opt)
		}
	}
	return p, nil
}

// Format writes the scenario in the file format ParseScenario reads. For a generated scenario
// with real outcomes at hand, wants fills in the want: annotations, so a failing random
// ruleset can be saved as a scenario file as it stands.
func (sc *Scenario) Format(wants map[int]Outcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\n", sc.Name)
	if sc.About != "" {
		fmt.Fprintf(&b, "about: %s\n", sc.About)
	}
	if sc.Containers == 1 {
		b.WriteString("container: yes\n")
	} else if sc.Containers > 1 {
		fmt.Fprintf(&b, "containers: %d\n", sc.Containers)
	}
	if sc.Forward != "" {
		fmt.Fprintf(&b, "forward: %s\n", sc.Forward)
	}
	if sc.Eth1 {
		b.WriteString("eth1: yes\n")
	}
	for _, a := range sc.Loopback {
		fmt.Fprintf(&b, "loopback: %s\n", a)
	}
	for _, s := range sc.Sysctls {
		fmt.Fprintf(&b, "sysctl: %s\n", s)
	}
	for _, s := range sc.Publish {
		fmt.Fprintf(&b, "publish: %s\n", s)
	}
	if sc.ExpectUndecided {
		b.WriteString("expect-undecided: yes\n")
	}
	block := func(name, body string) {
		if body == "" {
			return
		}
		fmt.Fprintf(&b, "--- %s\n%s", name, body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteByte('\n')
		}
	}
	block("iptables", sc.IPTables)
	block("ip6tables", sc.IP6Tables)
	block("nft", sc.NFT)
	if len(sc.Listens) > 0 {
		b.WriteString("--- listen\n")
		for _, l := range sc.Listens {
			b.WriteString(l.String() + "\n")
		}
	}
	b.WriteString("--- probes\n")
	for i, p := range sc.Probes {
		b.WriteString(p.String())
		want := p.Want
		if o, ok := wants[i]; ok {
			want = o
		}
		if want != "" {
			b.WriteString(" want:" + string(want))
		}
		if p.ExpectUndecided {
			b.WriteString(" expect-undecided")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// LoadScenarios reads every *.txt file in dir, sorted by name.
func LoadScenarios(dir string) ([]*Scenario, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []*Scenario
	names := map[string]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		sc, err := ParseScenario(filepath.Base(f), string(data))
		if err != nil {
			return nil, err
		}
		if prev, ok := names[sc.Name]; ok {
			return nil, fmt.Errorf("%s: name %q is already used by %s", f, sc.Name, prev)
		}
		names[sc.Name] = filepath.Base(f)
		out = append(out, sc)
	}
	return out, nil
}

// The script quotes nothing it takes from a scenario except through these checks, so a
// scenario file cannot smuggle shell syntax into the script.

func validToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// validSysctl allows only per-interface settings. They exist per network namespace on every
// kernel, so even under sudo (real root, no user namespace) they cannot reach the host.
func validSysctl(k string) bool {
	return (strings.HasPrefix(k, "net.ipv4.conf.") || strings.HasPrefix(k, "net.ipv6.conf.")) && validToken(k)
}

func validIface(s string) bool {
	return validToken(s) && len(s) < 16
}

func validPublish(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r == '.' || r == ':' || r == '[' || r == ']' ||
			r == '-' || r == '>' || r == '/' || r == 't' || r == 'c' || r == 'p' || r == 'u') {
			return false
		}
	}
	return strings.Contains(s, "->") && (strings.HasSuffix(s, "/tcp") || strings.HasSuffix(s, "/udp"))
}
