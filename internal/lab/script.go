package lab

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// guard is the first thing the script runs. It refuses to go on unless the launcher started it
// (the marker) and the network namespace is brand new (nothing but lo, which every fresh
// namespace starts with and no real machine has alone). Nothing may run before it.
const guard = `[ "${SEAWARD_LAB_INSIDE:-}" = 1 ] || { echo 'lab guard: not started by the lab launcher, refusing to run' >&2; exit 97; }
lab_links=$(ip -o link show) || { echo 'lab guard: cannot list interfaces, refusing to run' >&2; exit 97; }
[ "$(printf '%s\n' "$lab_links" | wc -l)" -eq 1 ] || { echo 'lab guard: more than one interface, this is not a fresh network namespace' >&2; exit 98; }
case "$lab_links" in "1: lo: "*) ;; *) echo 'lab guard: the only interface is not lo, refusing to run' >&2; exit 98 ;; esac
`

// scriptHeader is the shebang and a comment; neither runs anything.
const scriptHeader = "#!/bin/sh\n# Seaward lab scenario. Runs only inside a fresh network namespace; see the guard below.\n"

// MAC addresses are fixed so neighbour entries can be written ahead of time: with permanent
// entries no probe depends on ARP or neighbour discovery getting through the rules under test.
const (
	macHostEth0 = "02:00:00:00:00:10"
	macPeerEth0 = "02:00:00:00:00:01"
	macHostEth1 = "02:00:00:00:01:01"
	macPeerEth1 = "02:00:00:00:01:50"
	macDocker0  = "02:42:ac:11:00:01"
)

// Container namespaces, in order. Their IDs are fixed so docker-ps, docker-net and docker-ss agree.
var containers = []struct {
	NS, ID, Name, Addr, MAC, Veth string
}{
	{"ctr", "c1c1c1c1c1c1", "web", "172.17.0.2", "02:42:ac:11:00:02", "vethc1"},
	{"ctr2", "c2c2c2c2c2c2", "db", "172.17.0.3", "02:42:ac:11:00:03", "vethc2"},
}

// ScriptOptions tune the generated script.
type ScriptOptions struct {
	// TimeoutMS is how long the prober waits for an answer before calling a probe silent.
	TimeoutMS int
}

// DefaultTimeoutMS was chosen by measuring: with every scenario running at once on all CPUs,
// every answer came back within a few milliseconds, so 900 ms is a wide margin. It stays under
// one second, TCP's first SYN retransmission, so a probe is exactly one packet.
const DefaultTimeoutMS = 900

// Files returns the files the script reads, by name, to be written next to it in LAB_OUT.
func Files(sc *Scenario) map[string]string {
	f := map[string]string{}
	if sc.IPTables != "" {
		f["iptables.rules"] = sc.IPTables
	}
	if sc.IP6Tables != "" {
		f["ip6tables.rules"] = sc.IP6Tables
	}
	if sc.NFT != "" {
		f["nft.rules"] = sc.NFT
	}
	byNS := map[string]*strings.Builder{"host": {}}
	for i := 0; i < sc.Containers; i++ {
		byNS[containers[i].NS] = &strings.Builder{}
	}
	for _, l := range sc.Listens {
		byNS[l.NS].WriteString(l.helperLine() + "\n")
	}
	for ns, b := range byNS {
		f["listen-"+ns+".txt"] = b.String()
	}
	for _, iif := range []string{"eth0", "eth1"} {
		var b strings.Builder
		for i, p := range sc.Probes {
			if p.Iif == iif {
				fmt.Fprintf(&b, "%d %s %s %s %d\n", i, p.Src, p.Dst, p.Proto, p.Dport)
			}
		}
		if b.Len() > 0 {
			f["probes-"+iif+".txt"] = b.String()
		}
	}
	return f
}

// linkSources returns the probe sources on one interface that share the cable's subnet; each is
// added to the peer and given a neighbour entry on the host.
func linkSources(sc *Scenario, iif string, link []netip.Prefix, skip netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, p := range sc.Probes {
		if p.Iif == iif && inAny(p.Src, link) && p.Src != skip && !seen[p.Src] {
			seen[p.Src] = true
			out = append(out, p.Src)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// nodad skips duplicate address detection, so an IPv6 address is usable at once.
func nodad(a netip.Addr) string {
	if a.Is6() {
		return " nodad"
	}
	return ""
}

func bit(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Script returns the shell script that builds the scenario, takes the snapshot and sends the
// probes. It reads its input files from $LAB_OUT and runs the helper at $LAB_HELPER.
func Script(sc *Scenario, opt ScriptOptions) string {
	if opt.TimeoutMS <= 0 {
		opt.TimeoutMS = DefaultTimeoutMS
	}
	files := Files(sc)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	b.WriteString(scriptHeader)
	b.WriteString(guard)
	w(`# From here on everything runs inside the fresh namespace.`)
	w(`set -eu`)
	w(`[ -n "${LAB_OUT:-}" ] && [ -x "${LAB_HELPER:-}" ] || { echo 'lab: LAB_OUT and LAB_HELPER must be set' >&2; exit 96; }`)
	w(`# A private /run gives this namespace its own xtables lock and its own /run/netns.`)
	w(`mount -t tmpfs tmpfs /run`)
	w(`ip link set lo up`)
	w(`lab_pids=""`)
	w(`lab_cleanup() { for p in $lab_pids; do kill "$p" 2>/dev/null || true; done; }`)
	w(`trap lab_cleanup EXIT`)
	w(`lab_ready() {`)
	w(`  i=0`)
	w(`  until grep -q '^READY' "$1" 2>/dev/null; do`)
	w(`    if grep -q '^FAIL' "$1" 2>/dev/null; then cat "$1" >&2; return 1; fi`)
	w(`    i=$((i + 1)); [ "$i" -lt 1000 ] || { echo "lab: listener did not start: $1" >&2; return 1; }`)
	w(`    sleep 0.01`)
	w(`  done`)
	w(`}`)
	w(`lab_sec() { n=$1; shift; echo "### $n"; { "$@" 2>>"$LAB_OUT/snapshot.err" || echo "$n: exit $?" >>"$LAB_OUT/snapshot.err"; } | sed 's/^### / &/'; }`)
	w(`lab_sysctls() { sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding; sysctl -a -r 'net\.ipv4\.conf\..*\.route_localnet' 2>/dev/null; }`)

	w(`# A new namespace copies its IPv4 settings from the machine it was made on, so every`)
	w(`# setting the walk depends on is set here, before any interface exists to inherit it.`)
	w(`sysctl -q -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0`)
	w(`sysctl -q -w net.ipv4.conf.all.route_localnet=0 net.ipv4.conf.default.route_localnet=0`)
	w(`sysctl -q -w net.ipv4.ip_forward=%d`, bit(sc.Forwarding()))
	w(`sysctl -q -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0`)
	w(`sysctl -q -w net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0`)
	w(`sysctl -q -w net.ipv6.conf.all.forwarding=%d net.ipv6.conf.default.forwarding=%d`, bit(sc.Forwarding()), bit(sc.Forwarding()))
	w(`# ICMP errors are rate limited per sender and per namespace; many probes at once would`)
	w(`# lose some. Raising the limits is not enough: when several CPUs send the first errors of`)
	w(`# a fresh namespace at once, the global limiter's first refill races and drops one. An`)
	w(`# empty rate mask exempts every ICMP type from both limiters.`)
	w(`sysctl -q -w net.ipv4.icmp_ratemask=0 net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0`)
	w(`sysctl -q -w net.ipv6.icmp.ratemask= 2>/dev/null || true`)
	w(`sysctl -q -w net.ipv4.icmp_msgs_per_sec=1000000 net.ipv4.icmp_msgs_burst=1000000 2>/dev/null || true`)

	w(`# The outside world: the peer namespace at the other end of a virtual cable on eth0.`)
	w(`ip netns add peer`)
	w(`ip link add eth0 address %s type veth peer name veth0 address %s netns peer`, macHostEth0, macPeerEth0)
	w(`ip addr add %s/24 dev eth0`, hostEth0v4)
	w(`ip addr add %s/64 dev eth0 nodad`, hostEth0v6)
	w(`ip link set eth0 up`)
	w(`ip -n peer link set lo up`)
	w(`ip -n peer addr add %s/24 dev veth0`, peerEth0v4)
	w(`ip -n peer addr add %s/64 dev veth0 nodad`, peerEth0v6)
	w(`ip -n peer link set veth0 up`)
	w(`# Local routes let the prober send from any address in these ranges.`)
	w(`ip -n peer route add local %s dev lo`, eth0AnyIP[0])
	w(`ip -n peer -6 route add local %s dev lo`, eth0AnyIP[1])
	w(`ip -n peer route add 10.20.0.0/24 via %s`, hostEth0v4)
	w(`ip -n peer -6 route add 2001:db8:2::/64 via %s`, hostEth0v6)
	w(`ip route add default via %s dev eth0`, peerEth0v4)
	w(`ip -6 route add default via %s dev eth0`, peerEth0v6)
	w(`ip neigh replace %s lladdr %s dev eth0 nud permanent`, peerEth0v4, macPeerEth0)
	w(`ip -6 neigh replace %s lladdr %s dev eth0 nud permanent`, peerEth0v6, macPeerEth0)
	w(`ip -n peer neigh replace %s lladdr %s dev veth0 nud permanent`, hostEth0v4, macHostEth0)
	w(`ip -n peer -6 neigh replace %s lladdr %s dev veth0 nud permanent`, hostEth0v6, macHostEth0)
	for _, a := range linkSources(sc, "eth0", eth0Link, netip.Addr{}) {
		w(`ip -n peer addr add %s dev lo%s`, netip.PrefixFrom(a, a.BitLen()), nodad(a))
		w(`ip neigh replace %s lladdr %s dev eth0 nud permanent`, a, macPeerEth0)
	}

	if sc.UsesEth1() {
		w(`# A second outside network on eth1, played by the peer2 namespace.`)
		w(`ip netns add peer2`)
		w(`ip link add eth1 address %s type veth peer name veth1 address %s netns peer2`, macHostEth1, macPeerEth1)
		w(`ip addr add %s/24 dev eth1`, hostEth1v4)
		w(`ip addr add %s/64 dev eth1 nodad`, hostEth1v6)
		w(`ip link set eth1 up`)
		w(`ip -n peer2 link set lo up`)
		w(`ip -n peer2 addr add %s/24 dev veth1`, peerEth1v4)
		w(`ip -n peer2 addr add %s/64 dev veth1 nodad`, peerEth1v6)
		w(`ip -n peer2 link set veth1 up`)
		w(`ip -n peer2 route add local %s dev lo`, eth1AnyIP[0])
		w(`ip -n peer2 route add default via %s`, hostEth1v4)
		w(`ip -n peer2 -6 route add default via %s`, hostEth1v6)
		w(`ip route add %s via %s dev eth1`, eth1AnyIP[0], peerEth1v4)
		w(`ip neigh replace %s lladdr %s dev eth1 nud permanent`, peerEth1v4, macPeerEth1)
		w(`ip -6 neigh replace %s lladdr %s dev eth1 nud permanent`, peerEth1v6, macPeerEth1)
		w(`ip -n peer2 neigh replace %s lladdr %s dev veth1 nud permanent`, hostEth1v4, macHostEth1)
		w(`ip -n peer2 -6 neigh replace %s lladdr %s dev veth1 nud permanent`, hostEth1v6, macHostEth1)
		for _, a := range linkSources(sc, "eth1", eth1Link, peerEth1v4) {
			if a == peerEth1v6 {
				continue
			}
			w(`ip -n peer2 addr add %s dev lo%s`, netip.PrefixFrom(a, a.BitLen()), nodad(a))
			w(`ip neigh replace %s lladdr %s dev eth1 nud permanent`, a, macPeerEth1)
		}
	}

	if sc.Containers > 0 {
		w(`# Containers: namespaces behind the docker0 bridge, as Docker builds them.`)
		w(`ip link add docker0 address %s type bridge`, macDocker0)
		w(`ip addr add 172.17.0.1/16 dev docker0`)
		w(`ip link set docker0 up`)
		w(`ip -n peer route add 172.17.0.0/16 via %s`, hostEth0v4)
		for i := 0; i < sc.Containers; i++ {
			c := containers[i]
			w(`ip netns add %s`, c.NS)
			w(`ip link add %s type veth peer name eth0 address %s netns %s`, c.Veth, c.MAC, c.NS)
			w(`ip link set %s master docker0 up`, c.Veth)
			w(`ip -n %s link set lo up`, c.NS)
			w(`ip -n %s addr add %s/16 dev eth0`, c.NS, c.Addr)
			w(`ip -n %s link set eth0 up`, c.NS)
			w(`ip -n %s route add default via 172.17.0.1`, c.NS)
			w(`ip neigh replace %s lladdr %s dev docker0 nud permanent`, c.Addr, c.MAC)
			w(`ip -n %s neigh replace 172.17.0.1 lladdr %s dev eth0 nud permanent`, c.NS, macDocker0)
		}
	}

	for _, s := range sc.Sysctls {
		w(`sysctl -q -w %s`, s)
	}

	w(`# The rules under test.`)
	if _, ok := files["iptables.rules"]; ok {
		w(`iptables-restore < "$LAB_OUT/iptables.rules"`)
	}
	if _, ok := files["ip6tables.rules"]; ok {
		w(`ip6tables-restore < "$LAB_OUT/ip6tables.rules"`)
	}
	if _, ok := files["nft.rules"]; ok {
		w(`nft -f "$LAB_OUT/nft.rules"`)
	}

	w(`# Listeners: the test binary run again as a helper. A container always gets one, even with`)
	w(`# nothing to open, because docker-net needs a process inside it.`)
	w(`SEAWARD_LAB_HELPER=listen "$LAB_HELPER" "$LAB_OUT/listen-host.txt" >"$LAB_OUT/listen-host.out" 2>&1 &`)
	w(`lab_pids="$lab_pids $!"`)
	for i := 0; i < sc.Containers; i++ {
		c := containers[i]
		w(`SEAWARD_LAB_HELPER=listen ip netns exec %s "$LAB_HELPER" "$LAB_OUT/listen-%s.txt" >"$LAB_OUT/listen-%s.out" 2>&1 &`, c.NS, c.NS, c.NS)
		w(`lab_pid_%s=$!`, c.NS)
		w(`lab_pids="$lab_pids $!"`)
	}
	w(`lab_ready "$LAB_OUT/listen-host.out"`)
	for i := 0; i < sc.Containers; i++ {
		w(`lab_ready "$LAB_OUT/listen-%s.out"`, containers[i].NS)
	}

	w(`# The snapshot, taken with the same commands the collector runs.`)
	w(`{`)
	w(`echo '# seaward snapshot 1'`)
	w(`echo '### meta'`)
	w(`echo 'host lab-%s'`, sc.Name)
	w(`echo 'seaward lab'`)
	w(`echo 'collector script'`)
	w(`echo 'root yes'`)
	w(`lab_sec iptables-version iptables -V`)
	w(`lab_sec iptables-save iptables-save`)
	w(`lab_sec ip6tables-save ip6tables-save`)
	w(`lab_sec nft-json nft -j list ruleset`)
	w(`lab_sec ss ss -Htulpn`)
	w(`lab_sec ip-addr ip -j -d addr show`)
	w(`lab_sec ip-route-4 ip -j -4 route show table main`)
	w(`lab_sec ip-route-6 ip -j -6 route show table main`)
	w(`lab_sec sysctl lab_sysctls`)
	if sc.Containers > 0 {
		w(`echo '### docker-version'`)
		w(`echo '28.0.0'`)
		w(`echo '### docker-ps'`)
		for i := 0; i < sc.Containers; i++ {
			w(`echo '%s'`, dockerPS(sc, i))
		}
		w(`echo '### docker-net'`)
		for i := 0; i < sc.Containers; i++ {
			c := containers[i]
			w(`echo "%s $lab_pid_%s bridge bridge=%s|"`, c.ID, c.NS, c.Addr)
		}
		for i := 0; i < sc.Containers; i++ {
			c := containers[i]
			w(`lab_sec 'docker-ss %s' ip netns exec %s ss -Htulpn`, c.ID, c.NS)
		}
	}
	w(`} >"$LAB_OUT/snapshot.txt"`)

	w(`# The probes: all at once, from the outside namespaces.`)
	var waits []string
	for _, iif := range []string{"eth0", "eth1"} {
		if _, ok := files["probes-"+iif+".txt"]; !ok {
			continue
		}
		ns := map[string]string{"eth0": "peer", "eth1": "peer2"}[iif]
		w(`SEAWARD_LAB_HELPER=probe ip netns exec %s "$LAB_HELPER" "$LAB_OUT/probes-%s.txt" %d >"$LAB_OUT/results-%s.jsonl" 2>"$LAB_OUT/probe-%s.err" &`,
			ns, iif, opt.TimeoutMS, iif, iif)
		w(`lab_probe_%s=$!`, iif)
		waits = append(waits, "lab_probe_"+iif)
	}
	for _, v := range waits {
		w(`wait "$%s"`, v)
	}
	w(`# Kernel counters, so a lost answer can be traced to where it was lost.`)
	w(`{ echo '# host'; nstat -asz 2>/dev/null; echo '# peer'; ip netns exec peer nstat -asz 2>/dev/null; } >"$LAB_OUT/counters.txt" || true`)
	w(`echo ok >"$LAB_OUT/done"`)
	return b.String()
}

// dockerPS is the docker ps JSON line for container i. Only the first container carries the
// scenario's published ports; Docker publishes per container, and the scenarios that need two
// containers publish from the first.
func dockerPS(sc *Scenario, i int) string {
	c := containers[i]
	ports := ""
	if i == 0 {
		ports = strings.Join(sc.Publish, ", ")
	}
	return fmt.Sprintf(`{"ID":%q,"Names":%q,"Image":"lab","Ports":%q,"Networks":"bridge","State":"running"}`,
		c.ID, c.Name, ports)
}
