package snapshot

import (
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

func loadTestdata(t *testing.T) *Bundle {
	t.Helper()
	data, err := os.ReadFile("testdata/web-1.snapshot")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ruleParserNote reports whether a note is about the rule parsers, which other packages own;
// those notes may come and go as the parsers change.
func ruleParserNote(n string) bool {
	return strings.Contains(n, "could not be understood") && (strings.Contains(n, "packet rules") || strings.Contains(n, "ipsets ("))
}

func TestBuildTestdata(t *testing.T) {
	rs, h, err := Build(loadTestdata(t))
	if err != nil {
		t.Fatal(err)
	}
	if rs == nil || rs.Sets == nil {
		t.Fatal("no ruleset")
	}
	p := netip.MustParsePrefix
	a := netip.MustParseAddr
	l := func(proto, addr string, port uint16, proc string, pid int) host.Listener {
		return host.Listener{Proto: proto, Addr: a(addr), Port: port, Process: proc, PID: pid}
	}
	withDev := func(x host.Listener, dev string) host.Listener { x.Dev = dev; return x }
	inNS := func(x host.Listener, ns string) host.Listener { x.Netns = ns; return x }
	ufw := func(text string, port uint16, v6 bool) host.FrontendRule {
		return host.FrontendRule{Action: "allow", Proto: "tcp", PortLo: port, PortHi: port, IPv6: v6, Text: text}
	}
	want := &host.Host{
		Name: "web-1",
		Interfaces: []host.Interface{
			{Name: "lo", Up: true, Loopback: true, Addrs: []netip.Prefix{p("127.0.0.1/8"), p("::1/128")}},
			{Name: "eth0", Up: true, Addrs: []netip.Prefix{p("192.0.2.10/24"), p("2001:db8:10::10/64"), p("fe80::5054:ff:fe12:3456/64")}},
			{Name: "docker0", Up: true, Kind: "bridge", Addrs: []netip.Prefix{p("172.17.0.1/16")}},
			{Name: "br-7d1e0c2a9b44", Up: true, Kind: "bridge", Addrs: []netip.Prefix{p("172.18.0.1/16")}},
			{Name: "veth1a2b3c4", Up: true, Kind: "veth", Master: "br-7d1e0c2a9b44"},
		},
		Routes: []host.Route{
			{Dst: p("0.0.0.0/0"), Dev: "eth0", Gateway: a("192.0.2.1"), Type: "unicast"},
			{Dst: p("172.17.0.0/16"), Dev: "docker0", Type: "unicast"},
			{Dst: p("172.18.0.0/16"), Dev: "br-7d1e0c2a9b44", Type: "unicast"},
			{Dst: p("192.0.2.0/24"), Dev: "eth0", Type: "unicast"},
			{Dst: p("2001:db8:10::/64"), Dev: "eth0", Type: "unicast"},
			{Dst: p("fe80::/64"), Dev: "eth0", Type: "unicast"},
			{Dst: p("::/0"), Dev: "eth0", Gateway: a("2001:db8:10::1"), Type: "unicast"},
		},
		Forward4:      true,
		Forward6:      false,
		RouteLocalnet: map[string]bool{},
		Listeners: []host.Listener{
			withDev(l("udp", "127.0.0.53", 53, "systemd-resolve", 601), "lo"),
			withDev(l("udp", "192.0.2.10", 68, "systemd-network", 588), "eth0"),
			withDev(l("tcp", "127.0.0.53", 53, "systemd-resolve", 601), "lo"),
			l("tcp", "0.0.0.0", 22, "sshd", 812),
			l("tcp", "0.0.0.0", 8080, "docker-proxy", 1402),
			l("tcp", "127.0.0.1", 5432, "docker-proxy", 1460),
			l("tcp", "::", 22, "sshd", 812),
			l("tcp", "::", 8080, "docker-proxy", 1409),
			inNS(l("tcp", "0.0.0.0", 80, "nginx", 1388), idWeb),
			inNS(l("tcp", "0.0.0.0", 5432, "postgres", 1447), idDB),
			inNS(l("tcp", "::", 5432, "postgres", 1447), idDB),
		},
		Docker: &host.Docker{Version: "27.3.1", Containers: []host.Container{
			{ID: idWeb, Name: "web", Image: "nginx:1.27",
				Networks: []host.ContainerNet{{Network: "app", Addr: a("172.18.0.2")}},
				Ports: []host.Published{
					{Proto: "tcp", HostAddr: a("0.0.0.0"), HostPort: 8080, ContainerPort: 80},
					{Proto: "tcp", HostAddr: a("::"), HostPort: 8080, ContainerPort: 80},
				}, ListenersKnown: true},
			{ID: idDB, Name: "postgres", Image: "postgres:16",
				Networks:       []host.ContainerNet{{Network: "app", Addr: a("172.18.0.3")}},
				Ports:          []host.Published{{Proto: "tcp", HostAddr: a("127.0.0.1"), HostPort: 5432, ContainerPort: 5432}},
				ListenersKnown: true},
		}},
		Frontend: &host.Frontend{Tool: "ufw", Active: true, DefaultIncoming: "deny", Rules: []host.FrontendRule{
			ufw("22/tcp                     ALLOW IN    Anywhere", 22, false),
			ufw("80,443/tcp                 ALLOW IN    Anywhere                   # web", 80, false),
			ufw("80,443/tcp                 ALLOW IN    Anywhere                   # web", 443, false),
			ufw("22/tcp (v6)                ALLOW IN    Anywhere (v6)", 22, true),
			ufw("80,443/tcp (v6)            ALLOW IN    Anywhere (v6)              # web", 80, true),
			ufw("80,443/tcp (v6)            ALLOW IN    Anywhere (v6)              # web", 443, true),
		}},
	}
	var other []string
	for _, n := range h.Notes {
		if !ruleParserNote(n) {
			other = append(other, n)
		}
	}
	if len(other) != 0 {
		t.Errorf("unexpected notes: %q", other)
	}
	got := *h
	got.Notes = nil
	if !reflect.DeepEqual(&got, want) {
		gv, wv := reflectFields(&got), reflectFields(want)
		for k := range wv {
			if !reflect.DeepEqual(gv[k], wv[k]) {
				t.Errorf("%s:\n got  %+v\n want %+v", k, gv[k], wv[k])
			}
		}
	}
}

func reflectFields(h *host.Host) map[string]any {
	v := reflect.ValueOf(h).Elem()
	out := map[string]any{}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Pointer && !f.IsNil() {
			out[v.Type().Field(i).Name] = f.Elem().Interface()
			continue
		}
		out[v.Type().Field(i).Name] = f.Interface()
	}
	return out
}

func TestBuildNotRoot(t *testing.T) {
	b, err := Parse(`# seaward snapshot 1
### meta
host web-1
collector script
root no
### iptables-version
iptables v1.8.10 (nf_tables)
### ss
tcp   LISTEN 0      128   0.0.0.0:22   0.0.0.0:*
### ip-addr
[]
### ip-route-4
[]
### sysctl
net.ipv4.ip_forward = 0
### docker-ps
{"ID":"` + idWeb + `","Names":"web","Networks":"app","Ports":"0.0.0.0:8080->80/tcp","State":"running"}
### docker-net
` + idWeb + ` 1388 app app=172.18.0.2|
### errors
iptables-save: exit status 4
ip6tables-save: exit status 4
nft-json: Operation not permitted (you must be root)
ufw-status: ERROR: You need to be root to run this script
`)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err := Build(b)
	if err != nil {
		t.Fatal(err)
	}
	wantNotes := []string{
		"The IPv4 packet rules (iptables) could not be read: iptables-save needs root.",
		"The IPv6 packet rules (ip6tables) could not be read: ip6tables-save needs root.",
		"The nftables packet rules could not be read: nft needs root.",
		"The ufw settings could not be read: ufw needs root.",
		"The names of the programs behind each port were not read: the snapshot was taken without root.",
		"What listens inside 1 container(s) was not read: that needs root. Whether anything answers on their published ports is not known.",
	}
	if !reflect.DeepEqual(h.Notes, wantNotes) {
		t.Errorf("notes:\n got  %q\n want %q", h.Notes, wantNotes)
	}
	if h.Frontend != nil {
		t.Errorf("frontend from nothing: %+v", h.Frontend)
	}
	if h.NoListenerData || h.Docker.Containers[0].ListenersKnown {
		t.Error("ss was read, the container's listeners were not")
	}
}

func TestBuildNoListenerData(t *testing.T) {
	_, h, _ := Build(mustParse(t, "# seaward snapshot 1\n### meta\nroot yes\n### errors\nss: timed out after 5s\n"))
	if !h.NoListenerData {
		t.Error("a snapshot without ss must say it has no listener data")
	}
	_, h, _ = Build(mustParse(t, "# seaward snapshot 1\n### ss\n"))
	if h.NoListenerData {
		t.Error("an empty ss section means nothing listens, not no data")
	}
}

func TestBuildFirewalldDefaultZoneTakesUnclaimedInterfaces(t *testing.T) {
	b := mustParse(t, "# seaward snapshot 1\n### ip-addr\n"+
		`[{"ifname":"lo","flags":["LOOPBACK","UP"]},{"ifname":"eth0","flags":["UP"]},{"ifname":"eth1","flags":["UP"]},{"ifname":"docker0","flags":["UP"]}]`+
		"\n### firewalld-state\nrunning\n### firewalld-active\ndocker\n  interfaces: docker0\n"+
		"### firewalld-zones\ndocker (active)\n  target: ACCEPT\n  interfaces: docker0\n  services: \n  ports: \n\n"+
		"public (default)\n  target: default\n  interfaces: \n  services: \n  ports: 443/tcp\n")
	_, h, _ := Build(b)
	if h.Frontend == nil || h.Frontend.DefaultIncoming != "reject" {
		t.Fatalf("frontend: %+v", h.Frontend)
	}
	ifaces := map[string]bool{}
	for _, r := range h.Frontend.Rules {
		if r.Zone != "public" || r.PortLo != 443 {
			t.Errorf("rule %+v", r)
		}
		ifaces[r.Iface] = true
	}
	if !reflect.DeepEqual(ifaces, map[string]bool{"eth0": true, "eth1": true}) {
		t.Errorf("the default zone covers the interfaces no zone claims: %v", ifaces)
	}
}

func TestBuildNoRulesAtAll(t *testing.T) {
	b, _ := Parse("# seaward snapshot 1\n### meta\nhost box\nroot yes\n### ss\n### ip-addr\n[]\n### ip-route-4\n[]\n### sysctl\nnet.ipv4.ip_forward = 0\n")
	rs, h, err := Build(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Tables) != 0 {
		t.Error("tables from nothing")
	}
	if !reflect.DeepEqual(h.Notes, []string{"This machine has no packet rules: nothing in the kernel filters traffic."}) {
		t.Errorf("notes: %q", h.Notes)
	}

	b, _ = Parse("# seaward snapshot 1\n### meta\nhost box\nroot no\n### ss\n### ip-addr\n[]\n### ip-route-4\n[]\n### sysctl\nnet.ipv4.ip_forward = 0\n")
	_, h, _ = Build(b)
	if !slices.Contains(h.Notes, "The packet rules were not read: the snapshot was taken without root.") {
		t.Errorf("notes: %q", h.Notes)
	}
}

func TestBuildEmptyBundle(t *testing.T) {
	rs, h, err := Build(&Bundle{})
	if err != nil || rs == nil || h == nil {
		t.Fatalf("an empty bundle is still a snapshot: %v", err)
	}
	for _, w := range []string{"network interfaces", "IPv4 routes", "forwarding settings", "listening sockets", "no packet rules"} {
		if !slices.ContainsFunc(h.Notes, func(n string) bool { return strings.Contains(n, w) }) {
			t.Errorf("no note about %q: %q", w, h.Notes)
		}
	}
	if _, _, err := Build(nil); err == nil {
		t.Error("nil bundle should be an error")
	}
}

func TestBuildBrokenSections(t *testing.T) {
	b, _ := Parse("# seaward snapshot 1\n### meta\nroot yes\n### ip-addr\nnot json\n### ip-route-6\n{\n### iptables-save\n*filter\nCOMMIT\n### nft-json\n{]\n" +
		"### errors\nss: timed out after 5s\ndocker-ps: permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n" +
		"sysctl: something odd.\n")
	_, h, err := Build(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"The network interfaces and their addresses could not be understood",
		"The IPv6 routes could not be understood",
		"The listening sockets could not be read: ss did not answer in time.",
		"The Docker containers could not be read: docker needs root or membership of the docker group.",
		"The forwarding settings could not be read: sysctl failed (something odd).",
	} {
		if !slices.ContainsFunc(h.Notes, func(n string) bool { return strings.HasPrefix(n, w) }) {
			t.Errorf("no note starting %q in %q", w, h.Notes)
		}
	}
}

func TestBuildFrontendChoice(t *testing.T) {
	fw := "### firewalld-state\nrunning\n### firewalld-zones\npublic (default, active)\n  target: default\n  interfaces: eth0\n  services: \n  ports: 8080/tcp\n"
	ufwOff := "### ufw-status\nStatus: inactive\n"
	ufwOn := "### ufw-status\nStatus: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n"

	_, h, _ := Build(mustParse(t, "# seaward snapshot 1\n"+ufwOff+fw))
	if h.Frontend == nil || h.Frontend.Tool != "firewalld" || len(h.Frontend.Rules) != 2 {
		t.Errorf("running firewalld beats inactive ufw: %+v", h.Frontend)
	}
	_, h, _ = Build(mustParse(t, "# seaward snapshot 1\n"+ufwOn+fw))
	if h.Frontend.Tool != "ufw" || !slices.ContainsFunc(h.Notes, func(n string) bool { return strings.Contains(n, "Both ufw and firewalld") }) {
		t.Errorf("both: %+v %q", h.Frontend, h.Notes)
	}
	_, h, _ = Build(mustParse(t, "# seaward snapshot 1\n"+ufwOff))
	if h.Frontend.Tool != "ufw" || h.Frontend.Active {
		t.Errorf("inactive ufw: %+v", h.Frontend)
	}
}

func TestBuildDockerSSShortID(t *testing.T) {
	b := mustParse(t, "# seaward snapshot 1\n### meta\nroot yes\n### docker-ps\n"+
		`{"ID":"`+idWeb+`","Names":"web","Networks":"app","Ports":"","State":"running"}`+
		"\n### docker-ss "+idWeb[:12]+"\ntcp LISTEN 0 1 0.0.0.0:80 0.0.0.0:*\n")
	_, h, _ := Build(b)
	if len(h.Listeners) != 1 || h.Listeners[0].Netns != idWeb {
		t.Errorf("listeners: %+v", h.Listeners)
	}
	for _, n := range h.Notes {
		if strings.Contains(n, "inside") {
			t.Errorf("container was read: %q", n)
		}
	}
}

func mustParse(t *testing.T, s string) *Bundle {
	t.Helper()
	b, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildUnreadRuleSources(t *testing.T) {
	const head = "# seaward snapshot 1\n### meta\nhost box\n"
	const rest = "### ss\n### ip-addr\n[]\n### ip-route-4\n[]\n### sysctl\nnet.ipv4.ip_forward = 0\n"
	fams := func(rs *rules.Ruleset) string {
		var out []string
		for _, u := range rs.Unread {
			f := u.Family
			if f == "" {
				f = "both"
			}
			out = append(out, f)
		}
		slices.Sort(out)
		return strings.Join(out, " ")
	}
	for _, c := range []struct {
		name, bundle, want string
	}{
		{"everything read", head + "root yes\n### iptables-save\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n" + rest, ""},
		{"no rules on the machine", head + "root yes\n" + rest, ""},
		{"not root, nothing collected", head + "root no\n" + rest, "both"},
		{"not root, commands failed", head + "root no\n" + rest +
			"### errors\niptables-save: exit status 4\nip6tables-save: exit status 4\nnft-json: Operation not permitted (you must be root)\nufw-status: ERROR: You need to be root to run this script\n", "both ip ip6"},
		{"one listing failed", head + "root yes\n### iptables-save\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n" + rest +
			"### errors\nip6tables-save: timed out after 5s\n", "ip6"},
		{"a listing that is not one", head + "root yes\n### iptables-save\n-A INPUT -j ACCEPT\n" + rest, "ip"},
		{"a table only nft can list, and no nft listing", head + "root yes\n### iptables-save\n" +
			"# Table `filter' is incompatible, use 'nft' tool.\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n" + rest, "ip"},
	} {
		rs, h, err := Build(mustParse(t, c.bundle))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := fams(rs); got != c.want {
			t.Errorf("%s: unread families %q, want %q (%+v)", c.name, got, c.want, rs.Unread)
		}
		// Every unread source is also told to the reader.
		for _, u := range rs.Unread {
			if !slices.Contains(h.Notes, u.Why) {
				t.Errorf("%s: %q is not among the notes %q", c.name, u.Why, h.Notes)
			}
		}
	}
}
