package snapshot

import (
	"net/netip"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

func TestParseSSLine(t *testing.T) {
	a := netip.MustParseAddr
	tests := []struct {
		name string
		in   string
		want *host.Listener // nil: the row is skipped
	}{
		{"ipv4 any", `tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))`,
			&host.Listener{Proto: "tcp", Addr: a("0.0.0.0"), Port: 22, Process: "sshd", PID: 812}},
		{"loopback", `tcp   LISTEN 0      244        127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=990,fd=7))`,
			&host.Listener{Proto: "tcp", Addr: a("127.0.0.1"), Port: 5432, Process: "postgres", PID: 990}},
		{"ipv6 any", `tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=812,fd=4))`,
			&host.Listener{Proto: "tcp", Addr: a("::"), Port: 22, Process: "sshd", PID: 812}},
		{"ipv6 loopback", `tcp   LISTEN 0      5              [::1]:631          [::]:*`,
			&host.Listener{Proto: "tcp", Addr: a("::1"), Port: 631}},
		{"dual stack star", `tcp   LISTEN 0      4096               *:8080             *:*    users:(("grafana",pid=2001,fd=9))`,
			&host.Listener{Proto: "tcp", Addr: a("::"), DualStack: true, Port: 8080, Process: "grafana", PID: 2001}},
		{"bound to lo", `udp   UNCONN 0      0      127.0.0.53%lo:53          0.0.0.0:*    users:(("systemd-resolve",pid=601,fd=13))`,
			&host.Listener{Proto: "udp", Addr: a("127.0.0.53"), Dev: "lo", Port: 53, Process: "systemd-resolve", PID: 601}},
		{"any on eth0", `udp   UNCONN 0      0        0.0.0.0%eth0:68          0.0.0.0:*`,
			&host.Listener{Proto: "udp", Addr: a("0.0.0.0"), Dev: "eth0", Port: 68}},
		{"link-local with device", `udp   UNCONN 0      0      [fe80::1]%eth0:546            [::]:*    users:(("dhcpcd",pid=77,fd=11))`,
			&host.Listener{Proto: "udp", Addr: a("fe80::1"), Dev: "eth0", Port: 546, Process: "dhcpcd", PID: 77}},
		{"zone inside brackets", `udp   UNCONN 0      0      [fe80::1%eth0]:546            [::]:*`,
			&host.Listener{Proto: "udp", Addr: a("fe80::1"), Dev: "eth0", Port: 546}},
		{"public address", `tcp   LISTEN 0      511       192.0.2.10:443        0.0.0.0:*    users:(("nginx",pid=1,fd=6),("nginx",pid=2,fd=6))`,
			&host.Listener{Proto: "tcp", Addr: a("192.0.2.10"), Port: 443, Process: "nginx", PID: 1}},
		{"docker proxy", `tcp   LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*    users:(("docker-proxy",pid=1,fd=7))`,
			&host.Listener{Proto: "tcp", Addr: a("0.0.0.0"), Port: 8080, Process: "docker-proxy", PID: 1}},
		{"name with spaces and brackets", `tcp   LISTEN 0      10         127.0.0.1:9000       0.0.0.0:*    users:(("Web Content (x)",pid=4242,fd=30))`,
			&host.Listener{Proto: "tcp", Addr: a("127.0.0.1"), Port: 9000, Process: "Web Content (x)", PID: 4242}},
		{"old ipv6 form", `tcp   LISTEN 0      128             :::22              :::*`,
			&host.Listener{Proto: "tcp", Addr: a("::"), Port: 22}},
		{"v4-mapped", `tcp   LISTEN 0      128   [::ffff:127.0.0.1]:8000             *:*`,
			&host.Listener{Proto: "tcp", Addr: a("127.0.0.1"), Port: 8000}},
		{"udp multicast", `udp   UNCONN 0      0        224.0.0.251:5353       0.0.0.0:*`,
			&host.Listener{Proto: "udp", Addr: a("224.0.0.251"), Port: 5353}},
		{"header", "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess", nil},
		{"header old", "State      Recv-Q Send-Q Local Address:Port Peer Address:Port", nil},
		{"tcp not listening", `tcp   ESTAB  0      0       192.0.2.10:22      198.51.100.7:51000`, nil},
		{"connected udp", `udp   ESTAB  0      0       192.0.2.10:41000    203.0.113.5:53`, nil},
		{"empty", "", nil},
		{"short", "tcp LISTEN 0", nil},
		{"bad port", `tcp   LISTEN 0      128          0.0.0.0:http        0.0.0.0:*`, nil},
		{"port too big", `tcp   LISTEN 0      128          0.0.0.0:70000       0.0.0.0:*`, nil},
		{"raw socket", `raw   UNCONN 0      0                  *:58                 *:*`, nil},
		{"unterminated bracket", `tcp   LISTEN 0      128             [::1:22           [::]:*`, nil},
		{"users without pid", `tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd"))`,
			&host.Listener{Proto: "tcp", Addr: a("0.0.0.0"), Port: 22}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseSSLine(tt.in)
			if tt.want == nil {
				if ok {
					t.Fatalf("want skipped, got %+v", got)
				}
				return
			}
			if !ok {
				t.Fatal("row was skipped")
			}
			if got != *tt.want {
				t.Errorf("got  %+v\nwant %+v", got, *tt.want)
			}
		})
	}
}

func TestParseSSNetns(t *testing.T) {
	in := "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		"tcp   LISTEN 0      511       0.0.0.0:80      0.0.0.0:*\n\n" +
		"udp   UNCONN 0      0         0.0.0.0:53      0.0.0.0:*\n"
	ls := parseSS(in, "5b0f3c9e8d7a")
	if len(ls) != 2 {
		t.Fatalf("got %d listeners", len(ls))
	}
	for _, l := range ls {
		if l.Netns != "5b0f3c9e8d7a" {
			t.Errorf("netns not set: %+v", l)
		}
	}
}

func FuzzParseSS(f *testing.F) {
	f.Add(`tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=812,fd=3))`)
	f.Add(`udp   UNCONN 0      0      [fe80::1]%eth0:546            [::]:*`)
	f.Add(`tcp LISTEN 0 1 *:8080 *:* users:(("a b",pid=1,fd=2),("c",pid=3,fd=4))`)
	f.Fuzz(func(t *testing.T, in string) {
		for _, l := range parseSS(in, "x") {
			if l.Proto != "tcp" && l.Proto != "udp" {
				t.Fatalf("bad proto %q", l.Proto)
			}
			if !l.Addr.IsValid() || l.Addr.Zone() != "" {
				t.Fatalf("bad address %v", l.Addr)
			}
		}
	})
}
