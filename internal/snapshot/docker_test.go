package snapshot

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

func TestParseDockerPorts(t *testing.T) {
	a := netip.MustParseAddr
	pub := func(proto, addr string, hp, cp uint16) host.Published {
		return host.Published{Proto: proto, HostAddr: a(addr), HostPort: hp, ContainerPort: cp}
	}
	tests := []struct {
		name string
		in   string
		want []host.Published
	}{
		{"both families", "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp",
			[]host.Published{pub("tcp", "0.0.0.0", 8080, 80), pub("tcp", "::", 8080, 80)}},
		{"older ipv6 form", "0.0.0.0:8080->80/tcp, :::8080->80/tcp",
			[]host.Published{pub("tcp", "0.0.0.0", 8080, 80), pub("tcp", "::", 8080, 80)}},
		{"loopback only", "127.0.0.1:5432->5432/tcp", []host.Published{pub("tcp", "127.0.0.1", 5432, 5432)}},
		{"exposed but not published", "9000/tcp, 9001-9002/udp", nil},
		{"range", "0.0.0.0:6000-6002->6000-6002/udp", []host.Published{
			pub("udp", "0.0.0.0", 6000, 6000), pub("udp", "0.0.0.0", 6001, 6001), pub("udp", "0.0.0.0", 6002, 6002)}},
		{"shifted range", "192.0.2.10:7000-7001->8000-8001/tcp", []host.Published{
			pub("tcp", "192.0.2.10", 7000, 8000), pub("tcp", "192.0.2.10", 7001, 8001)}},
		{"specific ipv6", "[2001:db8::10]:443->8443/tcp", []host.Published{pub("tcp", "2001:db8::10", 443, 8443)}},
		{"the whole example", "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:5432->5432/tcp, 9000/tcp, 0.0.0.0:6000-6002->6000-6002/udp",
			[]host.Published{pub("tcp", "0.0.0.0", 8080, 80), pub("tcp", "::", 8080, 80), pub("tcp", "127.0.0.1", 5432, 5432),
				pub("udp", "0.0.0.0", 6000, 6000), pub("udp", "0.0.0.0", 6001, 6001), pub("udp", "0.0.0.0", 6002, 6002)}},
		{"top of the port space", "0.0.0.0:65534-65535->65534-65535/tcp", []host.Published{
			pub("tcp", "0.0.0.0", 65534, 65534), pub("tcp", "0.0.0.0", 65535, 65535)}},
		{"sctp is not tcp or udp", "0.0.0.0:3868->3868/sctp", nil},
		{"empty", "", nil},
		{"junk", "0.0.0.0:x->80/tcp, ->/tcp, nonsense:80->80/tcp, 0.0.0.0:9-8->9-8/tcp", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDockerPorts(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

const (
	idWeb = "5b0f3c9e8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"
	idDB  = "e2d4c6b8a0f1e3d5c7b9a1f3e5d7c9b1a3f5e7d9c1b3a5f7e9d1c3b5a7f9e1d3"
	idMon = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
)

func TestBuildDocker(t *testing.T) {
	a := netip.MustParseAddr
	ps := `{"ID":"` + idWeb + `","Image":"nginx:1.27","Names":"web","Networks":"app,edge","Ports":"0.0.0.0:8080->80/tcp","State":"running"}
{"ID":"` + idDB + `","Image":"postgres:16","Names":"postgres,web/db","Networks":"app","Ports":"127.0.0.1:5432->5432/tcp","State":"running"}
{"ID":"` + idMon + `","Image":"grafana/grafana","Names":"grafana","Networks":"host","Ports":"","State":"running"}
not json
{"ID":"ffff","Names":"old","State":"exited"}`
	net := idWeb + " 1388 app app=172.18.0.2|2001:db8:18::2 edge=172.19.0.2|\n" +
		idDB + " 1447 app app=172.18.0.3|\n" +
		idMon + " 1500 host\n"
	d, notes := buildDocker("27.3.1\n", ps, net, true)
	want := &host.Docker{Version: "27.3.1", Containers: []host.Container{
		{ID: idWeb, Name: "web", Image: "nginx:1.27",
			Networks: []host.ContainerNet{{Network: "app", Addr: a("172.18.0.2"), Addr6: a("2001:db8:18::2")}, {Network: "edge", Addr: a("172.19.0.2")}},
			Ports:    []host.Published{{Proto: "tcp", HostAddr: a("0.0.0.0"), HostPort: 8080, ContainerPort: 80}}},
		{ID: idDB, Name: "postgres", Image: "postgres:16",
			Networks: []host.ContainerNet{{Network: "app", Addr: a("172.18.0.3")}},
			Ports:    []host.Published{{Proto: "tcp", HostAddr: a("127.0.0.1"), HostPort: 5432, ContainerPort: 5432}}},
		{ID: idMon, Name: "grafana", Image: "grafana/grafana", HostNetwork: true},
	}}
	if !reflect.DeepEqual(d, want) {
		t.Errorf("got  %+v\nwant %+v", d, want)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "1 line") {
		t.Errorf("notes: %q", notes)
	}
}

func TestBuildDockerWithoutInspect(t *testing.T) {
	ps := `{"ID":"` + idWeb + `","Names":"web","Networks":"app","Ports":"","State":"running"}
{"ID":"` + idMon + `","Names":"grafana","Networks":"host","Ports":"","State":"running"}`
	d, notes := buildDocker("", ps, "", false)
	if len(d.Containers) != 2 || d.Containers[0].Networks[0].Network != "app" || !d.Containers[1].HostNetwork {
		t.Errorf("got %+v", d.Containers)
	}
	if len(notes) != 0 {
		t.Errorf("notes: %q", notes)
	}
	// With an inspect section that misses a container, say so.
	_, notes = buildDocker("", ps, idMon+" 1 host\n", true)
	if len(notes) != 1 || !strings.Contains(notes[0], "web") {
		t.Errorf("notes: %q", notes)
	}
}

func TestParseDockerNet(t *testing.T) {
	a := netip.MustParseAddr
	got := parseDockerNet(idWeb + " 1388 bridge bridge=172.17.0.2|\n" +
		idDB + " 0 container:" + idWeb + "\n" +
		"short line\n" +
		idMon + " x host\n" +
		idMon + " 77 app app=| weird noequals =172.0.0.1|\n")
	want := []dockerNet{
		{ID: idWeb, PID: 1388, Mode: "bridge", Networks: []host.ContainerNet{{Network: "bridge", Addr: a("172.17.0.2")}}},
		{ID: idDB, PID: 0, Mode: "container:" + idWeb},
		{ID: idMon, PID: 77, Mode: "app", Networks: []host.ContainerNet{{Network: "app"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestSameContainer(t *testing.T) {
	if !sameContainer(idWeb, idWeb[:12]) || sameContainer(idWeb, idDB) || sameContainer(idWeb, "5b0f") || sameContainer("", "") {
		t.Error("sameContainer")
	}
}
