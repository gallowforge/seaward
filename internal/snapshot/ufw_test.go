package snapshot

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

// ufwLine lays a rule out exactly as ufw does.
func ufwLine(dst, action, src, attrib, comment string) string {
	if comment != "" {
		comment = " # " + comment
	}
	return fmt.Sprintf("%-26s %-12s%-26s%s%s", dst, action, src, attrib, comment)
}

func TestParseUFWRule(t *testing.T) {
	p := netip.MustParsePrefix
	type R = host.FrontendRule
	tests := []struct {
		name     string
		line     string
		want     []R // Text is filled in from the line
		wantNote bool
	}{
		{"port and protocol", ufwLine("22/tcp", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22}}, false},
		{"port without protocol", ufwLine("22", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", PortLo: 22, PortHi: 22}}, false},
		{"port list", ufwLine("80,443/tcp", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 80, PortHi: 80}, {Action: "allow", Proto: "tcp", PortLo: 443, PortHi: 443}}, false},
		{"range", ufwLine("6000:6007/udp", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "udp", PortLo: 6000, PortHi: 6007}}, false},
		{"list with range", ufwLine("22,8000:8010/tcp", "LIMIT IN", "Anywhere", "", ""),
			[]R{{Action: "limit", Proto: "tcp", PortLo: 22, PortHi: 22}, {Action: "limit", Proto: "tcp", PortLo: 8000, PortHi: 8010}}, false},
		{"everything", ufwLine("Anywhere", "ALLOW IN", "203.0.113.0/24", "", ""),
			[]R{{Action: "allow", From: p("203.0.113.0/24")}}, false},
		{"everything on an interface", ufwLine("Anywhere on eth0", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Iface: "eth0"}}, false},
		{"everything on an interface v6", ufwLine("Anywhere (v6) on wg0", "ALLOW IN", "Anywhere (v6)", "", ""),
			[]R{{Action: "allow", Iface: "wg0", IPv6: true}}, false},
		{"port on an interface", ufwLine("22/tcp on eth0", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, Iface: "eth0"}}, false},
		{"port v6 on an interface", ufwLine("22/tcp (v6) on eth0", "DENY IN", "Anywhere (v6)", "", ""),
			[]R{{Action: "deny", Proto: "tcp", PortLo: 22, PortHi: 22, Iface: "eth0", IPv6: true}}, false},
		{"destination address", ufwLine("203.0.113.10 22/tcp", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, To: p("203.0.113.10/32")}}, false},
		{"destination address only", ufwLine("192.0.2.10", "ALLOW IN", "198.51.100.7", "", ""),
			[]R{{Action: "allow", To: p("192.0.2.10/32"), From: p("198.51.100.7/32")}}, false},
		{"destination address with protocol", ufwLine("192.0.2.10/udp", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "udp", To: p("192.0.2.10/32")}}, false},
		{"destination network with protocol", ufwLine("192.0.2.0/24/tcp", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", To: p("192.0.2.0/24")}}, false},
		{"anywhere with protocol", ufwLine("Anywhere/tcp", "ALLOW IN", "Anywhere/tcp", "", ""),
			[]R{{Action: "allow", Proto: "tcp"}}, false},
		{"ipv6 destination", ufwLine("2001:db8::10 443/tcp", "ALLOW IN", "2001:db8:1::/48", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 443, PortHi: 443, To: p("2001:db8::10/128"), From: p("2001:db8:1::/48"), IPv6: true}}, false},
		{"v6 suffix", ufwLine("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, IPv6: true}}, false},
		{"app profile", ufwLine("22/tcp (OpenSSH)", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22}}, false},
		{"app profile v6", ufwLine("22/tcp (OpenSSH (v6))", "ALLOW IN", "Anywhere (v6)", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, IPv6: true}}, false},
		{"app profile with a space", ufwLine("80,443/tcp (Nginx Full)", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 80, PortHi: 80}, {Action: "allow", Proto: "tcp", PortLo: 443, PortHi: 443}}, false},
		{"app profile on an interface", ufwLine("80/tcp (Apache) on eth0", "ALLOW IN", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 80, PortHi: 80, Iface: "eth0"}}, false},
		{"deny", ufwLine("23/tcp", "DENY IN", "Anywhere", "", ""),
			[]R{{Action: "deny", Proto: "tcp", PortLo: 23, PortHi: 23}}, false},
		{"reject", ufwLine("111", "REJECT IN", "Anywhere", "", ""),
			[]R{{Action: "reject", PortLo: 111, PortHi: 111}}, false},
		{"limit", ufwLine("22/tcp", "LIMIT IN", "Anywhere", "", ""),
			[]R{{Action: "limit", Proto: "tcp", PortLo: 22, PortHi: 22}}, false},
		{"outgoing ignored", ufwLine("53", "ALLOW OUT", "Anywhere", "", ""), nil, false},
		{"routed ignored", ufwLine("Anywhere on docker0", "ALLOW FWD", "Anywhere on eth0", "", ""), nil, false},
		{"source network", ufwLine("5432/tcp", "ALLOW IN", "172.17.0.0/16", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 5432, PortHi: 5432, From: p("172.17.0.0/16")}}, false},
		{"source address", ufwLine("22/tcp", "ALLOW IN", "198.51.100.7", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22, From: p("198.51.100.7/32")}}, false},
		{"source with port", ufwLine("Anywhere", "ALLOW IN", "203.0.113.5 53/udp", "", ""),
			[]R{{Action: "allow", Proto: "udp", From: p("203.0.113.5/32")}}, true},
		{"comment", ufwLine("172.17.0.1 53/udp", "ALLOW IN", "172.16.0.0/12", "", "dns for containers"),
			[]R{{Action: "allow", Proto: "udp", PortLo: 53, PortHi: 53, To: p("172.17.0.1/32"), From: p("172.16.0.0/12")}}, false},
		{"comment with a hash inside", ufwLine("8443/tcp", "ALLOW IN", "Anywhere", "", "admin # second"),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 8443, PortHi: 8443}}, false},
		{"log attribute", ufwLine("22/tcp", "ALLOW IN", "Anywhere", " (log)", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22}}, false},
		{"log-all attribute and comment", ufwLine("22/tcp", "DENY IN", "203.0.113.0/24", " (log-all)", "noisy"),
			[]R{{Action: "deny", Proto: "tcp", PortLo: 22, PortHi: 22, From: p("203.0.113.0/24")}}, false},
		{"long location pushes the columns", ufwLine("2001:db8:aaaa:bbbb:cccc:dddd:eeee:1 8080:8090/tcp", "ALLOW IN", "Anywhere (v6)", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 8080, PortHi: 8090, To: p("2001:db8:aaaa:bbbb:cccc:dddd:eeee:1/128"), IPv6: true}}, false},
		{"no direction (not verbose)", ufwLine("22/tcp", "ALLOW", "Anywhere", "", ""),
			[]R{{Action: "allow", Proto: "tcp", PortLo: 22, PortHi: 22}}, false},
		{"other protocol says nothing about ports", ufwLine("Anywhere/esp", "ALLOW IN", "Anywhere/esp", "", ""), nil, false},
		{"app name only (not verbose)", ufwLine("OpenSSH", "ALLOW", "Anywhere", "", ""), nil, true},
		{"no action", "22/tcp   MAYBE IN   Anywhere", nil, true},
		{"bad port", ufwLine("99999/tcp", "ALLOW IN", "Anywhere", "", ""), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, note := parseUFWRule(tt.line)
			for i := range tt.want {
				tt.want[i].Text = strings.TrimSpace(tt.line)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("line %q\ngot  %+v\nwant %+v", tt.line, got, tt.want)
			}
			if (note != "") != tt.wantNote {
				t.Errorf("note %q", note)
			}
		})
	}
}

func TestParseUFW(t *testing.T) {
	in := "Status: active\nLogging: on (low)\nDefault: reject (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\n" +
		"To                         Action      From\n--                         ------      ----\n" +
		ufwLine("22/tcp", "ALLOW IN", "Anywhere", "", "") + "\n" +
		ufwLine("53", "ALLOW OUT", "Anywhere", "", "") + "\n" +
		ufwLine("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "", "") + "\n\n" +
		ufwLine("Anywhere on docker0", "ALLOW FWD", "Anywhere on eth0", "", "") + "\n"
	f, notes := parseUFW(in)
	if f.Tool != "ufw" || !f.Active || f.DefaultIncoming != "reject" || len(f.Rules) != 2 || len(notes) != 0 {
		t.Fatalf("got %+v, notes %q", f, notes)
	}
	if f.Rules[0].IPv6 || !f.Rules[1].IPv6 {
		t.Errorf("families: %+v", f.Rules)
	}

	f, _ = parseUFW("Status: inactive\n")
	if f.Active || len(f.Rules) != 0 {
		t.Errorf("inactive: %+v", f)
	}
	for in, want := range map[string]string{
		"Default: deny (incoming), allow (outgoing), deny (routed)":      "deny",
		"Default: allow (incoming), allow (outgoing), disabled (routed)": "allow",
	} {
		if f, _ := parseUFW("Status: active\n" + in + "\n"); f.DefaultIncoming != want {
			t.Errorf("%q: got %q", in, f.DefaultIncoming)
		}
	}
}

func FuzzParseUFW(f *testing.F) {
	f.Add("Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n\nTo Action From\n-- ------ ----\n" +
		ufwLine("22/tcp (OpenSSH (v6)) on eth0", "ALLOW IN", "2001:db8::/32 1000:2000/udp", " (log)", "c") + "\n")
	f.Add("To   Action  From\n" + ufwLine("Anywhere/tcp", "LIMIT IN", "Anywhere", "", "") + "\n")
	f.Add("To Action From\n 192.0.2.0/24/tcp ALLOW IN ( (v6) on")
	f.Fuzz(func(t *testing.T, in string) {
		fr, _ := parseUFW(in)
		for _, r := range fr.Rules {
			if r.PortLo > r.PortHi {
				t.Fatalf("bad range %+v", r)
			}
			switch r.Action {
			case "allow", "deny", "reject", "limit":
			default:
				t.Fatalf("bad action %+v", r)
			}
		}
	})
}
