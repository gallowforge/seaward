package snapshot

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
)

// dockerInspectTemplate prints, per container, exactly: id, pid, network mode, then
// " name=ipv4|ipv6" for each network. It names these fields only, because a container's full
// inspect output holds its environment variables, and those often hold secrets.
const dockerInspectTemplate = `{{.Id}} {{.State.Pid}} {{.HostConfig.NetworkMode}}` +
	`{{range $k, $v := .NetworkSettings.Networks}} {{$k}}={{$v.IPAddress}}|{{$v.GlobalIPv6Address}}{{end}}`

// dockerPSTemplate prints, per container, one JSON object with the six fields read below and
// nothing else. Docker's whole listing line also carries the container's command with its
// arguments, its labels and its mounts, and a password given on a command line would ride along.
const dockerPSTemplate = `{"ID":{{json .ID}},"Names":{{json .Names}},"Image":{{json .Image}},` +
	`"Ports":{{json .Ports}},"Networks":{{json .Networks}},"State":{{json .State}}}`

// dockerPS is one line of that listing, keys as Docker names them.
type dockerPS struct {
	ID       string `json:"ID"`
	Names    string `json:"Names"`
	Image    string `json:"Image"`
	Ports    string `json:"Ports"`
	Networks string `json:"Networks"`
	State    string `json:"State"`
}

// parseDockerPS reads one JSON object per line. Lines that are not JSON are skipped and counted.
func parseDockerPS(text string) (cs []host.Container, bad int) {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var p dockerPS
		if err := json.Unmarshal([]byte(ln), &p); err != nil || p.ID == "" {
			bad++
			continue
		}
		// "docker ps" lists running containers only, but a hand-made snapshot might not.
		if p.State != "" && p.State != "running" {
			continue
		}
		name, _, _ := strings.Cut(p.Names, ",")
		c := host.Container{ID: p.ID, Name: name, Image: p.Image, Ports: parseDockerPorts(p.Ports)}
		for _, n := range strings.Split(p.Networks, ",") {
			if n = strings.TrimSpace(n); n != "" {
				c.Networks = append(c.Networks, host.ContainerNet{Network: n})
			}
		}
		cs = append(cs, c)
	}
	return cs, bad
}

// parseDockerPorts reads the Ports column: "0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 9000/tcp,
// 0.0.0.0:6000-6002->6000-6002/udp". An entry without "->" is exposed but not published, so it
// is not reachable from outside and is left out. A range becomes one entry per port.
func parseDockerPorts(s string) []host.Published {
	var out []host.Published
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		hostPart, ctrPart, ok := strings.Cut(e, "->")
		if !ok {
			continue
		}
		cports, proto, ok := strings.Cut(ctrPart, "/")
		if !ok || (proto != "tcp" && proto != "udp") {
			continue
		}
		i := strings.LastIndexByte(hostPart, ':')
		if i < 0 {
			continue
		}
		addrStr := strings.TrimSuffix(strings.TrimPrefix(hostPart[:i], "["), "]")
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}
		hlo, hhi, ok1 := parseDashRange(hostPart[i+1:])
		clo, chi, ok2 := parseDashRange(cports)
		if !ok1 || !ok2 {
			continue
		}
		for hp := hlo; ; hp++ {
			cp := clo
			// Equal-length ranges map port for port; otherwise every host port goes to the
			// one container port.
			if chi-clo == hhi-hlo {
				cp = clo + (hp - hlo)
			}
			out = append(out, host.Published{Proto: proto, HostAddr: addr.WithZone(""), HostPort: hp, ContainerPort: cp})
			if hp == hhi {
				break
			}
		}
	}
	return out
}

func parseDashRange(s string) (lo, hi uint16, ok bool) {
	a, b, isRange := strings.Cut(s, "-")
	l, err := strconv.ParseUint(a, 10, 16)
	if err != nil {
		return 0, 0, false
	}
	h := l
	if isRange {
		if h, err = strconv.ParseUint(b, 10, 16); err != nil || h < l {
			return 0, 0, false
		}
	}
	return uint16(l), uint16(h), true
}

// dockerNet is one line of the docker-net section.
type dockerNet struct {
	ID       string
	PID      int
	Mode     string
	Networks []host.ContainerNet
}

// parseDockerNet reads "<id> <pid> <network mode> <name>=<ipv4>|<ipv6> ..." lines.
func parseDockerNet(text string) []dockerNet {
	var out []dockerNet
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		d := dockerNet{ID: f[0], PID: pid, Mode: f[2]}
		for _, n := range f[3:] {
			i := strings.LastIndexByte(n, '=')
			if i <= 0 {
				continue
			}
			cn := host.ContainerNet{Network: n[:i]}
			v4, v6, _ := strings.Cut(n[i+1:], "|")
			if a, err := netip.ParseAddr(v4); err == nil && a.Is4() {
				cn.Addr = a
			}
			if a, err := netip.ParseAddr(v6); err == nil && a.Is6() {
				cn.Addr6 = a.WithZone("")
			}
			d.Networks = append(d.Networks, cn)
		}
		out = append(out, d)
	}
	return out
}

// sameContainer matches a full ID against one that may be shortened.
func sameContainer(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return strings.HasPrefix(b, a) && len(a) >= 12
}

// buildDocker joins the ps, net and version sections.
func buildDocker(version, ps, net string, hasNet bool) (*host.Docker, []string) {
	var notes []string
	d := &host.Docker{Version: strings.TrimSpace(version)}
	cs, bad := parseDockerPS(ps)
	if bad > 0 {
		notes = append(notes, strconv.Itoa(bad)+" line(s) of the Docker container list could not be read.")
	}
	nets := parseDockerNet(net)
	for i := range cs {
		c := &cs[i]
		found := false
		for _, n := range nets {
			if !sameContainer(n.ID, c.ID) {
				continue
			}
			found = true
			if len(n.ID) > len(c.ID) {
				c.ID = n.ID
			}
			if n.Mode == "host" {
				c.HostNetwork = true
				c.Networks = nil
			} else if len(n.Networks) > 0 {
				c.Networks = n.Networks
			}
			if strings.HasPrefix(n.Mode, "container:") {
				notes = append(notes, "Container "+c.Name+" shares the network of another container ("+
					strings.TrimPrefix(n.Mode, "container:")+"); its addresses are that container's.")
			}
			break
		}
		if !found {
			// Without the inspect line, "host" in the ps network column still tells.
			if len(c.Networks) == 1 && c.Networks[0].Network == "host" {
				c.HostNetwork, c.Networks = true, nil
			} else if hasNet {
				notes = append(notes, "The network addresses of container "+c.Name+" were not in the snapshot.")
			}
		}
	}
	d.Containers = cs
	return d, notes
}
