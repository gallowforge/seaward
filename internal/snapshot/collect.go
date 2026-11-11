package snapshot

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Version is the Seaward version written into each snapshot. The build sets it.
var Version = "dev"

// commands is every command the collector can run, and nothing else ever runs. Each is a fixed
// argument list with no shell; the only words filled in at run time are the placeholders below,
// which take values the earlier commands printed:
//
//	<ids>     container IDs from docker ps (one argument each)
//	<pid>     a container's process ID from docker inspect
//	<service> a firewalld service name from the zone list
var commands = []command{
	{"iptables-version", []string{"iptables", "-V"}},
	{"iptables-save", []string{"iptables-save"}},
	{"ip6tables-save", []string{"ip6tables-save"}},
	{"iptables-legacy-save", []string{"iptables-legacy-save"}},
	{"ip6tables-legacy-save", []string{"ip6tables-legacy-save"}},
	{"nft-json", []string{"nft", "-j", "list", "ruleset"}},
	{"ipset-save", []string{"ipset", "save"}},
	{"ss", []string{"ss", "-Htulpn"}},
	{"ip-addr", []string{"ip", "-j", "-d", "addr", "show"}},
	{"ip-route-4", []string{"ip", "-j", "-4", "route", "show", "table", "main"}},
	{"ip-route-6", []string{"ip", "-j", "-6", "route", "show", "table", "main"}},
	{"sysctl", []string{"sysctl", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}},
	{"sysctl", []string{"sysctl", "-a", "-r", `net\.ipv4\.conf\..*\.route_localnet`}},
	{"docker-version", []string{"docker", "version", "--format", "{{.Server.Version}}"}},
	{"docker-ps", []string{"docker", "ps", "--no-trunc", "--format", dockerPSTemplate}},
	{"docker-net", []string{"docker", "inspect", "--format", dockerInspectTemplate, "<ids>"}},
	{"docker-ss", []string{"nsenter", "-t", "<pid>", "-n", "ss", "-Htulpn"}},
	{"ufw-status", []string{"ufw", "status", "verbose"}},
	{"firewalld-state", []string{"firewall-cmd", "--state"}},
	{"firewalld-active", []string{"firewall-cmd", "--get-active-zones"}},
	{"firewalld-zones", []string{"firewall-cmd", "--list-all-zones"}},
	{"firewalld-service", []string{"firewall-cmd", "--info-service=<service>"}},
}

// commandTimeout bounds each command, so one hung tool cannot stall the snapshot.
var commandTimeout = 5 * time.Second

type command struct {
	section string
	argv    []string
}

// argv returns the command for a section with its placeholders filled in. It is the only way
// the collector builds a command line.
func argvFor(section string, nth int, fill map[string][]string) []string {
	for _, c := range commands {
		if c.section != section {
			continue
		}
		if nth > 0 {
			nth--
			continue
		}
		var out []string
		for _, a := range c.argv {
			switch {
			case a == "<ids>":
				out = append(out, fill["ids"]...)
			case a == "<pid>":
				out = append(out, fill["pid"]...)
			case strings.Contains(a, "<service>"):
				out = append(out, strings.ReplaceAll(a, "<service>", first(fill["service"])))
			default:
				out = append(out, a)
			}
		}
		return out
	}
	panic("snapshot: no command for section " + section)
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// runResult is what one command did.
type runResult struct {
	stdout  string
	errLine string // "" when it worked
	missing bool   // the program is not installed
	code    int    // exit code; -1 when it did not finish
}

// runner runs one argument list; tests replace it.
type runner func(ctx context.Context, argv []string) runResult

// sbinDirs are searched as well as PATH: a non-root user's PATH often leaves them out.
var sbinDirs = []string{"/usr/sbin", "/sbin", "/usr/local/sbin"}

func lookPath(name string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, d := range sbinDirs {
		p := d + "/" + name
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

func execRun(ctx context.Context, argv []string) runResult {
	path, ok := lookPath(argv[0])
	if !ok {
		return runResult{missing: true}
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	cmd.Env = append(localEnv(), "LC_ALL=C")
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := runResult{stdout: strings.TrimRight(out.String(), "\n")}
	if err == nil {
		return r
	}
	r.code = -1
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		r.code = ee.ExitCode()
	}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		r.errLine = "timed out after " + commandTimeout.String()
	default:
		r.errLine = firstLine(errb.String())
		if r.errLine == "" {
			r.errLine = err.Error()
		}
	}
	return r
}

// localEnv is the environment without the variables that point docker at another machine: a
// snapshot must describe one machine, not this one's rules beside another one's containers.
func localEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "DOCKER_HOST" || k == "DOCKER_CONTEXT" || k == "DOCKER_CONFIG" {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			return ln
		}
	}
	return ""
}

func collect(ctx context.Context) *Bundle {
	name, _ := os.Hostname()
	return collectWith(ctx, execRun, name, os.Geteuid() == 0, func(n string) bool { _, ok := lookPath(n); return ok })
}

// collector holds one run's state.
type collector struct {
	ctx  context.Context
	run  runner
	b    *Bundle
	errs []string
}

// do runs the nth command of a section and returns its output. A missing program leaves no
// trace; a failure leaves an errors line. Output that came with a failure is kept only when
// keepOnFail says it is useful.
func (c *collector) do(section, arg string, nth int, fill map[string][]string, keepOnFail func(runResult) bool) (string, bool) {
	r := c.run(c.ctx, argvFor(section, nth, fill))
	if r.missing {
		return "", false
	}
	label := section
	if arg != "" {
		label += " " + arg
	}
	if r.errLine != "" {
		if keepOnFail != nil && keepOnFail(r) {
			return r.stdout, true
		}
		c.errs = append(c.errs, label+": "+strings.ReplaceAll(r.errLine, "\n", " "))
		return "", false
	}
	return r.stdout, true
}

func (c *collector) section(section, arg string, fill map[string][]string) (string, bool) {
	out, ok := c.do(section, arg, 0, fill, nil)
	if ok {
		c.b.Add(section, arg, out)
	}
	return out, ok
}

func collectWith(ctx context.Context, run runner, hostname string, root bool, has func(string) bool) *Bundle {
	c := &collector{ctx: ctx, run: run, b: &Bundle{}}
	rootWord := "no"
	if root {
		rootWord = "yes"
	}
	c.b.Add("meta", "", "host "+hostname+"\nseaward "+Version+"\ncollector cli\nroot "+rootWord)

	// Packet rules.
	ver, _ := c.section("iptables-version", "", nil)
	c.section("iptables-save", "", nil)
	c.section("ip6tables-save", "", nil)
	// The legacy tables are a second, separate set of kernel tables; they matter only when the
	// default tool talks to nf_tables, and only when something actually put rules there.
	if !strings.Contains(ver, "(legacy)") {
		for _, s := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
			// A listing that worked and holds no table is left out. One that failed is noted like
			// any other: rules may sit in tables nobody could list, and the report must say so.
			if out, ok := c.do(s, "", 0, nil, nil); ok && hasSaveTables(out) {
				c.b.Add(s, "", out)
			}
		}
	}
	c.section("nft-json", "", nil)
	c.section("ipset-save", "", nil)

	// The machine.
	c.section("ss", "", nil)
	// The interfaces are kept without their hardware addresses, which nothing reads: see
	// hardwareMasks.
	if out, ok := c.do("ip-addr", "", 0, nil, nil); ok {
		c.b.Add("ip-addr", "", maskHardware(out))
	}
	c.section("ip-route-4", "", nil)
	c.section("ip-route-6", "", nil)
	var sys []string
	for nth := 0; nth < 2; nth++ {
		// sysctl exits non-zero when one key is missing (no IPv6) but still prints the rest.
		if out, ok := c.do("sysctl", "", nth, nil, func(r runResult) bool { return r.stdout != "" }); ok && out != "" {
			sys = append(sys, out)
		}
	}
	if len(sys) > 0 {
		c.b.Add("sysctl", "", strings.Join(sys, "\n"))
	}

	// Docker.
	c.section("docker-version", "", nil)
	if ps, ok := c.section("docker-ps", "", nil); ok {
		cs, _ := parseDockerPS(ps)
		var ids []string
		for _, ct := range cs {
			// IDs are hex; anything else could be read as an option, so it is not passed on.
			if isHex(ct.ID) {
				ids = append(ids, ct.ID)
			}
		}
		if len(ids) > 0 {
			// A container that stopped since docker ps makes inspect fail, but the lines for
			// the others are still good.
			net, ok := c.do("docker-net", "", 0, map[string][]string{"ids": ids}, func(r runResult) bool { return r.stdout != "" })
			if ok {
				c.b.Add("docker-net", "", net)
			}
			if ok && root && has("nsenter") {
				for _, n := range parseDockerNet(net) {
					// A host-network container's listeners are already in the host's ss.
					if n.PID <= 0 || n.Mode == "host" || !isHex(n.ID) {
						continue
					}
					c.section("docker-ss", n.ID, map[string][]string{"pid": {strconv.Itoa(n.PID)}})
				}
			}
		}
	}

	// Firewall managers.
	c.section("ufw-status", "", nil)
	// "firewall-cmd --state" exits non-zero and prints "not running" when firewalld is stopped;
	// that is an answer, not a failure.
	// Some versions print "not running" on stderr.
	state, ok := c.do("firewalld-state", "", 0, nil, func(r runResult) bool {
		return strings.TrimSpace(r.stdout) != "" || r.errLine == "not running"
	})
	if ok && state == "" {
		state = "not running"
	}
	if ok {
		c.b.Add("firewalld-state", "", state)
		if strings.TrimSpace(state) == "running" {
			c.section("firewalld-active", "", nil)
			if zones, ok := c.section("firewalld-zones", "", nil); ok {
				queue := firewalldServiceNames(zones)
				seen := map[string]bool{}
				for len(queue) > 0 && len(seen) < 128 {
					s := queue[0]
					queue = queue[1:]
					if seen[s] || !safeName(s) {
						continue
					}
					seen[s] = true
					if out, ok := c.section("firewalld-service", s, map[string][]string{"service": {s}}); ok {
						queue = append(queue, parseFWService(out).includes...)
					}
				}
			}
		}
	}

	if len(c.errs) > 0 {
		c.b.Add("errors", "", strings.Join(c.errs, "\n"))
	}
	return c.b
}

// hasSaveTables reports whether iptables-save output holds at least one table.
func hasSaveTables(s string) bool {
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(ln, "*") {
			return true
		}
	}
	return false
}

// safeName keeps a service name that came from command output from turning into an option.
func safeName(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.+", r)) {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
