// Command seaward shows which ports on a Linux machine can really be reached from outside, and
// the rule that decides each one. It only reads: it never adds, changes or removes a rule.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

// Exit statuses.
const (
	exitOK         = 0
	exitError      = 1
	exitUsage      = 2
	exitExposed    = 3 // --check: a port is reachable that the firewall tool does not allow
	exitIncomplete = 4 // --check: nothing exposed was found, but part of the answer is missing
)

const usage = `seaward shows which ports on this machine can really be reached from outside,
and the rule that decides each one. It only reads. It never changes a rule.

  seaward scan                 the report for this machine
  seaward why PORT             follow a packet to one port, rule by rule
  seaward snapshot -o FILE     save what a scan reads, to look at elsewhere
  seaward snapshot --script    the collector as a shell script, for a
                               machine you will not install seaward on
  seaward version

Options
  -f, --file FILE    read a snapshot, not this machine ("-" is standard input)
      --from ADDR    with why: follow a packet from this address
      --json         with scan or why: the answer as JSON
      --check        with scan: exit with status 3 when a port is exposed,
                     4 when none is but something is undecided, was not
                     read or was not asked
      --no-color     plain text, also set by NO_COLOR

Reading firewall rules needs root: sudo seaward scan
`

type options struct {
	pos     []string
	file    string
	out     string
	from    string
	json    bool
	check   bool
	script  bool
	help    bool
	color   bool
	noColor bool
}

// parse reads the arguments. Options may stand before or after the command and its port.
func parse(args []string) (options, error) {
	var o options
	value := func(i *int, name, inline string, has bool) (string, error) {
		if has {
			return inline, nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-" || !strings.HasPrefix(a, "-") {
			o.pos = append(o.pos, a)
			continue
		}
		if a == "--" {
			o.pos = append(o.pos, args[i+1:]...)
			break
		}
		name, inline, has := strings.Cut(a, "=")
		var err error
		switch name {
		case "-f", "--file":
			o.file, err = value(&i, name, inline, has)
		case "-o", "--output":
			o.out, err = value(&i, name, inline, has)
		case "--from":
			o.from, err = value(&i, name, inline, has)
		case "--json":
			o.json = true
		case "--check":
			o.check = true
		case "--script":
			o.script = true
		case "--color":
			o.color = true
		case "--no-color":
			o.noColor = true
		case "-h", "--help":
			o.help = true
		case "-V", "--version":
			o.pos = append([]string{"version"}, o.pos...)
		default:
			return o, fmt.Errorf("unknown option %s", name)
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parse(args)
	if err != nil {
		fmt.Fprintf(stderr, "seaward: %v\nRun \"seaward help\" for the commands.\n", err)
		return exitUsage
	}
	if o.help || len(o.pos) == 0 || o.pos[0] == "help" {
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	cmd, rest := o.pos[0], o.pos[1:]
	if err := misplaced(o, cmd); err != nil {
		fmt.Fprintf(stderr, "seaward: %v\nRun \"seaward help\" for the commands.\n", err)
		return exitUsage
	}
	text := scan.TextOptions{Color: useColor(o, stdout), Width: termWidth(stdout)}
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "seaward", snapshot.Version)
		return exitOK
	case "snapshot":
		err = doSnapshot(ctx, o, stdout, stderr)
	case "scan":
		if len(rest) > 0 {
			fmt.Fprintf(stderr, "seaward: scan takes no argument, got %q\n", rest[0])
			return exitUsage
		}
		return doScan(ctx, o, text, stdin, stdout, stderr)
	case "why":
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "seaward: why needs a port: seaward why 5432, or seaward why 53/udp")
			return exitUsage
		}
		err = doWhy(ctx, o, rest, text, stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "seaward: unknown command %q\nRun \"seaward help\" for the commands.\n", cmd)
		return exitUsage
	}
	var bad usageError
	if errors.As(err, &bad) {
		fmt.Fprintln(stderr, "seaward:", err)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, "seaward:", err)
		return exitError
	}
	return exitOK
}

// misplaced names an option given to a command that has no use for it. Such an option would be
// passed over in silence, and a script that asked for --check or --json would never learn it.
func misplaced(o options, cmd string) error {
	for _, c := range []struct {
		set        bool
		name, with string
	}{
		{o.file != "", "--file", "scan why"},
		{o.from != "", "--from", "why"},
		{o.json, "--json", "scan why"},
		{o.check, "--check", "scan"},
		{o.out != "", "--output", "snapshot"},
		{o.script, "--script", "snapshot"},
	} {
		with := strings.Fields(c.with)
		if !c.set || !slices.Contains([]string{"scan", "why", "snapshot"}, cmd) || slices.Contains(with, cmd) {
			continue
		}
		return fmt.Errorf("%s goes with %s, not with %s", c.name, strings.Join(with, " and "), cmd)
	}
	return nil
}

// printJSON writes a value the way every --json answer is written: indented, one document.
func printJSON(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

type usageError string

func (e usageError) Error() string { return string(e) }

// load reads the rules and the machine: from a snapshot when one is named, else from this machine.
func load(ctx context.Context, o options, stdin io.Reader, stderr io.Writer) (*rules.Ruleset, *host.Host, error) {
	var b *snapshot.Bundle
	switch {
	case o.file == "-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, nil, err
		}
		if b, err = snapshot.Parse(string(data)); err != nil {
			return nil, nil, err
		}
	case o.file != "":
		data, err := os.ReadFile(o.file)
		if err != nil {
			return nil, nil, err
		}
		if b, err = snapshot.Parse(string(data)); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", o.file, err)
		}
	case runtime.GOOS != "linux":
		return nil, nil, errors.New("only a Linux machine can be read directly. Take a snapshot there " +
			"(sudo seaward snapshot -o server.snapshot) and read it here: seaward scan -f server.snapshot")
	default:
		if os.Geteuid() != 0 {
			fmt.Fprintln(stderr, "seaward: not running as root, so the firewall rules may be out of reach. For the full answer: sudo seaward scan")
		}
		b = snapshot.Collect(ctx)
		if err := ctx.Err(); err != nil {
			return nil, nil, errors.New("stopped")
		}
	}
	return snapshot.Build(b)
}

func doScan(ctx context.Context, o options, text scan.TextOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	rs, h, err := load(ctx, o, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "seaward:", err)
		return exitError
	}
	rep := scan.Run(rs, h)
	if o.json {
		if err := printJSON(stdout, rep); err != nil {
			fmt.Fprintln(stderr, "seaward:", err)
			return exitError
		}
	} else {
		text.Hint = "seaward why PORT" + fileArg(o)
		fmt.Fprint(stdout, scan.Text(rep, text))
	}
	if o.check {
		switch {
		case rep.Counts.Exposed > 0:
			return exitExposed
		case len(rep.Unread) > 0 || rep.Counts.Undecided > 0 || len(rep.Partial) > 0:
			return exitIncomplete
		}
	}
	return exitOK
}

// fileArg is the " -f FILE" a suggested command needs to read the same snapshot again, written so
// that a shell takes the name as one word. Nothing when the machine itself or standard input was read.
func fileArg(o options) string {
	if o.file == "" || o.file == "-" {
		return ""
	}
	plain := func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_./:@%+,=-", r)
	}
	for i, r := range o.file {
		if !plain(r) || (i == 0 && r == '-') {
			return " -f '" + strings.ReplaceAll(o.file, "'", `'\''`) + "'"
		}
	}
	return " -f " + o.file
}

// protocols are the ones that have ports: the ones a packet to a port can be followed in.
var protocols = []string{"tcp", "udp", "sctp", "dccp", "udplite"}

// portArg reads what why was asked about. There is one way to write it: PORT, or PORT/PROTO
// with a port from 1 to 65535 and one of the protocols above. Anything else is refused, never
// guessed at: "22/tcp/udp" is not a question about udp. The words are what followed "why".
func portArg(words ...string) (proto string, port uint16, err error) {
	const how = " Write it as 5432, or 53/udp."
	said := strings.Join(words, " ")
	fail := func(format string, a ...any) (string, uint16, error) {
		return "", 0, usageError(fmt.Sprintf(format, a...))
	}
	// A protocol may be written in capitals. Only the letters A to Z are folded: strings.ToLower
	// would also turn a dotted capital I into an i, and "udplİte" is not a protocol.
	lower := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}, s)
	}
	// Sorted into numbers, protocols and the rest, what was given says what is wrong with it.
	var nums, protos, rest []string
	for _, part := range strings.Split(strings.Join(words, "/"), "/") {
		switch {
		case part != "" && strings.Trim(part, "0123456789") == "":
			nums = append(nums, part)
		case slices.Contains(protocols, lower(part)):
			protos = append(protos, lower(part))
		default:
			rest = append(rest, part)
		}
	}
	if len(nums) == 1 {
		n, e := strconv.ParseUint(nums[0], 10, 16)
		if e != nil || n == 0 {
			return fail("%q is not a port: ports run from 1 to 65535.", nums[0])
		}
		port = uint16(n)
	}
	switch {
	case len(rest) == 1 && rest[0] != "" && len(nums) == 1 && said == nums[0]+"/"+rest[0]:
		return fail("%q is not a protocol with ports. Write tcp, udp, sctp, dccp or udplite.", rest[0])
	case len(rest) > 0:
		return fail("%q is not a port."+how, said)
	case len(nums) == 0:
		return fail("%q names no port."+how, said)
	case len(nums) > 1:
		return fail("%q names more than one port. Ask about one at a time.", said)
	case len(protos) > 1:
		return fail("%q names more than one protocol. Ask about one at a time.", said)
	}
	// One port and at most one protocol. Given the other way round or as two words the meaning is
	// plain, and so is the one way to write it.
	want := nums[0]
	if len(protos) == 1 {
		proto = protos[0]
		want += "/" + proto
	}
	if lower(said) != want {
		return fail("%q is not how a port is written. Write it as %s.", said, want)
	}
	return proto, port, nil
}

// whyJSON is what "why PORT --json" prints: the ports of the report that match, each as scan
// --json gives it, with every packet sent at it and every step of the way. A port nothing
// listens on and no rule sends anywhere gives an empty list. Partial is set when the scan did
// not ask every sender: the answer then rules nobody out.
type whyJSON struct {
	Host    string      `json:"host"`
	Ports   []scan.Port `json:"ports"`
	Partial []string    `json:"partial,omitempty"`
}

// traceJSON is what "why PORT --from ADDR --json" prints: the packets of that one sender, one for
// each outside address of the machine it would arrive at.
type traceJSON struct {
	Host  string      `json:"host"`
	Proto string      `json:"proto"`
	Port  uint16      `json:"port"`
	From  string      `json:"from"`
	Cells []scan.Cell `json:"cells"`
}

func doWhy(ctx context.Context, o options, words []string, text scan.TextOptions, stdin io.Reader, stdout, stderr io.Writer) error {
	proto, port, err := portArg(words...)
	if err != nil {
		return err
	}
	var from netip.Addr
	if o.from != "" {
		if from, err = netip.ParseAddr(o.from); err != nil {
			return usageError(fmt.Sprintf("--from wants one address, such as 198.51.100.7; got %q", o.from))
		}
	}
	rs, h, err := load(ctx, o, stdin, stderr)
	if err != nil {
		return err
	}
	if from.IsValid() {
		if proto == "" {
			proto = "tcp"
		}
		cells := scan.Trace(rs, h, proto, port, from)
		if o.json {
			return printJSON(stdout, traceJSON{Host: h.Name, Proto: proto, Port: port, From: from.String(), Cells: append([]scan.Cell{}, cells...)})
		}
		if len(cells) == 0 {
			fmt.Fprintf(stdout, "A packet from %s has no outside address of this machine to arrive at.\n", from)
			return nil
		}
		fmt.Fprint(stdout, scan.TraceText(proto, port, cells, text))
		return nil
	}
	rep := scan.Run(rs, h)
	ports := []scan.Port{}
	for _, p := range rep.Ports {
		if p.Port == port && (proto == "" || p.Proto == proto) {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		// A port inside a long range that the scan asked about in part has no row of its own, and
		// neither has one the scan did not come to before its ceiling of ports. It is asked about
		// now: "the scan followed no packet there" would be false of it.
		ports = append(ports, scan.One(rs, h, proto, port)...)
	}
	if o.json {
		return printJSON(stdout, whyJSON{Host: rep.Host, Ports: ports, Partial: scan.SendersNotAsked(rep)})
	}
	for i := range ports {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprint(stdout, scan.WhyText(&ports[i], text))
	}
	if len(ports) == 0 {
		what, arg := "port "+strconv.Itoa(int(port)), strconv.Itoa(int(port))
		if proto != "" {
			what, arg = proto+" "+what, arg+"/"+proto
		}
		switch proto {
		case "", "tcp", "udp":
			fmt.Fprintf(stdout, "Nothing listens on %s and no rule sends it somewhere else, so the scan followed no packet there.\n"+
				"To follow a packet anyway, name a sender: seaward why %s --from 198.51.100.7%s\n", what, arg, fileArg(o))
		default:
			// A scan asks about tcp and udp ports. What the rules do with another protocol is
			// not known until a packet of it is followed.
			fmt.Fprintf(stdout, "A scan asks about tcp and udp ports only, so it followed no packet to %s.\n"+
				"To follow one, name a sender: seaward why %s --from 198.51.100.7%s\n", what, arg, fileArg(o))
		}
	}
	return nil
}

func doSnapshot(ctx context.Context, o options, stdout, stderr io.Writer) error {
	if o.script {
		fmt.Fprint(stdout, snapshot.Script())
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("a snapshot is taken on the Linux machine itself: sudo seaward snapshot -o server.snapshot")
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "seaward: not running as root, so the firewall rules may be out of reach. For the full answer: sudo seaward snapshot")
	}
	b := snapshot.Collect(ctx)
	if ctx.Err() != nil {
		return errors.New("stopped")
	}
	if o.out == "" || o.out == "-" {
		fmt.Fprint(stdout, b.String())
		return nil
	}
	// Root was for reading the rules. The file is the caller's, so it is written as the caller:
	// under sudo, as whoever ran sudo. Then the scan that follows needs no root to open it, and
	// -o can write nothing that person could not have written themselves.
	stepped := false
	if uid, gid, ok := sudoUser(os.Geteuid(), os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")); ok {
		if err := stepDown(uid, gid); err != nil {
			return fmt.Errorf("could not give up root to write %s as the user who ran sudo (%w), so nothing was written. "+
				"To write it yourself: sudo seaward snapshot > %s", o.out, err, o.out)
		}
		stepped = true
	}
	if err := writePrivate(o.out, []byte(b.String())); err != nil {
		if stepped && errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%w. The file is written as the user who ran sudo, not as root", err)
		}
		return err
	}
	fmt.Fprintf(stderr, "seaward: wrote %s. Read it anywhere with: seaward scan -f %s\n", o.out, o.out)
	return nil
}

// writePrivate writes a snapshot readable by its owner alone: rules, addresses and program names
// are theirs to share. It writes a new file beside the target and moves it into place, so a link
// planted under that name is never followed, an older file's looser mode does not survive, and a
// snapshot is never left half written.
func writePrivate(path string, data []byte) error {
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file, so it is left alone. To print the snapshot instead: seaward snapshot > FILE", path)
	}
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+name+".*") // a new file, mode 600
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// sudoUser is who ran sudo, when this process is root because of sudo.
func sudoUser(euid int, sudoUID, sudoGID string) (uid, gid int, ok bool) {
	if euid != 0 {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(sudoUID)
	gid, err2 := strconv.Atoi(sudoGID)
	if err1 != nil || err2 != nil || uid <= 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// useColor: colour is for a person at a terminal, never for a pipe or a file.
func useColor(o options, stdout io.Writer) bool {
	if o.noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if o.color {
		return true
	}
	_, isTerm := termSize(stdout)
	return isTerm
}

// termWidth is the width to wrap at: the terminal's, kept between 60 and 110 columns.
func termWidth(stdout io.Writer) int {
	w, isTerm := termSize(stdout)
	if !isTerm || w <= 0 {
		return 100
	}
	return min(max(w, 60), 110)
}

// termSize reports the width of the terminal behind w, and whether w is a terminal at all.
func termSize(w io.Writer) (int, bool) {
	f, ok := w.(*os.File)
	if !ok {
		return 0, false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return 0, false
	}
	return columns(f), true
}
