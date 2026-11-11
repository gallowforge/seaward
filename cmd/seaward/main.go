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
	"runtime"
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

  seaward scan                      the report for this machine
  seaward why PORT                  follow a packet to one port, rule by rule
  seaward snapshot -o FILE          save what a scan reads, to look at on another machine
  seaward snapshot --script         the collector as a shell script, for a machine without seaward
  seaward version

Options
  -f, --file FILE    read a snapshot instead of this machine ("-" is standard input)
      --from ADDR    with why: follow a packet from this address
      --json         with scan: the report as JSON
      --check        with scan: exit with status 3 when a port is exposed,
                     4 when nothing is exposed but the rules could not all be read
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
		if len(rest) == 0 || len(rest) > 2 {
			fmt.Fprintln(stderr, "seaward: why needs a port: seaward why 5432, or seaward why 53/udp")
			return exitUsage
		}
		err = doWhy(ctx, o, strings.Join(rest, "/"), text, stdin, stdout, stderr)
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
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "seaward:", err)
			return exitError
		}
		fmt.Fprintln(stdout, string(data))
	} else {
		text.Hint = "seaward why PORT"
		if o.file != "" && o.file != "-" {
			text.Hint += " -f " + o.file
		}
		fmt.Fprint(stdout, scan.Text(rep, text))
	}
	if o.check {
		switch {
		case rep.Counts.Exposed > 0:
			return exitExposed
		case len(rep.Unread) > 0 || rep.Counts.Undecided > 0:
			return exitIncomplete
		}
	}
	return exitOK
}

// portArg reads "5432", "5432/tcp", "tcp/5432" and "udp 53".
func portArg(s string) (proto string, port uint16, err error) {
	for _, part := range strings.Split(strings.ToLower(s), "/") {
		if n, e := strconv.ParseUint(part, 10, 16); e == nil && n > 0 {
			port = uint16(n)
			continue
		}
		switch part {
		case "tcp", "udp", "sctp", "dccp", "udplite":
			proto = part
		default:
			return "", 0, usageError(fmt.Sprintf("%q is not a port. Write it as 5432, or 53/udp.", s))
		}
	}
	if port == 0 {
		return "", 0, usageError(fmt.Sprintf("%q names no port. Write it as 5432, or 53/udp.", s))
	}
	return proto, port, nil
}

func doWhy(ctx context.Context, o options, arg string, text scan.TextOptions, stdin io.Reader, stdout, stderr io.Writer) error {
	proto, port, err := portArg(arg)
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
		if len(cells) == 0 {
			fmt.Fprintf(stdout, "A packet from %s has no outside address of this machine to arrive at.\n", from)
			return nil
		}
		fmt.Fprint(stdout, scan.TraceText(proto, port, cells, text))
		return nil
	}
	rep := scan.Run(rs, h)
	shown := 0
	for i := range rep.Ports {
		p := &rep.Ports[i]
		if p.Port != port || (proto != "" && p.Proto != proto) {
			continue
		}
		if shown > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprint(stdout, scan.WhyText(p, text))
		shown++
	}
	if shown == 0 {
		what := "port " + strconv.Itoa(int(port))
		if proto != "" {
			what = proto + " " + what
		}
		fmt.Fprintf(stdout, "Nothing listens on %s and no rule names it, so the scan sent nothing there.\n"+
			"To follow a packet anyway, name a sender: seaward why %d --from 198.51.100.7\n", what, port)
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
	// Rules, addresses and process names are the owner's to share: the file is theirs alone.
	if err := os.WriteFile(o.out, []byte(b.String()), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "seaward: wrote %s. Read it anywhere with: seaward scan -f %s\n", o.out, o.out)
	return nil
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
