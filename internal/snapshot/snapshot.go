// Package snapshot is the bundle of command output Seaward works from: reading and writing it,
// collecting it from the machine, and turning it into the firewall model and the machine model.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gallowforge/seaward/internal/host"
	"github.com/gallowforge/seaward/internal/rules"
)

// Section is the output of one command.
type Section struct {
	Name string // "iptables-save"
	Arg  string // "docker-ss <container id>": the container id; else empty
	Body string
}

// Bundle is a snapshot: sections in the order they were written.
type Bundle struct {
	Sections []Section
}

// magic is the first line of every snapshot; the number is the format version.
const magic = "# seaward snapshot 1"

const headerPrefix = "### "

// ErrNotSnapshot is returned by Parse when the text does not start with the snapshot line.
var ErrNotSnapshot = errors.New("snapshot: this is not a Seaward snapshot (the first line should be \"" + magic + "\")")

// Parse reads a bundle from its text form.
//
// A body line that starts with any number of spaces and then "### " was written with one extra
// leading space, so that it cannot be taken for a header; Parse removes that space again.
func Parse(text string) (*Bundle, error) {
	text = strings.TrimPrefix(text, "\uFEFF")
	first, _, _ := strings.Cut(text, "\n")
	// A file that went through a Windows editor has CRLF line ends everywhere. Only then are they
	// normalised, so that a body which itself holds a carriage return survives a round trip.
	if strings.HasSuffix(first, "\r") {
		text = strings.ReplaceAll(text, "\r\n", "\n")
		first = strings.TrimSuffix(first, "\r")
	}
	if strings.TrimRight(first, " \t") != magic {
		if strings.HasPrefix(first, "# seaward snapshot ") {
			return nil, fmt.Errorf("snapshot: unsupported format %q (this version reads %q)", first, magic)
		}
		return nil, ErrNotSnapshot
	}

	b := &Bundle{}
	_, rest, _ := strings.Cut(text, "\n")
	if rest == "" {
		return b, nil
	}
	lines := strings.Split(rest, "\n")

	var cur *Section
	var body []string
	flush := func() {
		if cur == nil {
			return
		}
		cur.Body = strings.Join(body, "\n")
		b.Sections = append(b.Sections, *cur)
		cur, body = nil, nil
	}
	for i, ln := range lines {
		if strings.HasPrefix(ln, headerPrefix) {
			// The newline before this header belongs to the format, not to the body.
			flush()
			name, arg, _ := strings.Cut(strings.TrimSpace(ln[len(headerPrefix):]), " ")
			cur = &Section{Name: name, Arg: strings.TrimSpace(arg)}
			continue
		}
		if cur == nil {
			// Before the first section only comments and blank lines are expected; anything
			// else is ignored rather than refused, so a hand-annotated file still reads.
			continue
		}
		if i == len(lines)-1 && ln == "" {
			// The final newline of the file closes the last body.
			break
		}
		body = append(body, unescape(ln))
	}
	flush()
	return b, nil
}

// String writes the bundle in its text form. Parse(b.String()) gives b back.
func (b *Bundle) String() string {
	var sb strings.Builder
	sb.WriteString(magic)
	sb.WriteByte('\n')
	for _, s := range b.Sections {
		sb.WriteString(headerPrefix)
		sb.WriteString(s.Name)
		if s.Arg != "" {
			sb.WriteByte(' ')
			sb.WriteString(s.Arg)
		}
		sb.WriteByte('\n')
		if s.Body == "" {
			continue
		}
		for _, ln := range strings.Split(s.Body, "\n") {
			sb.WriteString(escape(ln))
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// escape adds one leading space to a body line that could be read as a header.
func escape(ln string) string {
	if strings.HasPrefix(strings.TrimLeft(ln, " "), headerPrefix) {
		return " " + ln
	}
	return ln
}

func unescape(ln string) string {
	if strings.HasPrefix(ln, " ") && strings.HasPrefix(strings.TrimLeft(ln, " "), headerPrefix) {
		return ln[1:]
	}
	return ln
}

// Get returns the body of the first section with this name.
func (b *Bundle) Get(name string) (string, bool) {
	for _, s := range b.Sections {
		if s.Name == name {
			return s.Body, true
		}
	}
	return "", false
}

// GetArg returns the body of the first section with this name and argument.
func (b *Bundle) GetArg(name, arg string) (string, bool) {
	for _, s := range b.Sections {
		if s.Name == name && s.Arg == arg {
			return s.Body, true
		}
	}
	return "", false
}

// All returns every section with this name, in order ("docker-ss" gives one per container).
func (b *Bundle) All(name string) []Section {
	var out []Section
	for _, s := range b.Sections {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

// Has reports whether the bundle holds a section with this name.
func (b *Bundle) Has(name string) bool {
	_, ok := b.Get(name)
	return ok
}

// Add appends a section.
func (b *Bundle) Add(name, arg, body string) {
	b.Sections = append(b.Sections, Section{Name: name, Arg: arg, Body: body})
}

// Errors returns the errors section as a map from section name to message.
func (b *Bundle) Errors() map[string]string {
	out := map[string]string{}
	for _, s := range b.All("errors") {
		for _, ln := range strings.Split(s.Body, "\n") {
			name, msg, ok := strings.Cut(ln, ":")
			name = strings.TrimSpace(name)
			if !ok || name == "" {
				continue
			}
			if _, seen := out[name]; !seen {
				out[name] = strings.TrimSpace(msg)
			}
		}
	}
	return out
}

// Meta returns the meta section as a map of key to value.
func (b *Bundle) Meta() map[string]string {
	out := map[string]string{}
	body, _ := b.Get("meta")
	for _, ln := range strings.Split(body, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(ln), " ")
		if k != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// Build turns a bundle into the firewall model and the machine model. A section that is missing
// or cannot be parsed becomes a note on the host, not an error; the error is for a bundle that is
// not a snapshot at all.
func Build(b *Bundle) (*rules.Ruleset, *host.Host, error) { return build(b) }

// Collect runs the read-only commands on this machine and returns their output as a bundle.
func Collect(ctx context.Context) *Bundle { return collect(ctx) }

// Script returns a POSIX shell script that prints the same bundle Collect produces, for a machine
// where nothing can be installed.
func Script() string { return script() }
