// Package snapshot is the bundle of command output Seaward works from: reading and writing it,
// collecting it from the machine, and turning it into the firewall model and the machine model.
package snapshot

import (
	"context"
	"errors"

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

// Parse reads a bundle from its text form.
func Parse(text string) (*Bundle, error) {
	return nil, errors.New("snapshot: not written yet")
}

// String writes the bundle in its text form. Parse(b.String()) gives b back.
func (b *Bundle) String() string { return "" }

// Get returns the body of the first section with this name.
func (b *Bundle) Get(name string) (string, bool) { return "", false }

// Build turns a bundle into the firewall model and the machine model. A section that is missing
// or cannot be parsed becomes a note on the host, not an error; the error is for a bundle that is
// not a snapshot at all.
func Build(b *Bundle) (*rules.Ruleset, *host.Host, error) {
	return nil, nil, errors.New("snapshot: not written yet")
}

// Collect runs the read-only commands on this machine and returns their output as a bundle.
func Collect(ctx context.Context) *Bundle { return &Bundle{} }

// Script returns a POSIX shell script that prints the same bundle Collect produces, for a machine
// where nothing can be installed.
func Script() string { return "" }
