// Package engine walks packets through the firewall model the way the kernel would.
package engine

import (
	"net/netip"

	"github.com/gallowforge/seaward/internal/host"
)

// Probe is one packet: the first packet of a new connection from outside.
type Probe struct {
	Iif   string     // the interface it arrives on
	Src   netip.Addr // who sent it
	Dst   netip.Addr // where it was sent
	Proto string     // "tcp" or "udp"
	Sport uint16     // 0 means an ordinary high port
	Dport uint16
}

// Class is how a probe ended.
type Class int

const (
	Open      Class = iota + 1 // a program received it
	Closed                     // it got through and nothing was listening
	Rejected                   // a rule refused it and told the sender
	Filtered                   // dropped without a word
	Forwarded                  // let through to another machine
	Undecided                  // hangs on something the model cannot see
)

func (c Class) String() string {
	switch c {
	case Open:
		return "open"
	case Closed:
		return "closed"
	case Rejected:
		return "rejected"
	case Filtered:
		return "filtered"
	case Forwarded:
		return "forwarded"
	case Undecided:
		return "undecided"
	}
	return "?"
}

// Result is what happened to a probe and why.
type Result struct {
	Class Class
	Steps []Step
	// Listener is the socket that received an Open probe.
	Listener *host.Listener
	// Container is set when the packet was delivered into a container.
	Container *host.Container
	// FinalDst and FinalPort are the destination after any rewriting.
	FinalDst  netip.Addr
	FinalPort uint16
	// Rewritten is true when a rule changed the destination on the way.
	Rewritten bool
	// Out is the interface a packet the machine sends on leaves through; "" when it stays here.
	Out string
	// outs is set on an Undecided result whose ways through were followed apart: every interface
	// one of them leaves through, unless the walked rules stop it first.
	outs []string
	// Unknowns lists what an Undecided result hangs on, or what was uncertain on the way to a
	// result every branch agreed on.
	Unknowns []string
	// Possible lists the ways an Undecided probe can end, depending on the unknowns. It is empty
	// when the walk itself could not say: a way through stopped at something the model does not
	// follow, so a list would be short of an end nobody knows.
	Possible []Class
	// Otherwise is set on an Undecided result when all that was not seen is a chain that can do no
	// more than drop the packet: the packet is either dropped there or ends this way, and nothing
	// else can happen to it. It is zero on every other result.
	Otherwise Class
}

// StepKind says what a step of the path is.
type StepKind string

const (
	StepRule    StepKind = "rule"    // a rule matched and did something
	StepJump    StepKind = "jump"    // a rule sent the packet into another chain
	StepPolicy  StepKind = "policy"  // the end of a base chain: its policy applied
	StepRoute   StepKind = "route"   // the routing decision
	StepDeliver StepKind = "deliver" // the socket lookup or the hand-over to another machine
)

// Step is one thing that happened to the packet.
type Step struct {
	Kind   StepKind `json:"kind"`
	Hook   string   `json:"hook,omitempty"`   // "ingress", "prerouting", "route", "input", "forward", "postrouting"
	Family string   `json:"family,omitempty"` // table family
	Table  string   `json:"table,omitempty"`
	Chain  string   `json:"chain,omitempty"`
	Rule   string   `json:"rule,omitempty"` // the rule as its owner prints it
	// Effect is a few plain words: "accept", "drop", "reject", "to chain DOCKER",
	// "destination becomes 172.17.0.2:80", "policy drop".
	Effect string `json:"effect"`
	// Decisive marks the step that settled the result.
	Decisive bool `json:"decisive,omitempty"`
}
