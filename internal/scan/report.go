// Package scan answers the question Seaward exists for: which ports of a machine can be reached
// from outside, by whom, and which rule decides it. It follows one first packet per port from every
// kind of sender the rules tell apart, and compares the answers with what the firewall manager
// (ufw, firewalld) says it allows.
package scan

import "github.com/gallowforge/seaward/internal/engine"

// Step is one thing that happened to a packet on its way.
type Step = engine.Step

// Report is everything Seaward says about one machine.
type Report struct {
	Host     string    `json:"host"`
	Headline string    `json:"headline"`
	Detail   string    `json:"detail,omitempty"`
	Frontend *Frontend `json:"frontend,omitempty"`
	Vantages []Vantage `json:"vantages"`
	Ports    []Port    `json:"ports"`
	// Unread lists rule sources that exist on the machine and could not be read.
	Unread []string `json:"unread,omitempty"`
	Notes  []string `json:"notes,omitempty"`
	Counts Counts   `json:"counts"`
	// Caveat is the limit every report has, in one sentence.
	Caveat string `json:"caveat"`
}

// Caveat is said under every report.
const Caveat = "Read from this machine's own rules. Anything in front of it (a cloud firewall, a router) is not seen."

// Counts sums the findings up.
type Counts struct {
	Reachable int `json:"reachable"` // exposed, open, limited
	Exposed   int `json:"exposed"`
	Stopped   int `json:"stopped"` // blocked, shadowed
	Quiet     int `json:"quiet"`   // local, closed, dead
	Undecided int `json:"undecided"`
}

// Frontend is the firewall manager and what it says it allows.
type Frontend struct {
	Tool    string   `json:"tool"`
	Default string   `json:"default"`
	Allows  []string `json:"allows"`
}

// Vantage is one place a packet can come from.
type Vantage struct {
	ID    string `json:"id"`    // "internet", "lan:eth0", "vpn:wg0"
	Label string `json:"label"` // "the internet", "the local network on eth0 (192.0.2.0/24)"
	Short string `json:"short"` // "internet", "LAN eth0"
	Iface string `json:"iface"`
	Scope string `json:"scope"` // "world", "lan" or "vpn"
}

// The findings, most serious first.
const (
	Exposed   = "exposed"   // reachable, and the firewall manager does not allow it
	Open      = "open"      // reachable from anywhere (and allowed, when a manager is active)
	Limited   = "limited"   // reachable from part of the outside only; no manager to compare with
	Undecided = "undecided" // hangs on something the snapshot does not hold
	Shadowed  = "shadowed"  // the manager allows it, yet another rule stops it
	Dead      = "dead"      // the manager allows it, and nothing is listening
	Blocked   = "blocked"   // a rule stops it
	Closed    = "closed"    // nothing answers on an outside address
	Local     = "local"     // listens on the loopback only
)

// Port is one port and what was found out about it.
type Port struct {
	Proto    string `json:"proto"`
	Port     uint16 `json:"port"`
	Finding  string `json:"finding"`
	Severity string `json:"severity"` // "high", "medium", "unknown", "info", "low", "ok"
	Title    string `json:"title"`
	Service  string `json:"service,omitempty"` // "sshd", "nginx in container web (nginx:1.27)"
	Reach    string `json:"reach,omitempty"`   // who gets through: "the internet", "the local network only"
	Stated   string `json:"stated,omitempty"`  // what the firewall manager says about it
	Why      string `json:"why,omitempty"`
	Rewrite  *Step  `json:"rewrite,omitempty"`  // the rule that sent the packet somewhere else
	Deciding *Step  `json:"deciding,omitempty"` // the rule or policy that settled it
	// Views is the port seen from each place in Report.Vantages, in the same order.
	Views []View `json:"views"`
	Cells []Cell `json:"cells"`
}

// The states of a View.
const (
	ViewOpen      = "open"      // anyone there gets through
	ViewSome      = "some"      // only the senders in Note get through
	ViewStopped   = "stopped"   // a rule stops it
	ViewClosed    = "closed"    // nothing answers
	ViewUndecided = "undecided" // hangs on something the snapshot does not hold
)

// View is one port seen from one place.
type View struct {
	Vantage string `json:"vantage"`
	State   string `json:"state"`
	Note    string `json:"note,omitempty"` // "IPv4 only", "198.51.100.0/24 only"
}

// Cell is one packet: who sent it, to which address, how it ended and why.
type Cell struct {
	Vantage  string   `json:"vantage"`
	From     string   `json:"from"` // the senders this packet stands for
	Src      string   `json:"src"`
	Dst      string   `json:"dst"`
	IPv6     bool     `json:"ipv6,omitempty"`
	Class    string   `json:"class"`
	Possible []string `json:"possible,omitempty"`
	// Allowed is what the firewall manager says about this packet; absent without a manager.
	Allowed  *bool    `json:"allowed,omitempty"`
	Why      string   `json:"why"`
	Rewrite  *Step    `json:"rewrite,omitempty"`
	Deciding *Step    `json:"deciding,omitempty"`
	Steps    []Step   `json:"steps"`
	Unknowns []string `json:"unknowns,omitempty"`
}
