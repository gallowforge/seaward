// Package rules is the firewall model. Every parser (iptables-save, nft JSON) produces it and the
// engine walks it. It is deliberately close to how nftables thinks: a rule is an ordered list of
// expressions, each one either a match that can fail or a statement that does something.
package rules

import "net/netip"

// Ruleset is everything the kernel's packet filter was told, from every source.
type Ruleset struct {
	Tables []*Table
	// Sets holds named sets: nft sets and maps under SetKey(family, table, name), ipsets under
	// SetKey("", "", name).
	Sets map[string]*Set
	// Notes are things a parser saw and could not represent (a table family it skips, a flowtable).
	Notes []string
	// Unread lists the rule sources that exist on the machine and could not be read (no root, a
	// listing that would not parse). Rules nobody read may stop or redirect anything, so the engine
	// decides nothing for a family while one of its sources is unread.
	Unread []Unread
	// Unfollowed lists the base chains the kernel runs at a point of the packet path the engine
	// does not walk: an egress hook, a bridge, an ingress hook underneath the interface a packet
	// arrives on. Each has rules or drops by policy, so the engine decides nothing for a packet
	// that passes one.
	Unfollowed []Unfollowed
}

// Unread is one rule source that could not be read.
type Unread struct {
	Family string // "ip" or "ip6" when only that family's rules are missing; "" for both
	Why    string // one plain sentence
}

// Unfollowed is one base chain outside the path the engine walks, and the packets it sees.
type Unfollowed struct {
	Why string // one plain sentence that names the chain
	// In and Out name the interfaces whose arriving and leaving packets the chain sees. A name
	// that ends in "*" stands for every interface whose name starts that way.
	In, Out []string
	// BridgeIn and BridgeOut are for a chain of a bridge table: it sees what arrives or leaves
	// through any bridge of the machine.
	BridgeIn, BridgeOut bool
	// OnlyStops is true when the chain can do no more than drop a packet or let it pass: none of
	// its rules changes a packet, sends it elsewhere or answers it. A packet the walked rules drop
	// is then dropped whatever the chain does.
	OnlyStops bool
	// Walked is true for an ingress chain the engine does walk, as a base chain of its table, for
	// a packet that arrives on one of In itself. The entry then stands only for a packet that
	// passes one of In underneath the interface it arrives on: a port of its bridge or bond, the
	// interface its VLAN sits on.
	Walked bool
}

// SetKey is the key of a named set in Ruleset.Sets.
func SetKey(family, table, name string) string { return family + "\x00" + table + "\x00" + name }

// Table is one table of one family.
type Table struct {
	Family string // "ip", "ip6", "inet" or "netdev"
	Name   string
	Origin string // "iptables" (nf_tables backend), "iptables-legacy" or "nft"
	Chains map[string]*Chain
	Order  []string // chain names in source order
}

// Hooks, as Chain.Hook spells them. Ingress comes first: it runs for each packet as it arrives
// on an interface, before connection tracking and before prerouting.
const (
	HookIngress     = "ingress"
	HookPrerouting  = "prerouting"
	HookInput       = "input"
	HookForward     = "forward"
	HookOutput      = "output"
	HookPostrouting = "postrouting"
)

// Chain is a list of rules. A base chain is attached to a hook; any other chain is only reached by
// a jump or goto.
type Chain struct {
	Name     string
	Base     bool
	Hook     string      // base chains: one of the Hook constants
	Type     string      // base chains: "filter", "nat" or "route"
	Priority int         // base chains: lower runs first
	Policy   VerdictKind // base chains: Accept or Drop
	// Devs names the interfaces an ingress chain is attached to: it sees a packet that arrives on
	// one of them and no other. A name that ends in "*" stands for every interface whose name
	// starts that way.
	Devs  []string
	Rules []*Rule
}

// Rule is one rule. Exprs run left to right; the first match that fails ends the rule.
type Rule struct {
	// Text is the rule as its owner prints it: the iptables-save line, or nft syntax.
	Text  string
	Exprs []Expr
}

// Expr is a Match, an Unknown, or one of the statements below.
type Expr interface{ expr() }

// FieldName names something a rule can look at.
type FieldName int

const (
	FSaddr        FieldName = iota // source address
	FDaddr                         // destination address (after any DNAT that already happened)
	FSport                         // source port (tcp, udp, sctp, dccp, udplite)
	FDport                         // destination port
	FL4Proto                       // IP protocol number: 6 tcp, 17 udp, 1 icmp, 58 icmpv6 ...
	FNFProto                       // 4 or 6: which IP version the packet is (inet tables)
	FIifName                       // input interface name
	FOifName                       // output interface name ("" before routing and on input)
	FMark                          // packet mark
	FCtMark                        // connection mark
	FCtState                       // one of the CtState values
	FCtStatusDNAT                  // 1 when this connection had its destination rewritten, else 0
	FCtStatusSNAT                  // 1 when this connection had its source rewritten, else 0
	FCtOrigDaddr                   // destination address before any DNAT
	FCtOrigDport                   // destination port before any DNAT
	FCtDirection                   // 0 original, 1 reply (a new packet is always original)
	FFibDaddrType                  // one of the AddrType values, for the destination
	FFibSaddrType                  // one of the AddrType values, for the source
	FRpfOK                         // 1 when the reverse path check for the source passes, else 0
	FPktType                       // one of the PktType values
	FTCPFlags                      // TCP flag bits: FIN 1, SYN 2, RST 4, PSH 8, ACK 16, URG 32
	FICMPType                      // ICMP type (v4)
	FICMPv6Type                    // ICMPv6 type
	FIPSecIn                       // 1 when the packet arrived through IPsec, else 0
	// The address type as the arriving interface alone sees it: an address of another interface
	// of this machine is unicast there (addrtype --limit-iface-in, "fib daddr . iif type").
	FFibDaddrTypeIif
	FFibSaddrTypeIif
)

// Connection states for FCtState. A probe is always the first packet of a connection: CtNew.
const (
	CtInvalid uint32 = 1 << iota
	CtEstablished
	CtRelated
	CtNew
	CtUntracked
)

// Address types for FFibDaddrType and FFibSaddrType (the kernel's RTN_ values).
const (
	AddrUnspec      uint32 = 0
	AddrUnicast     uint32 = 1
	AddrLocal       uint32 = 2
	AddrBroadcast   uint32 = 3
	AddrAnycast     uint32 = 4
	AddrMulticast   uint32 = 5
	AddrBlackhole   uint32 = 6
	AddrUnreachable uint32 = 7
	AddrProhibit    uint32 = 8
)

// Packet types for FPktType.
const (
	PktHost      uint32 = 0 // addressed to this machine
	PktBroadcast uint32 = 1
	PktMulticast uint32 = 2
	PktOtherHost uint32 = 3
)

// Field is a field name with an optional mask: the value compared is (field & Mask). The mask
// applies to numeric fields only (marks, TCP flags).
type Field struct {
	Name    FieldName
	Mask    uint32
	HasMask bool
}

// Match passes when the packet's key is in the values (or, with Neg, when it is not). The key is
// one field, or several for a concatenation such as "ip saddr . tcp dport". A field the packet does
// not have (a port on ICMP, an address of the other family) makes the match fail whatever Neg says,
// as in the kernel.
type Match struct {
	Key []Field
	Neg bool
	// Exactly one of Values and SetRef is used. SetRef is a key into Ruleset.Sets.
	Values *Set
	SetRef string
}

// Unknown is a condition the model cannot decide: an extension it does not know, a set whose
// contents were not captured. The engine follows both outcomes and reports what the answer hangs on.
type Unknown struct {
	Why string // one plain sentence, shown to the user
}

// Always is a condition that is true for a probe (a rate limit the first packet passes, a comment).
// It exists so a rule's Text and its Exprs stay in step; the engine skips it.
type Always struct {
	What string
}

// Never is a condition that is false for a probe, because a probe is the first packet this machine
// has ever seen from its sender: "this address was seen in the last minute" (recent --rcheck),
// "this address already has four connections open" (connlimit above), "this is a fragment".
type Never struct {
	What string
}

// VerdictKind is what a verdict does.
type VerdictKind int

const (
	Accept VerdictKind = iota + 1
	Drop
	Reject   // dropped, and the sender is told (RST or ICMP error)
	Return   // back to the calling chain; in a base chain: the policy
	Continue // on to the next rule
	Jump     // to Chain, then back
	Goto     // to Chain, not coming back
)

// Verdict ends or redirects the walk.
type Verdict struct {
	Kind  VerdictKind
	Chain string // Jump and Goto: a chain in the same table
}

// VerdictMap looks the packet's key up and runs the verdict it finds. No entry ends the rule, as a
// failed match does; an entry that says continue goes on to the next expression. Exactly one of
// Entries and SetRef is used.
type VerdictMap struct {
	Key     []Field
	Entries []VmapEntry
	SetRef  string
}

// VmapEntry is one line of a verdict map.
type VmapEntry struct {
	Key     Elem
	Verdict Verdict
}

// DNAT rewrites the destination. A zero Addr keeps the address; a zero Port keeps the port. In a
// nat chain it ends the chain with accept.
//
// With a range of ports the kernel keeps the port the packet came for when it already lies in the
// range and takes the first port of the range when it does not, unless the rule asks for a random
// one. With a range of addresses it picks one by who sent the packet, which the engine does not
// work out: that packet is undecided.
type DNAT struct {
	Addr   netip.Addr
	AddrHi netip.Addr // zero unless a range
	Port   uint16
	PortHi uint16 // zero unless a range
	Random bool   // the port is picked at random out of the range
}

// Redirect rewrites the destination to this machine: the first address of the input interface.
// A zero Port keeps the port. A range of ports is read as for DNAT.
type Redirect struct {
	Port   uint16
	PortHi uint16
	Random bool
}

// SetMark changes the packet mark or the connection mark: new = (old AND And) XOR Xor.
// Plain "set mark to v" is And 0, Xor v.
type SetMark struct {
	Ct  bool // true: the connection mark
	And uint32
	Xor uint32
}

// CopyMark copies between packet mark and connection mark (CONNMARK --restore-mark and
// --save-mark, "meta mark set ct mark"): dst = (dst AND NOT Mask) OR (src AND Mask).
type CopyMark struct {
	ToCt bool // true: packet mark -> connection mark; false: connection mark -> packet mark
	Mask uint32
}

// Noop is a statement with no effect on whether a new connection gets through: a counter, a log
// line, masquerade and source NAT, TCPMSS clamping.
type Noop struct {
	What string
}

// Notrack takes the packet out of connection tracking (raw table NOTRACK, "notrack"): its state
// becomes untracked and no NAT applies to it.
type Notrack struct{}

// UnknownStmt is a statement whose effect the model cannot follow (TPROXY, NFQUEUE, a flow
// offload it does not know). The engine reports the port as undecided and says why.
type UnknownStmt struct {
	Why string
}

func (*Match) expr()       {}
func (*Unknown) expr()     {}
func (*Always) expr()      {}
func (*Never) expr()       {}
func (*Notrack) expr()     {}
func (*Verdict) expr()     {}
func (*VerdictMap) expr()  {}
func (*DNAT) expr()        {}
func (*Redirect) expr()    {}
func (*SetMark) expr()     {}
func (*CopyMark) expr()    {}
func (*Noop) expr()        {}
func (*UnknownStmt) expr() {}

// Set is a set of elements; each element has one atom per key field.
type Set struct {
	Name  string // empty for an inline set
	Elems []Elem
	// Verdicts is used by named verdict maps only: one verdict per element.
	Verdicts []Verdict
	// Dynamic sets are filled by the rules themselves at run time; the elements are what was in
	// the set when the snapshot was taken.
	Dynamic bool
	// Incomplete means the contents could not be read or represented, so a lookup is unknown.
	Incomplete bool
	Why        string // with Incomplete: one plain sentence
}

// Elem is one element: one atom per key field.
type Elem []Atom

// AtomKind says which fields of an Atom are in use.
type AtomKind int

const (
	AtomAny    AtomKind = iota // matches every value (used for a wildcard field in a concatenation)
	AtomPrefix                 // Prefix: an address or a network
	AtomRange                  // AddrLo..AddrHi, both included
	AtomNum                    // Lo..Hi, both included: ports, protocol numbers, marks, flags, types
	AtomStr                    // S exactly: an interface name
	AtomStrPfx                 // every string that starts with S: iptables "eth+", nft "eth*"
)

// Atom is one value or range of values of one field.
type Atom struct {
	Kind   AtomKind
	Prefix netip.Prefix
	AddrLo netip.Addr
	AddrHi netip.Addr
	Lo, Hi uint32
	S      string
}

// Num is the atom for one number.
func Num(v uint32) Atom { return Atom{Kind: AtomNum, Lo: v, Hi: v} }

// NumRange is the atom for lo..hi.
func NumRange(lo, hi uint32) Atom { return Atom{Kind: AtomNum, Lo: lo, Hi: hi} }

// Pfx is the atom for an address or network.
func Pfx(p netip.Prefix) Atom { return Atom{Kind: AtomPrefix, Prefix: p.Masked()} }

// Str is the atom for an exact string.
func Str(s string) Atom { return Atom{Kind: AtomStr, S: s} }

// StrPfx is the atom for every string starting with s.
func StrPfx(s string) Atom { return Atom{Kind: AtomStrPfx, S: s} }

// One is a set of single-field elements, for the common one-field match.
func One(atoms ...Atom) *Set {
	s := &Set{}
	for _, a := range atoms {
		s.Elems = append(s.Elems, Elem{a})
	}
	return s
}

// Eq is the match "field is one of atoms".
func Eq(f FieldName, atoms ...Atom) *Match {
	return &Match{Key: []Field{{Name: f}}, Values: One(atoms...)}
}

// Ne is the match "field is none of atoms".
func Ne(f FieldName, atoms ...Atom) *Match {
	return &Match{Key: []Field{{Name: f}}, Neg: true, Values: One(atoms...)}
}
