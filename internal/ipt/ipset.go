package ipt

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gallowforge/seaward/internal/rules"
)

// setTypeDims gives the dimensions of each ipset type, in the names the package comment lists.
var setTypeDims = map[string][]string{
	"hash:ip":           {"ip"},
	"hash:net":          {"net"},
	"hash:ip,port":      {"ip", "port"},
	"hash:net,port":     {"net", "port"},
	"hash:ip,port,ip":   {"ip", "port", "ip"},
	"hash:ip,port,net":  {"ip", "port", "net"},
	"hash:net,port,net": {"net", "port", "net"},
	"hash:net,net":      {"net", "net"},
	"hash:net,iface":    {"net", "iface"},
	"hash:ip,mark":      {"ip", "mark"},
	"hash:mac":          {"mac"},
	"hash:ip,mac":       {"ip", "mac"},
	"bitmap:ip":         {"ip"},
	"bitmap:ip,mac":     {"ip", "mac"},
	"bitmap:port":       {"port-only"},
}

// createArity is how many values each "create" option takes.
var createArity = map[string]int{
	"family": 1, "hashsize": 1, "maxelem": 1, "bucketsize": 1, "initval": 1, "timeout": 1,
	"counters": 0, "comment": 0, "skbinfo": 0, "forceadd": 0, "netmask": 1, "bitmask": 1,
	"markmask": 1, "range": 1, "size": 1, "probes": 1, "resize": 1,
}

// addArity is how many values each "add" option takes.
var addArity = map[string]int{
	"timeout": 1, "packets": 1, "bytes": 1, "comment": 1, "skbmark": 1, "skbprio": 1,
	"skbqueue": 1, "nomatch": 0, "wildcard": 0, "before": 1, "after": 1,
}

type pendingSet struct {
	set      *rules.Set
	typ      string
	dims     []string
	family   string
	netmask  int // hash:ip and bitmap:ip: elements stand for networks of this length
	markmask uint32
	members  []string // list:set
}

// ParseIPSet parses the output of "ipset save". Sets are keyed by rules.SetKey("", "", name).
func ParseIPSet(text string) (sets map[string]*rules.Set, dims map[string][]string, notes []string, err error) {
	sets = map[string]*rules.Set{}
	dims = map[string][]string{}
	pend := map[string]*pendingSet{}
	var order []string
	incomplete := func(ps *pendingSet, why string) {
		if !ps.set.Incomplete {
			ps.set.Incomplete, ps.set.Why = true, why
		}
	}
	for n, raw := range strings.Split(text, "\n") {
		ln := n + 1
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		toks, terr := tokenize(line)
		if terr != nil {
			notes = append(notes, fmt.Sprintf("line %d of the ipset save output could not be read: %v", ln, terr))
			if f := strings.Fields(line); len(f) > 1 {
				if ps := pend[f[1]]; ps != nil {
					incomplete(ps, "a line of the set could not be read")
				}
			}
			continue
		}
		words := make([]string, len(toks))
		for i, t := range toks {
			words[i] = t.s
		}
		if len(words) < 3 {
			notes = append(notes, fmt.Sprintf("line %d of the ipset save output is too short to mean anything", ln))
			continue
		}
		cmd, name := words[0], words[1]
		switch cmd {
		case "create", "-N":
			if _, dup := pend[name]; dup {
				notes = append(notes, fmt.Sprintf("the ipset %s is created twice; the first one is kept", name))
				continue
			}
			ps := &pendingSet{set: &rules.Set{Name: name}, typ: words[2], family: "inet", markmask: 0xffffffff}
			pend[name] = ps
			order = append(order, name)
			if d, ok := setTypeDims[ps.typ]; ok {
				ps.dims = append([]string(nil), d...)
			} else if ps.typ != "list:set" {
				incomplete(ps, "the ipset type "+ps.typ+" is not one seaward knows")
				ps.dims = []string{"unknown"}
			}
			for i := 3; i < len(words); i++ {
				opt := words[i]
				k, ok := createArity[opt]
				if !ok {
					incomplete(ps, "the ipset has a setting seaward does not know ("+opt+")")
					continue
				}
				val := ""
				if k == 1 {
					if i+1 >= len(words) {
						incomplete(ps, "the ipset setting "+opt+" has no value")
						break
					}
					i++
					val = words[i]
				}
				switch opt {
				case "family":
					ps.family = val
				case "timeout":
					// Entries that expire are put there by rules or tools while the machine runs.
					ps.set.Dynamic = true
				case "netmask":
					if v, err := strconv.Atoi(val); err == nil {
						ps.netmask = v
					} else {
						incomplete(ps, "the ipset netmask "+val+" is not one seaward can read")
					}
				case "bitmask":
					incomplete(ps, "the ipset masks addresses with a bit mask, which seaward does not model")
				case "markmask":
					if v, ok := parseU32(val); ok {
						ps.markmask = v
					} else {
						incomplete(ps, "the ipset mark mask "+val+" is not a number")
					}
				}
			}
			if ps.markmask != 0xffffffff {
				for i, d := range ps.dims {
					if d == "mark" {
						ps.dims[i] = fmt.Sprintf("mark/0x%x", ps.markmask)
					}
				}
			}
			for _, d := range ps.dims {
				if d == "mac" {
					incomplete(ps, "the ipset holds hardware (MAC) addresses, which seaward does not model")
				}
			}
		case "add", "-A":
			ps := pend[name]
			if ps == nil {
				notes = append(notes, fmt.Sprintf("line %d of the ipset save output adds to the set %s, which was never created", ln, name))
				continue
			}
			nomatch, wildcard := false, false
			for i := 3; i < len(words); i++ {
				k, ok := addArity[words[i]]
				if !ok {
					incomplete(ps, "an element of the set has an option seaward does not know ("+words[i]+")")
					continue
				}
				switch words[i] {
				case "nomatch":
					nomatch = true
				case "wildcard":
					wildcard = true
				}
				i += k
			}
			if nomatch {
				incomplete(ps, "the set has nomatch elements, which carve exceptions out of it that seaward does not model")
			}
			if ps.typ == "list:set" {
				ps.members = append(ps.members, words[2])
				continue
			}
			if ps.set.Incomplete {
				continue
			}
			elem, why := ps.parseElem(words[2], wildcard)
			if why != "" {
				incomplete(ps, why)
				continue
			}
			ps.set.Elems = append(ps.set.Elems, elem)
		default:
			notes = append(notes, fmt.Sprintf("line %d of the ipset save output starts with %q, which is not create or add", ln, cmd))
		}
	}
	// list:set is the union of its members when they all have the same parts.
	for _, name := range order {
		ps := pend[name]
		if ps.typ != "list:set" {
			continue
		}
		if len(ps.members) == 0 {
			// An empty list never matches; any one-field key gives the same answer.
			ps.dims = []string{"ip"}
			continue
		}
		for i, m := range ps.members {
			mp := pend[m]
			switch {
			case mp == nil:
				incomplete(ps, "the list holds the set "+m+", which was not captured")
			case mp.typ == "list:set":
				incomplete(ps, "the list holds another list, which the kernel does not allow")
			case i > 0 && strings.Join(mp.dims, ",") != strings.Join(ps.dims, ","):
				incomplete(ps, "the list holds sets of different types, which seaward cannot combine")
			default:
				if i == 0 {
					ps.dims = append([]string(nil), mp.dims...)
				}
				if mp.set.Incomplete {
					incomplete(ps, "the list holds the set "+m+", which is incomplete: "+mp.set.Why)
				}
				ps.set.Dynamic = ps.set.Dynamic || mp.set.Dynamic
				ps.set.Elems = append(ps.set.Elems, mp.set.Elems...)
			}
		}
		if ps.dims == nil {
			ps.dims = []string{"ip"}
		}
	}
	for _, name := range order {
		ps := pend[name]
		if ps.set.Incomplete {
			ps.set.Elems = nil
		}
		sets[rules.SetKey("", "", name)] = ps.set
		dims[name] = ps.dims
	}
	return sets, dims, notes, nil
}

// parseElem reads one element, comma-separated, one part per dimension.
func (ps *pendingSet) parseElem(s string, wildcard bool) (rules.Elem, string) {
	parts := strings.Split(s, ",")
	if len(parts) != len(ps.dims) {
		return nil, "the element " + s + " does not fit the set type " + ps.typ
	}
	var e rules.Elem
	for i, part := range parts {
		base, _, _ := strings.Cut(ps.dims[i], "/")
		switch base {
		case "ip", "net":
			a, ok := setAddr(part, ps.netmask)
			if !ok {
				return nil, "the element " + s + " has an address seaward cannot read"
			}
			e = append(e, a)
		case "port":
			proto, port, why := setPort(part)
			if why != "" {
				return nil, why
			}
			e = append(e, rules.Num(proto), port)
		case "port-only":
			if _, rest, ok := strings.Cut(part, ":"); ok {
				part = rest
			}
			a, ok := parsePortRange(part, "-")
			if !ok {
				return nil, "the element " + s + " has a port seaward cannot read"
			}
			e = append(e, a)
		case "iface":
			if strings.HasPrefix(part, "physdev:") {
				return nil, "the set matches bridge ports (physdev), which seaward does not model"
			}
			if wildcard {
				e = append(e, rules.StrPfx(part))
			} else {
				e = append(e, rules.Str(part))
			}
		case "mark":
			v, ok := parseU32(part)
			if !ok {
				return nil, "the element " + s + " has a mark seaward cannot read"
			}
			e = append(e, rules.Num(v&ps.markmask))
		default:
			return nil, "the set type " + ps.typ + " is not one seaward can read"
		}
	}
	return e, ""
}

// setAddr reads an address, a network or a range. With a netmask (hash:ip, bitmap:ip) a plain
// address stands for its whole network.
func setAddr(s string, netmask int) (rules.Atom, bool) {
	if strings.Contains(s, "-") && !strings.Contains(s, "/") {
		return parseAddrRange(s)
	}
	pf, why := parsePrefix(s)
	if why != "" {
		return rules.Atom{}, false
	}
	if netmask > 0 && pf.IsSingleIP() && netmask <= pf.Addr().BitLen() {
		pf = netip.PrefixFrom(pf.Addr(), netmask)
	}
	return rules.Pfx(pf), true
}

// setPort reads "proto:port", "proto:a-b" or a bare port (TCP).
func setPort(s string) (uint32, rules.Atom, string) {
	proto, port, hasProto := strings.Cut(s, ":")
	if !hasProto {
		proto, port = "tcp", s
	}
	n, all, ok := parseProto(proto)
	if !ok || all {
		return 0, rules.Atom{}, "an element uses the protocol " + proto + ", which seaward cannot read"
	}
	switch n {
	case 6, 17, 132, 136:
	case 1, 58:
		return 0, rules.Atom{}, "the set holds ICMP types, which seaward does not model in a set"
	default:
		return 0, rules.Atom{}, "the set holds the protocol " + proto + " without ports, which seaward does not model in a set"
	}
	a, ok := parsePortRange(port, "-")
	if !ok {
		return 0, rules.Atom{}, "an element has a port seaward cannot read (" + port + ")"
	}
	return n, a, ""
}
