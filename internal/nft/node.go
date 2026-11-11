package nft

import (
	"encoding/json"
	"sort"
	"strconv"
)

// node is one value of the decoded listing. Reading an object's key through get marks the key as
// read, so that after a rule's expression is translated the parser can tell whether anything in it
// went unread: a part nobody looked at becomes an unknown instead of being dropped.
type node struct {
	v any // nil, bool, string, json.Number, []*node or *object
}

// object is a JSON object that remembers which of its keys were read.
type object struct {
	m    map[string]*node
	used map[string]bool
	all  bool // the whole object, and everything in it, counts as read
}

// build turns what encoding/json decoded into nodes.
func build(v any) *node {
	switch v := v.(type) {
	case map[string]any:
		o := &object{m: make(map[string]*node, len(v))}
		for k, x := range v {
			o.m[k] = build(x)
		}
		return &node{v: o}
	case []any:
		a := make([]*node, len(v))
		for i, x := range v {
			a[i] = build(x)
		}
		return &node{v: a}
	}
	return &node{v: v}
}

// obj is the node as an object, or nil.
func (n *node) obj() *object {
	if n == nil {
		return nil
	}
	o, _ := n.v.(*object)
	return o
}

// arr is the node's elements when it is a list, or nil.
func (n *node) arr() []*node {
	if n == nil {
		return nil
	}
	a, _ := n.v.([]*node)
	return a
}

func (n *node) isArr() bool {
	if n == nil {
		return false
	}
	_, ok := n.v.([]*node)
	return ok
}

// null reports a missing value or a JSON null.
func (n *node) null() bool { return n == nil || n.v == nil }

func (n *node) str() (string, bool) {
	if n == nil {
		return "", false
	}
	s, ok := n.v.(string)
	return s, ok
}

func (n *node) boolean() (value, ok bool) {
	if n == nil {
		return false, false
	}
	b, ok := n.v.(bool)
	return b, ok
}

// num reads a whole number that is not negative.
func (n *node) num() (uint64, bool) {
	if n == nil {
		return 0, false
	}
	j, ok := n.v.(json.Number)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(string(j), 10, 64)
	return v, err == nil
}

// u32 reads a whole number that fits in 32 bits.
func (n *node) u32() (uint32, bool) {
	v, ok := n.num()
	if !ok || v > 0xffffffff {
		return 0, false
	}
	return uint32(v), true
}

// i64 reads a whole number that may be negative.
func (n *node) i64() (int64, bool) {
	if n == nil {
		return 0, false
	}
	j, ok := n.v.(json.Number)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(string(j), 10, 64)
	return v, err == nil
}

// done marks the node and everything under it as read: the caller knows what it is and has no use
// for the details (a counter's packet count, a log prefix).
func (n *node) done() {
	if n == nil {
		return
	}
	switch v := n.v.(type) {
	case *object:
		v.all = true
	case []*node:
		for _, x := range v {
			x.done()
		}
	}
}

// unread names a key under the node that nothing read, or "".
func (n *node) unread() string {
	if n == nil {
		return ""
	}
	switch v := n.v.(type) {
	case *object:
		if v.all {
			return ""
		}
		for _, k := range v.keys() {
			if !v.used[k] {
				return k
			}
			if u := v.m[k].unread(); u != "" {
				return u
			}
		}
	case []*node:
		for _, x := range v {
			if u := x.unread(); u != "" {
				return u
			}
		}
	}
	return ""
}

// keys lists the object's keys in a fixed order.
func (o *object) keys() []string {
	ks := make([]string, 0, len(o.m))
	for k := range o.m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// get reads a key and marks it as read. A missing key gives nil, which every reader accepts.
func (o *object) get(k string) *node {
	if o == nil {
		return nil
	}
	n, ok := o.m[k]
	if !ok {
		return nil
	}
	if o.used == nil {
		o.used = map[string]bool{}
	}
	o.used[k] = true
	return n
}

// peek reads a key without marking it.
func (o *object) peek(k string) *node {
	if o == nil {
		return nil
	}
	return o.m[k]
}

func (o *object) has(k string) bool {
	if o == nil {
		return false
	}
	_, ok := o.m[k]
	return ok
}

// one returns the key and value of an object that has exactly one key, as every nft expression
// does, and marks it as read. Any other object gives "".
func (o *object) one() (string, *node) {
	k, n := o.onePeek()
	if k != "" {
		o.get(k)
	}
	return k, n
}

// onePeek is one without the mark.
func (o *object) onePeek() (string, *node) {
	if o == nil || len(o.m) != 1 {
		return "", nil
	}
	for k, n := range o.m {
		return k, n
	}
	return "", nil
}

// text reads a string key, or "".
func (o *object) text(k string) string {
	s, _ := o.get(k).str()
	return s
}

// strs reads a list of strings; nft writes a one-item list as a bare string.
func (n *node) strs() []string {
	if s, ok := n.str(); ok {
		return []string{s}
	}
	var out []string
	for _, x := range n.arr() {
		if s, ok := x.str(); ok {
			out = append(out, s)
		}
	}
	return out
}
