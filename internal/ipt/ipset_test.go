package ipt

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gallowforge/seaward/internal/rules"
)

func TestIPSetDims(t *testing.T) {
	var b strings.Builder
	for typ := range setTypeDims {
		name := strings.NewReplacer(":", "_", ",", "_").Replace(typ)
		b.WriteString("create " + name + " " + typ + "\n")
	}
	_, dims, notes, err := ParseIPSet(b.String())
	if err != nil || len(notes) != 0 {
		t.Fatalf("%v %v", err, notes)
	}
	for typ, want := range setTypeDims {
		name := strings.NewReplacer(":", "_", ",", "_").Replace(typ)
		if !reflect.DeepEqual(dims[name], want) {
			t.Errorf("%s: %v, want %v", typ, dims[name], want)
		}
	}
	if !reflect.DeepEqual(setTypeDims["hash:ip,port"], []string{"ip", "port"}) || !reflect.DeepEqual(setTypeDims["bitmap:port"], []string{"port-only"}) {
		t.Error("documented dimension names changed")
	}
}

func TestIPSetElements(t *testing.T) {
	text := `create a hash:ip,port family inet hashsize 1024 maxelem 65536
add a 192.0.2.1,tcp:80
add a 192.0.2.2,80
add a 192.0.2.3,udp:53-60
add a 192.0.2.4,sctp:9 timeout 30 packets 1 bytes 60 comment "two words" skbmark 0x1/0xff
create r hash:ip family inet
add r 192.0.2.1-192.0.2.9
create n6 hash:net,port,net family inet6
add n6 2001:db8::/32,tcp:443,2001:db8:1::/48
create bp bitmap:port range 0-1024
add bp tcp:22
add bp 1000-1010
`
	sets, dims, notes, err := ParseIPSet(text)
	if err != nil || len(notes) != 0 {
		t.Fatalf("%v %v", err, notes)
	}
	a := sets[rules.SetKey("", "", "a")]
	want := []rules.Elem{
		{pfx("192.0.2.1/32"), num(6), num(80)},
		{pfx("192.0.2.2/32"), num(6), num(80)},
		{pfx("192.0.2.3/32"), num(17), nr(53, 60)},
		{pfx("192.0.2.4/32"), num(132), num(9)},
	}
	if a.Name != "a" || a.Incomplete || !reflect.DeepEqual(a.Elems, want) {
		t.Errorf("a: %+v", a)
	}
	if r := sets[rules.SetKey("", "", "r")]; !reflect.DeepEqual(r.Elems, []rules.Elem{{rng("192.0.2.1", "192.0.2.9")}}) {
		t.Errorf("r: %+v", r)
	}
	n6 := sets[rules.SetKey("", "", "n6")]
	if !reflect.DeepEqual(n6.Elems, []rules.Elem{{pfx("2001:db8::/32"), num(6), num(443), pfx("2001:db8:1::/48")}}) {
		t.Errorf("n6: %+v", n6)
	}
	if !reflect.DeepEqual(dims["n6"], []string{"net", "port", "net"}) {
		t.Errorf("n6 dims %v", dims["n6"])
	}
	if bp := sets[rules.SetKey("", "", "bp")]; !reflect.DeepEqual(bp.Elems, []rules.Elem{{num(22)}, {nr(1000, 1010)}}) {
		t.Errorf("bp: %+v", bp)
	}
}

func TestIPSetIncomplete(t *testing.T) {
	for _, c := range []struct{ text, why string }{
		{"create m hash:ip,mac\nadd m 192.0.2.1,00:11:22:33:44:55\n", "hardware"},
		{"create m bitmap:ip,mac range 192.0.2.0/24\n", "hardware"},
		{"create m hash:net\nadd m 10.0.0.0/8\nadd m 10.1.0.0/16 nomatch\n", "nomatch"},
		{"create m hash:ip,port\nadd m 192.0.2.1,icmp:ping\n", "ICMP"},
		{"create m hash:ip,port\nadd m 192.0.2.1,gre:0\n", "without ports"},
		{"create m hash:net,iface\nadd m 10.0.0.0/8,physdev:eth0\n", "physdev"},
		{"create m hash:ip\nadd m 192.0.2.1,80\n", "does not fit"},
		{"create m hash:ip\nadd m bogus\n", "address"},
		{"create m hash:weird\n", "not one seaward knows"},
		{"create m hash:ip frobnicate\n", "frobnicate"},
		{"create m hash:ip bitmask 255.255.0.0\n", "bit mask"},
		{"create m hash:ip\nadd m 192.0.2.1 surprise\n", "surprise"},
		{"create m list:set size 8\nadd m nosuch\n", "not captured"},
		{"create a hash:ip\ncreate b hash:ip,port\ncreate m list:set\nadd m a\nadd m b\n", "different types"},
		{"create a hash:ip\nadd a 192.0.2.1 nomatch\ncreate m list:set\nadd m a\n", "incomplete"},
	} {
		sets, _, _, err := ParseIPSet(c.text)
		if err != nil {
			t.Fatal(err)
		}
		m := sets[rules.SetKey("", "", "m")]
		if m == nil || !m.Incomplete || !strings.Contains(m.Why, c.why) || len(m.Elems) != 0 {
			t.Errorf("%q: %+v, want Incomplete with %q", c.text, m, c.why)
		}
	}
}

func TestIPSetListAndNotes(t *testing.T) {
	text := `create a hash:net family inet timeout 300
add a 192.0.2.0/24 timeout 100
create b hash:net family inet6
add b 2001:db8::/32
create empty list:set size 8
create l list:set size 8
add l a
add l b before a
add ghost 192.0.2.1
create a hash:ip
destroy a
`
	sets, dims, notes, err := ParseIPSet(text)
	if err != nil {
		t.Fatal(err)
	}
	l := sets[rules.SetKey("", "", "l")]
	if l.Incomplete || !l.Dynamic || !reflect.DeepEqual(l.Elems, []rules.Elem{{pfx("192.0.2.0/24")}, {pfx("2001:db8::/32")}}) || !reflect.DeepEqual(dims["l"], []string{"net"}) {
		t.Errorf("l: %+v %v", l, dims["l"])
	}
	if e := sets[rules.SetKey("", "", "empty")]; e.Incomplete || len(e.Elems) != 0 || len(dims["empty"]) != 1 {
		t.Errorf("empty: %+v %v", e, dims["empty"])
	}
	if len(notes) != 3 {
		t.Errorf("notes: %q", notes)
	}
	// A list built from what ParseIPSet returned is matched with the right key.
	exprs := parseOne(t, "ip", "filter", "INPUT", "-m set --match-set l src", dims)
	if !same(exprs, []rules.Expr{setRef("l", false, fld(rules.FSaddr))}) {
		t.Errorf("list match: %s", dumpList(exprs))
	}
}
