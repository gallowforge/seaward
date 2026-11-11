package ipt

import (
	"os"
	"path/filepath"
	"testing"
)

func addSeeds(f *testing.F) {
	for _, name := range []string{"docker-ufw.save", "plain.save", "ip6.save", "incompatible.save", "extensions.save", "ipset.save"} {
		if b, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(string(b))
		}
	}
	f.Add("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT ! -s 10.0.0.0/255.0.255.0 -m set ! --match-set x src,dst -j DNAT --to-destination [2001:db8::2]-[\nCOMMIT\n")
	f.Add("*nat\n:PREROUTING ACCEPT [0:0]\n[1:2] -A PREROUTING -j DNAT --to-destination :\nCOMMIT\n")
	f.Add("*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING ! -m conntrack ! --ctstate \"\" ! \nCOMMIT\n")
	f.Add("create s list:set\nadd s s\nadd s 1.2.3.4,tcp:\ncreate t hash:ip,port\nadd t ,\n")
}

// ParseSave must never panic, whatever it is given.
func FuzzParseSave(f *testing.F) {
	addSeeds(f)
	dims := map[string][]string{"x": {"ip", "port"}, "y": {"mark/0xzz"}, "z": {}, "w": {"mac", "ip"}}
	f.Fuzz(func(t *testing.T, s string) {
		for _, fam := range []string{"ip", "ip6"} {
			tables, _, err := ParseSave(s, Options{Family: fam, SetDims: dims})
			if err != nil {
				continue
			}
			for _, tbl := range tables {
				for _, name := range tbl.Order {
					for _, r := range tbl.Chains[name].Rules {
						for _, e := range r.Exprs {
							if e == nil {
								t.Fatalf("nil expression in %q", r.Text)
							}
						}
					}
				}
			}
		}
	})
}

// ParseIPSet must never panic either.
func FuzzParseIPSet(f *testing.F) {
	addSeeds(f)
	f.Fuzz(func(t *testing.T, s string) {
		sets, dims, _, _ := ParseIPSet(s)
		for name, d := range dims {
			if len(d) == 0 {
				t.Fatalf("set %s has no dimensions", name)
			}
		}
		for k, set := range sets {
			if set == nil {
				t.Fatalf("nil set %q", k)
			}
		}
	})
}
