package ipt

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// The .save files were produced by loading rules with iptables-restore inside a private network
// namespace and printing them back with iptables-save, so they are what the tool really prints.
func TestGolden(t *testing.T) {
	cases := []struct {
		file   string
		family string
	}{
		{"docker-ufw.save", "ip"},
		{"plain.save", "ip"},
		{"ip6.save", "ip6"},
		{"incompatible.save", "ip"},
		{"extensions.save", "ip"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			tables, notes, err := ParseSave(string(in), Options{Family: c.family})
			if err != nil {
				t.Fatal(err)
			}
			got := dumpTables(tables, notes)
			golden := filepath.Join("testdata", c.file+".golden")
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if got != string(want) {
				t.Errorf("dump differs from %s; run with -update and review the diff\n%s", golden, got)
			}
		})
	}
}

func TestGoldenIPSet(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "ipset.save"))
	if err != nil {
		t.Fatal(err)
	}
	sets, dims, notes, err := ParseIPSet(string(in))
	if err != nil {
		t.Fatal(err)
	}
	got := dumpSets(sets, dims, notes)
	golden := filepath.Join("testdata", "ipset.save.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("dump differs from %s\n%s", golden, got)
	}
}
