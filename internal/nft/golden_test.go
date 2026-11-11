package nft

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// TestGolden pins down how every fixture is read, rule by rule. Run with -update after a
// deliberate change and read the diff.
func TestGolden(t *testing.T) {
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			got := dump(load(t, name))
			path := filepath.Join("testdata", name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("%s reads differently from testdata/%s.golden; run go test -update and read the diff", name, name)
			}
		})
	}
}
