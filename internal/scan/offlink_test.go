package scan

import (
	"net/netip"
	"testing"

	"github.com/gallowforge/seaward/internal/host"
)

// A rule counts as link-local or multicast only when its whole range lies there. One that merely
// starts at such an address covers ordinary addresses too, and those are probed.
func TestOffLink(t *testing.T) {
	for _, c := range []struct {
		to   string
		want bool
	}{
		{"fe80::/64", true}, {"fe80::/10", true}, {"ff02::fb/128", true}, {"ff00::/8", true},
		{"224.0.0.251/32", true}, {"224.0.0.0/4", true}, {"169.254.0.0/16", true},
		{"fe80::/8", false}, {"fe00::/7", false}, {"ff00::/7", false}, {"224.0.0.0/3", false},
		{"169.254.0.0/15", false}, {"203.0.113.10/32", false}, {"0.0.0.0/0", false}, {"::/0", false},
	} {
		if got := offLink(host.FrontendRule{To: netip.MustParsePrefix(c.to)}); got != c.want {
			t.Errorf("offLink(%s) = %v, want %v", c.to, got, c.want)
		}
	}
	if offLink(host.FrontendRule{}) {
		t.Error("a rule with no destination was taken for link-local")
	}
}
