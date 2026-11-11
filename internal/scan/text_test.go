package scan

import (
	"reflect"
	"testing"
)

// Running text is wrapped to the full width, so paragraphs under one another keep one edge, and a
// paragraph does not end on one stray word when the line above can spare its last.
func TestFill(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     []string
	}{
		{"nothing to wrap", "one two three", []string{"one two three"}},
		{"empty", "", nil},
		{"a stray word takes the word before it down",
			"one two three four five six seven",
			[]string{"one two three four five", "six seven"}},
		{"two words at the end are left alone",
			"one two three four five six seven eight",
			[]string{"one two three four five six", "seven eight"}},
		{"the line above keeps at least two words",
			"abcdefghijklmno abcdefghijklmn z",
			[]string{"abcdefghijklmno abcdefghijklmn", "z"}},
		{"a word too long to share the last line stays where it is",
			"a b cccccccccccccccccccccccccc ddddd",
			[]string{"a b cccccccccccccccccccccccccc", "ddddd"}},
		{"only the last line is touched",
			"one two three four five six seven eight nine ten eleven twelve",
			[]string{"one two three four five six", "seven eight nine ten", "eleven twelve"}},
	} {
		if got := fill(c.in, 30); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// The two sentences that stand alone are balanced: as many lines as plain wrapping needs, about
// equally long.
func TestBalance(t *testing.T) {
	const caveat = "Read from this machine's own rules. Anything in front of it (a cloud firewall, a router) is not seen."
	want := []string{"Read from this machine's own rules. Anything in front", "of it (a cloud firewall, a router) is not seen."}
	if got := balance(caveat, 100); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if got := balance("7 ports can be reached from outside.", 100); len(got) != 1 {
		t.Errorf("a sentence that fits was broken: %q", got)
	}
}

// What the firewall tool was told to allow breaks between entries, never inside one.
func TestWrapList(t *testing.T) {
	allows := []string{"22/tcp", "80/tcp", "443/tcp", "9100/tcp from 198.51.100.0/24", "8443/tcp"}
	for _, c := range []struct {
		width int
		want  []string
	}{
		{88, []string{"22/tcp, 80/tcp, 443/tcp, 9100/tcp from 198.51.100.0/24, 8443/tcp"}},
		{52, []string{"22/tcp, 80/tcp, 443/tcp,", "9100/tcp from 198.51.100.0/24, 8443/tcp"}},
		{30, []string{"22/tcp, 80/tcp, 443/tcp,", "9100/tcp from 198.51.100.0/24,", "8443/tcp"}},
	} {
		if got := wrapList(allows, c.width); !reflect.DeepEqual(got, c.want) {
			t.Errorf("at %d columns:\n got  %q\n want %q", c.width, got, c.want)
		}
	}
	if got := wrapList(nil, 52); len(got) != 0 {
		t.Errorf("an empty list: %q", got)
	}
}

// A rule too long for the line breaks before an option, so "-j ACCEPT" and "! -i eth0" stay whole.
func TestWrapRule(t *testing.T) {
	const dnat = "-A DOCKER ! -i br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.18.0.2:5432"
	for _, c := range []struct {
		name, in string
		width    int
		want     []string
	}{
		{"fits", "-A FORWARD -j DOCKER-FORWARD", 60, []string{"-A FORWARD -j DOCKER-FORWARD"}},
		{"an option keeps its value", dnat, 84,
			[]string{"-A DOCKER ! -i br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j DNAT", "--to-destination 172.18.0.2:5432"}},
		{"narrower", dnat, 48,
			[]string{"-A DOCKER ! -i br-4c2f9a71d0e3 -p tcp -m tcp", "--dport 5432 -j DNAT", "--to-destination 172.18.0.2:5432"}},
		{"a negation stays with what it negates",
			"-A DOCKER -d 172.18.0.2/32 ! -i br-4c2f9a71d0e3 -o br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j ACCEPT", 44,
			[]string{"-A DOCKER -d 172.18.0.2/32", "! -i br-4c2f9a71d0e3 -o br-4c2f9a71d0e3", "-p tcp -m tcp --dport 5432 -j ACCEPT"}},
		{"a negated value is not taken for the start of an option",
			"-A INPUT -s ! 198.51.100.0/24 -p tcp -m tcp --dport 22 -j DROP", 30,
			[]string{"-A INPUT -s ! 198.51.100.0/24", "-p tcp -m tcp --dport 22", "-j DROP"}},
		{"a rule without options breaks between words",
			"tcp dport 22 ip saddr @admins accept", 24,
			[]string{"tcp dport 22 ip saddr", "@admins accept"}},
		{"an option with more behind it than a line holds breaks between its words",
			`-A INPUT -m comment --comment "a long remark that will not fit on one line" -j ACCEPT`, 30,
			[]string{"-A INPUT -m comment", `--comment "a long remark that`, `will not fit on one line"`, "-j ACCEPT"}},
		{"empty", "", 40, nil},
	} {
		if got := wrapRule(c.in, c.width); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

// More than four names are said as the first three and a count; up to four are left alone.
func TestFew(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e", "f"}
	for n, want := range map[int][]string{
		0: {}, 1: {"a"}, 3: {"a", "b", "c"}, 4: {"a", "b", "c", "d"},
		5: {"a", "b", "c", "2 more"}, 6: {"a", "b", "c", "3 more"},
	} {
		if got := few(names[:n]); !reflect.DeepEqual(append([]string{}, got...), want) {
			t.Errorf("few of %d: %q, want %q", n, got, want)
		}
	}
	if names[3] != "d" {
		t.Errorf("few wrote into the list it was given: %q", names)
	}
}

// Who reaches a port breaks after a comma or before the "and", so a name and the count at the
// end stay whole; a name longer than the column breaks between its words after all.
func TestWrapNames(t *testing.T) {
	const many = "the local network, 198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only"
	for _, c := range []struct {
		name, in string
		width    int
		want     []string
	}{
		{"fits", many, 80, []string{many}},
		{"the count stays whole", many, 70,
			[]string{"the local network, 198.51.100.8, 198.51.100.16, 198.51.100.24", "and 13 more only"}},
		{"narrower", many, 40,
			[]string{"the local network, 198.51.100.8,", "198.51.100.16, 198.51.100.24", "and 13 more only"}},
		{"a name stays whole", "the local network on eth0 and VPN peers only", 30,
			[]string{"the local network on eth0", "and VPN peers only"}},
		{"what the tool says", "allowed only from 198.51.100.8, from 198.51.100.16, from 198.51.100.24 and 13 more", 40,
			[]string{"allowed only from 198.51.100.8,", "from 198.51.100.16, from 198.51.100.24", "and 13 more"}},
		{"a name longer than the column", "the local network on eth0, eth1 and eth2 over IPv4 only", 12,
			[]string{"the local", "network on", "eth0, eth1", "and eth2", "over IPv4", "only"}},
		{"one word", "nobody", 12, []string{"nobody"}},
		{"empty", "", 40, nil},
		// A whole IPv6 address is one word, and longer than a column of a narrow terminal.
		{"a word longer than the column is cut after a colon", "2001:db8:1234:5678:9abc:def0:1234:5678 only", 24,
			[]string{"2001:db8:1234:5678:9abc:", "def0:1234:5678 only"}},
		{"and the names after it go on", "2001:db8:1234:5678:9abc:def0:1234:5678, 2001:db8::7 and 3 more only", 30,
			[]string{"2001:db8:1234:5678:9abc:def0:", "1234:5678, 2001:db8::7", "and 3 more only"}},
		{"a network", "2001:db8:1234:5678:9abc:def0:1234:5600/120 only", 22,
			[]string{"2001:db8:1234:5678:", "9abc:def0:1234:5600/", "120 only"}},
		{"nothing to cut at", "abcdefghijklmnopqrstuvwxyz only", 12, []string{"abcdefghijkl", "mnopqrstuvwx", "yz only"}},
	} {
		got := wrapNames(c.in, c.width)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
		for _, ln := range got {
			if len(ln) > max(c.width, reachWrap) {
				t.Errorf("%s: a line of %d in a column of %d: %q", c.name, len(ln), c.width, ln)
			}
		}
	}
}
