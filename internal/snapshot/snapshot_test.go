package snapshot

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	bodies := []string{
		"",
		"one line",
		"one line\n",
		"two\nlines",
		"\n",
		"\n\n",
		"### looks like a header",
		" ### already one space",
		"   ### three spaces",
		"a\n### b\n ### c\nd",
		"###no space is not a header",
		"trailing\r",
		"tabs\tand  spaces  ",
		"ends with blank lines\n\n\n",
		"# a comment-looking line",
	}
	b := &Bundle{}
	for i, body := range bodies {
		arg := ""
		if i%3 == 0 {
			arg = "abc123"
		}
		b.Add("sec", arg, body)
	}
	got, err := Parse(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, b) {
		for i := range b.Sections {
			if i >= len(got.Sections) || got.Sections[i] != b.Sections[i] {
				t.Errorf("section %d: got %#v, want %#v", i, safeSection(got, i), b.Sections[i])
			}
		}
		t.Fatalf("round trip lost something:\n%s", b.String())
	}
	// And every body alone, last in the file.
	for _, body := range bodies {
		one := &Bundle{Sections: []Section{{Name: "x", Body: body}}}
		got, err := Parse(one.String())
		if err != nil || !reflect.DeepEqual(got, one) {
			t.Errorf("body %q: got %#v, err %v", body, got, err)
		}
	}
}

func safeSection(b *Bundle, i int) any {
	if i < len(b.Sections) {
		return b.Sections[i]
	}
	return nil
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Section
	}{
		{"empty snapshot", "# seaward snapshot 1\n", nil},
		{"no trailing newline at all", "# seaward snapshot 1", nil},
		{"comments before first section", "# seaward snapshot 1\n# made by hand\n\n### meta\nhost web-1\n",
			[]Section{{Name: "meta", Body: "host web-1"}}},
		{"missing trailing newline", "# seaward snapshot 1\n### a\nx\n### b\ny",
			[]Section{{Name: "a", Body: "x"}, {Name: "b", Body: "y"}}},
		{"empty bodies", "# seaward snapshot 1\n### a\n### b\n",
			[]Section{{Name: "a"}, {Name: "b"}}},
		{"argument", "# seaward snapshot 1\n### docker-ss 5b0f3c9e\ntcp LISTEN\n",
			[]Section{{Name: "docker-ss", Arg: "5b0f3c9e", Body: "tcp LISTEN"}}},
		{"crlf", "# seaward snapshot 1\r\n### a\r\nx\r\ny\r\n### b c\r\n",
			[]Section{{Name: "a", Body: "x\ny"}, {Name: "b", Arg: "c"}}},
		{"escaped header line", "# seaward snapshot 1\n### a\n ### not a header\n",
			[]Section{{Name: "a", Body: "### not a header"}}},
		{"byte order mark", "\uFEFF# seaward snapshot 1\n### a\nx\n",
			[]Section{{Name: "a", Body: "x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Parse(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(b.Sections, tt.want) {
				t.Errorf("got %#v\nwant %#v", b.Sections, tt.want)
			}
		})
	}
}

func TestParseNotSnapshot(t *testing.T) {
	for _, in := range []string{"", "hello", "### meta\nhost x\n", "#seaward snapshot 1\n"} {
		if _, err := Parse(in); !errors.Is(err, ErrNotSnapshot) {
			t.Errorf("Parse(%q): err %v, want ErrNotSnapshot", in, err)
		}
	}
	if _, err := Parse("# seaward snapshot 2\n"); err == nil || errors.Is(err, ErrNotSnapshot) {
		t.Errorf("a newer format should say so, got %v", err)
	}
}

func TestLookups(t *testing.T) {
	b, err := Parse("# seaward snapshot 1\n### meta\nhost web-1\nroot no\n### docker-ss aaa\none\n### docker-ss bbb\ntwo\n" +
		"### errors\nufw-status: ERROR: You need to be root to run this script\nnft-json: Operation not permitted\n")
	if err != nil {
		t.Fatal(err)
	}
	if body, ok := b.GetArg("docker-ss", "bbb"); !ok || body != "two" {
		t.Errorf("GetArg: %q %v", body, ok)
	}
	if _, ok := b.GetArg("docker-ss", "ccc"); ok {
		t.Error("GetArg found a section that is not there")
	}
	if body, ok := b.Get("docker-ss"); !ok || body != "one" {
		t.Errorf("Get gives the first: %q", body)
	}
	if all := b.All("docker-ss"); len(all) != 2 || all[1].Arg != "bbb" {
		t.Errorf("All: %#v", all)
	}
	if m := b.Meta(); m["host"] != "web-1" || m["root"] != "no" {
		t.Errorf("Meta: %v", m)
	}
	errs := b.Errors()
	if errs["ufw-status"] != "ERROR: You need to be root to run this script" || errs["nft-json"] != "Operation not permitted" {
		t.Errorf("Errors: %v", errs)
	}
}

func TestTestdataReads(t *testing.T) {
	data, err := os.ReadFile("testdata/web-1.snapshot")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(string(data))
	if err != nil {
		t.Fatal(err)
	}
	// Writing it back gives the same sections (the comment lines are not kept).
	again, err := Parse(b.String())
	if err != nil || !reflect.DeepEqual(again, b) {
		t.Fatal("testdata does not survive a round trip")
	}
	if !strings.HasPrefix(b.String(), magic+"\n### meta\n") {
		t.Error("String should start with the magic line and the first section")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("# seaward snapshot 1\n### a\nx\n")
	f.Add("# seaward snapshot 1\r\n### a b\r\n ### c\r\n")
	f.Add("# seaward snapshot 1\n### a\n\n\n### b")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, in string) {
		b, err := Parse(in)
		if err != nil {
			return
		}
		again, err := Parse(b.String())
		if err != nil {
			t.Fatalf("reparse failed: %v", err)
		}
		if !reflect.DeepEqual(normal(again), normal(b)) {
			t.Fatalf("round trip changed the bundle:\n%#v\n%#v", b, again)
		}
		// Build must never panic on anything Parse accepts.
		_, _, _ = Build(b)
	})
}

// normal makes nil and empty section lists compare equal.
func normal(b *Bundle) []Section {
	if len(b.Sections) == 0 {
		return nil
	}
	return b.Sections
}

func FuzzRoundTripBodies(f *testing.F) {
	f.Add("name", "arg", "body\n### x\n")
	f.Fuzz(func(t *testing.T, name, arg, body string) {
		// Names and arguments are single words by construction; bodies can be anything.
		if name == "" || strings.ContainsAny(name, " \t\r\n\v\f\u0085 ") || strings.ContainsAny(arg, "\r\n") ||
			strings.TrimSpace(arg) != arg || strings.ContainsFunc(name, isSpaceRune) {
			return
		}
		b := &Bundle{Sections: []Section{{Name: name, Arg: arg, Body: body}, {Name: "next", Body: "x"}}}
		got, err := Parse(b.String())
		if err != nil || !reflect.DeepEqual(got, b) {
			t.Fatalf("got %#v, err %v; want %#v", got, err, b)
		}
	})
}

func isSpaceRune(r rune) bool { return strings.TrimSpace(string(r)) == "" }
