package scan

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// TextOptions says how a report is written for a terminal.
type TextOptions struct {
	Color bool   // ANSI colours; colour is only ever used for state
	Width int    // columns to wrap at; 0 means 100
	Hint  string // the command that shows a packet's path, with PORT where the port goes
}

// Text writes the report for a terminal: the verdict, the ports that need a look in full, the
// rest as a table, then what was looked from and what was not seen.
func Text(r *Report, o TextOptions) string {
	t := newWriter(o)
	t.line(t.paint("1", "seaward") + "  " + r.Host)
	t.line("")
	for _, ln := range balance(r.Headline, t.w) {
		t.line(t.paint("1", ln))
	}
	if r.Detail != "" {
		t.para(0, r.Detail)
	}
	// Ports that hang on rules nobody could read are not spelled out one by one: the reason is the
	// same for all of them and is said once, here.
	unread := map[string]bool{}
	for i, u := range r.Unread {
		unread[u] = true
		label := ""
		if i == 0 {
			t.line("")
			label = "not read"
		}
		t.field(0, "33", label, 10, u)
	}

	tool := ""
	if r.Frontend != nil {
		tool = r.Frontend.Tool
	}
	var rest []*Port
	for i := range r.Ports {
		p := &r.Ports[i]
		if !loud(p.Finding) || (p.Finding == Undecided && unread[p.Why]) {
			rest = append(rest, p)
			continue
		}
		t.line("")
		t.block(p)
	}
	if len(rest) > 0 {
		t.line("")
		t.table(rest, tool)
	}

	t.line("")
	const lw = 12
	for i, v := range r.Vantages {
		label := ""
		if i == 0 {
			label = "seen from"
		}
		t.field(0, "2", label, lw, v.Label)
	}
	if r.Frontend != nil {
		allows := strings.Join(r.Frontend.Allows, ", ")
		if allows == "" {
			allows = "nothing"
		}
		t.field(0, "2", tool+" allows", max(lw, len(tool)+9), allows)
	}
	for _, n := range r.Notes {
		t.field(0, "2", "note", lw, n)
	}
	t.line("")
	for _, ln := range balance(r.Caveat, t.w) {
		t.line(t.paint("2", ln))
	}
	if o.Hint != "" && len(r.Ports) > 0 {
		hint := strings.ReplaceAll(o.Hint, "PORT", fmt.Sprint(r.Ports[0].Port))
		t.line(t.paint("2", "To follow a packet rule by rule: ") + hint)
	}
	return t.sb.String()
}

// WhyText writes the path of every packet that was sent at one port.
func WhyText(p *Port, o TextOptions) string {
	t := newWriter(o)
	head := t.paint("1", fmt.Sprintf("%s %d", p.Proto, p.Port))
	if p.Service != "" {
		head += "  " + p.Service
	}
	t.line(head)
	t.para(0, p.Title)
	if p.Finding == Local && p.Why != "" {
		t.para(0, p.Why+" Sent from outside all the same, a packet ends like this:")
	}
	t.cells(p.Cells)
	return t.sb.String()
}

// TraceText writes the path of packets from one sender, as Trace returns them.
func TraceText(proto string, port uint16, cells []Cell, o TextOptions) string {
	t := newWriter(o)
	t.line(t.paint("1", fmt.Sprintf("%s %d", proto, port)))
	t.cells(cells)
	return t.sb.String()
}

// loud findings are written out in full; the others take one line each.
func loud(finding string) bool {
	switch finding {
	case Exposed, Undecided, Shadowed, Dead:
		return true
	}
	return false
}

// tint is the colour of a finding.
func tint(finding string) string {
	switch finding {
	case Exposed:
		return "1;31"
	case Undecided, Shadowed, Dead:
		return "33"
	case Open:
		return "32"
	case Limited:
		return "36"
	}
	return "2"
}

type writer struct {
	sb    strings.Builder
	color bool
	w     int
}

func newWriter(o TextOptions) *writer {
	w := o.Width
	if w <= 0 {
		w = 100
	}
	if w < 60 {
		w = 60
	}
	return &writer{color: o.Color, w: w}
}

func (t *writer) paint(code, s string) string {
	if !t.color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (t *writer) line(s string) {
	t.sb.WriteString(strings.TrimRight(s, " "))
	t.sb.WriteByte('\n')
}

// para writes running text, wrapped, behind an indent.
func (t *writer) para(indent int, s string) {
	for _, ln := range balance(s, t.w-indent) {
		t.line(strings.Repeat(" ", indent) + ln)
	}
}

// field writes "label  value", the value wrapped and hanging under itself.
func (t *writer) field(indent int, code, label string, lw int, value string) {
	for i, ln := range balance(value, t.w-indent-lw) {
		head := strings.Repeat(" ", indent+lw)
		if i == 0 {
			head = strings.Repeat(" ", indent) + t.paint(code, label) + strings.Repeat(" ", max(1, lw-len(label)))
		}
		t.line(head + ln)
	}
}

// rule writes a rule as its owner prints it. A long rule breaks between words and continues two
// columns in, so it can still be told from the next line.
func (t *writer) rule(indent int, code, text string) {
	for i, ln := range wrap(text, t.w-indent-2) {
		pre := strings.Repeat(" ", indent)
		if i > 0 {
			pre += "  "
		}
		t.line(pre + t.paint(code, ln))
	}
}

// where is the short name of the chain a step happened in: "nat DOCKER", "ip6 filter INPUT".
func where(s *Step) string {
	if s == nil || s.Table == "" {
		return ""
	}
	tbl := s.Table
	if s.Family != "" && s.Family != "ip" {
		tbl = s.Family + " " + tbl
	}
	return tbl + " " + s.Chain
}

func (t *writer) block(p *Port) {
	head := t.paint(tint(p.Finding), strings.ToUpper(p.Finding)) + "  " + t.paint("1", fmt.Sprintf("%s %d", p.Proto, p.Port))
	if p.Service != "" {
		head += "  " + p.Service
	}
	t.line(head)
	t.para(2, p.Title)
	const lw = 12
	if p.Reach != "" && p.Reach != "nobody" && p.Reach != "not known" && !strings.Contains(p.Title, p.Reach) {
		t.field(2, "2", "reached by", lw, p.Reach)
	}
	if p.Why != "" {
		t.field(2, "2", "why", lw, p.Why)
	}
	// A rule says what it does in its own words; a step without one (a chain's policy) is spelled out.
	step := func(label string, s *Step) {
		if s.Rule == "" {
			t.field(2, "2", label, lw, strings.TrimLeft(where(s)+", "+s.Effect, ", "))
			return
		}
		t.field(2, "2", label, lw, where(s))
		t.rule(2+lw, "", s.Rule)
	}
	if p.Rewrite != nil {
		step("rewritten", p.Rewrite)
	}
	if p.Deciding != nil {
		step("decided by", p.Deciding)
	}
}

// table writes the quiet ports, one per line. Too wide for the terminal, a container gives up its
// image name first; after that, what the firewall tool says moves to a line of its own under the
// port. A column nobody has anything to say in is left out.
func (t *writer) table(ports []*Port, tool string) {
	type row [5]string
	head := row{"", "PORT", "SERVICE", "REACHED BY", ""}
	if tool != "" {
		head[4] = strings.ToUpper(tool) + " SAYS"
	}
	cols := []int{0, 1, 3, 4}
	for _, p := range ports {
		if p.Service != "" {
			cols = []int{0, 1, 2, 3, 4}
			break
		}
	}
	var rows []row
	var w [5]int
	fill := func(brief bool) {
		rows, w = rows[:0], [5]int{}
		for _, p := range ports {
			r := row{p.Finding, fmt.Sprintf("%s %d", p.Proto, p.Port), p.Service, p.Reach, ""}
			if brief {
				r[2] = noImage(r[2])
			}
			if r[2] == "" {
				r[2] = "-"
			}
			if tool != "" {
				r[4] = p.Stated
			}
			rows = append(rows, r)
		}
		for _, r := range append([]row{head}, rows...) {
			for i, c := range r {
				w[i] = max(w[i], utf8.RuneCountInString(c))
			}
		}
	}
	// total is the width of a line that ends with column last.
	total := func(last int) int {
		n := 0
		for _, i := range cols {
			if i <= last {
				n += 2 + w[i]
			}
		}
		return n
	}
	fill(false)
	last := 3
	if tool != "" {
		if total(4) > t.w {
			fill(true)
		}
		if total(4) <= t.w {
			last = 4
		} else {
			fill(false)
		}
	}
	// Still too wide: the service name gives way first, then who reaches it.
	for _, i := range []int{2, 3} {
		if over := total(last) - t.w; over > 0 {
			w[i] = max(12, w[i]-over)
		}
	}
	write := func(r row, codes [5]string) {
		var b strings.Builder
		pad := 2
		for _, i := range cols {
			if i > last {
				break
			}
			c := clip(r[i], w[i])
			b.WriteString(strings.Repeat(" ", pad))
			b.WriteString(t.paint(codes[i], c))
			pad = w[i] + 2 - utf8.RuneCountInString(c)
		}
		t.line(b.String())
	}
	write(head, [5]string{"2", "2", "2", "2", "2"})
	for _, r := range rows {
		write(r, [5]string{tint(r[0]), "", "", "", ""})
		if last == 3 && r[4] != "" {
			t.field(2+w[0]+2+w[1]+2, "2", tool+":", len(tool)+2, r[4])
		}
	}
}

// noImage drops the image from a container's name: "container db (postgres:16)" becomes
// "container db".
func noImage(s string) string {
	if i := strings.LastIndex(s, " ("); i > 0 && strings.HasSuffix(s, ")") && strings.Contains(s, "container ") {
		return s[:i]
	}
	return s
}

// clip shortens s to n characters, the last three of them dots.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimRight(string(r[:max(1, n-3)]), " ") + "..."
}

// outcome says how a packet ended, in the words of the person who sent it.
func outcome(class string) string {
	switch class {
	case "open":
		return "gets through"
	case "forwarded":
		return "passed on"
	case "closed":
		return "no listener"
	case "rejected":
		return "refused"
	case "filtered":
		return "dropped"
	case "undecided":
		return "not decided"
	}
	return class
}

func (t *writer) cells(cells []Cell) {
	type group struct {
		c     *Cell
		heads []string
	}
	var groups []*group
	byKey := map[string]*group{}
	for i := range cells {
		c := &cells[i]
		var k strings.Builder
		k.WriteString(c.Dst + "\x00" + c.Class + "\x00" + c.Why)
		for _, s := range c.Steps {
			k.WriteString("\x00" + string(s.Kind) + "|" + s.Family + "|" + s.Table + "|" + s.Chain + "|" + s.Rule + "|" + s.Effect)
		}
		g := byKey[k.String()]
		if g == nil {
			g = &group{c: c}
			byKey[k.String()] = g
			groups = append(groups, g)
		}
		from := c.Src
		if c.From != "" && c.From != c.Src {
			from = c.From + " (" + c.Src + ")"
		}
		g.heads = append(g.heads, from+" -> "+c.Dst)
	}
	const lw = 14
	for _, g := range groups {
		c := g.c
		code := "2"
		switch {
		case c.Class == "undecided":
			code = "33"
		case (c.Class == "open" || c.Class == "forwarded") && c.Allowed != nil && !*c.Allowed:
			code = "1;31"
		case c.Class == "open" || c.Class == "forwarded":
			code = "32"
		}
		t.line("")
		for i, h := range g.heads {
			label := ""
			if i == 0 {
				label = outcome(c.Class)
			}
			t.field(0, code, label, lw, h)
		}
		if c.Why != "" {
			t.para(2, c.Why)
		}
		if len(c.Possible) > 1 {
			var words []string
			for _, p := range c.Possible {
				words = append(words, outcome(p))
			}
			t.para(2, "It could end either way: "+strings.Join(words, ", or ")+".")
		}
		for _, u := range c.Unknowns {
			t.field(2, "33", "hangs on", 10, u)
		}
		t.steps(c)
	}
}

func (t *writer) steps(c *Cell) {
	hw, ww := 0, 0
	for i := range c.Steps {
		hw = max(hw, len(c.Steps[i].Hook))
		ww = max(ww, min(len(where(&c.Steps[i])), 30))
	}
	if len(c.Steps) > 0 {
		t.line("")
	}
	for i := range c.Steps {
		s := &c.Steps[i]
		code, ruleCode := "", "2"
		switch {
		case s.Kind == "jump":
			code = "2"
		case s.Decisive || strings.HasPrefix(s.Effect, "destination becomes"):
			code, ruleCode = "1", ""
		case s.Kind == "rule" || s.Kind == "policy":
			ruleCode = ""
		}
		// The steps that settle the answer carry a mark, so they stand out without colour too.
		num := fmt.Sprintf("%3d  ", i+1)
		if s.Decisive || strings.HasPrefix(s.Effect, "destination becomes") {
			num = fmt.Sprintf(">%2d  ", i+1)
		}
		wh := where(s)
		pre := num + s.Hook + strings.Repeat(" ", hw+2-len(s.Hook)) + wh + strings.Repeat(" ", max(2, ww+2-len(wh)))
		for j, ln := range wrap(s.Effect, t.w-utf8.RuneCountInString(pre)) {
			if j == 0 {
				t.line(t.paint("2", num) + t.paint(code, pre[len(num):]+ln))
				continue
			}
			t.line(strings.Repeat(" ", utf8.RuneCountInString(pre)) + t.paint(code, ln))
		}
		if s.Rule != "" {
			t.rule(len(num)+hw+2, ruleCode, s.Rule)
		}
	}
}

// balance wraps like wrap, then narrows the lines as far as it can without adding one, so that a
// paragraph does not end on one stray word.
func balance(s string, width int) []string {
	lines := wrap(s, width)
	if len(lines) < 2 {
		return lines
	}
	for w := (utf8.RuneCountInString(s) + len(lines) - 1) / len(lines); w < width; w++ {
		if l := wrap(s, w); len(l) == len(lines) {
			return l
		}
	}
	return lines
}

// wrap breaks text between words so that no line is longer than width, unless one word is.
func wrap(s string, width int) []string {
	if width < 24 {
		width = 24
	}
	var out []string
	line, n := "", 0
	for _, w := range strings.Fields(s) {
		wn := utf8.RuneCountInString(w)
		if line != "" && n+1+wn > width {
			out = append(out, line)
			line, n = "", 0
		}
		if line != "" {
			line += " "
			n++
		}
		line += w
		n += wn
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
