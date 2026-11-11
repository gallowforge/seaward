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
	// Ports that hang on rules nobody could read, on a chain that was not followed or on senders
	// nobody asked are not spelled out one by one: the reason is the same for all of them and is
	// said once, here.
	said := map[string]bool{}
	sw := 10
	switch {
	case len(r.Unfollowed) > 0:
		sw = 14
	case len(r.Partial) > 0:
		sw = 11
	}
	first := true
	for i, list := range [][]string{r.Unread, r.Unfollowed, r.Partial} {
		for j, u := range list {
			said[u] = true
			label := ""
			if j == 0 {
				label = [...]string{"not read", "not followed", "not asked"}[i]
				if first {
					t.line("")
				}
				first = false
			}
			t.field(0, "33", label, sw, u)
		}
	}
	// quiet says whether everything an undecided port hangs on was just said.
	quiet := func(p *Port) bool {
		if said[p.Why] {
			return true
		}
		n := 0
		for i := range p.Cells {
			if c := &p.Cells[i]; c.Class == "undecided" {
				for _, u := range c.Unknowns {
					if !said[sentence(u)] {
						return false
					}
					n++
				}
			}
		}
		return n > 0
	}

	tool := ""
	if r.Frontend != nil {
		tool = r.Frontend.Tool
	}
	var rest []*Port
	for i := range r.Ports {
		p := &r.Ports[i]
		if !loud(p.Finding) || (p.Finding == Undecided && quiet(p)) {
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
		// Every opening the tool was told to make, whether or not anything answers behind it: the
		// headline counts ports that can be reached, and this is the list they are held against.
		w := max(lw, len(tool)+9)
		lines := wrapList(r.Frontend.Allows, t.w-w)
		if len(lines) == 0 {
			lines = []string{"empty"}
		}
		t.lines(0, "2", tool+"'s list", w, lines)
	}
	for _, n := range r.Notes {
		t.field(0, "2", "note", lw, n)
	}
	t.line("")
	for _, ln := range balance(r.Caveat, t.w) {
		t.line(t.paint("2", ln))
	}
	if o.Hint != "" && len(r.Ports) > 0 {
		// A command is there to be copied, so it is never broken: too long to stand beside its
		// introduction, it takes a line of its own.
		hint := strings.ReplaceAll(o.Hint, "PORT", fmt.Sprint(r.Ports[0].Port))
		const lead = "To follow a packet rule by rule:"
		if len(lead)+1+utf8.RuneCountInString(hint) <= t.w {
			t.line(t.paint("2", lead+" ") + hint)
		} else {
			t.line(t.paint("2", lead))
			t.line("  " + hint)
		}
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
		t.para(0, p.Why)
		t.para(0, "Sent from outside all the same, a packet ends like this:")
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
	for _, ln := range fill(s, t.w-indent) {
		t.line(strings.Repeat(" ", indent) + ln)
	}
}

// field writes "label  value", the value wrapped and hanging under itself.
func (t *writer) field(indent int, code, label string, lw int, value string) {
	t.lines(indent, code, label, lw, fill(value, t.w-indent-lw))
}

// lines writes a label and, beside it, lines that are already broken.
func (t *writer) lines(indent int, code, label string, lw int, lines []string) {
	for i, ln := range lines {
		head := strings.Repeat(" ", indent+lw)
		if i == 0 {
			head = strings.Repeat(" ", indent) + t.paint(code, label) + strings.Repeat(" ", max(1, lw-len(label)))
		}
		t.line(head + ln)
	}
}

// rule writes a rule as its owner prints it. A long rule breaks before an option and continues two
// columns in, so it can still be told from the next line.
func (t *writer) rule(indent int, code, text string) {
	for i, ln := range wrapRule(text, t.w-indent-2) {
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
	if p.Reach != "" && p.Reach != "nobody" && p.Reach != nobodyAsked && p.Reach != "not known" && !strings.Contains(p.Title, p.Reach) {
		t.lines(2, "2", "reached by", lw, wrapNames(p.Reach, t.w-2-lw))
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
// port, a long service name is cut short, and who reaches the port, which is never cut, goes on
// under itself. A column nobody has anything to say in is left out.
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
	measure := func(brief bool) {
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
	measure(false)
	last := 3
	if tool != "" {
		if total(4) > t.w {
			measure(true)
		}
		if total(4) <= t.w {
			last = 4
		} else {
			measure(false)
		}
	}
	// Still too wide: the service name gives way first, then who reaches it takes more lines.
	for _, i := range []int{2, 3} {
		if over := total(last) - t.w; over > 0 {
			w[i] = min(w[i], max(reachWrap, w[i]-over))
		}
	}
	write := func(r row, codes [5]string) {
		var b strings.Builder
		reach := wrapNames(r[3], w[3])
		if len(reach) == 0 {
			reach = []string{""}
		}
		pad, col, at := 2, 0, 0 // col is how far the line has got, at where its reach column starts
		for _, i := range cols {
			if i > last {
				break
			}
			c := clip(r[i], w[i])
			if i == 3 {
				c, at = reach[0], col+pad
			}
			b.WriteString(strings.Repeat(" ", pad))
			b.WriteString(t.paint(codes[i], c))
			col += pad + utf8.RuneCountInString(c)
			pad = w[i] + 2 - utf8.RuneCountInString(c)
		}
		t.line(b.String())
		for _, ln := range reach[1:] {
			t.line(strings.Repeat(" ", at) + t.paint(codes[3], ln))
		}
	}
	write(head, [5]string{"2", "2", "2", "2", "2"})
	for _, r := range rows {
		write(r, [5]string{tint(r[0]), "", "", "", ""})
		if last == 3 && r[4] != "" {
			in := 2 + w[0] + 2 + w[1] + 2
			t.lines(in, "2", tool+":", len(tool)+2, wrapNames(r[4], t.w-in-len(tool)-2))
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
		// A packet that reaches nothing, whether a chain that was not followed drops it or the
		// followed rules have the last word, is told by how those rules end it.
		end := c.Class
		if c.Otherwise == "closed" || c.Otherwise == "rejected" {
			end, code = c.Otherwise, "2"
		}
		t.line("")
		for i, h := range g.heads {
			label := ""
			if i == 0 {
				label = outcome(end)
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
			lead := "It could end either way: "
			if end != c.Class {
				lead = "It does not get through either way: "
			}
			t.para(2, lead+strings.Join(words, ", or ")+".")
		}
		for _, u := range c.Unknowns {
			if sentence(u) != c.Why { // already said, as the reason itself
				t.field(2, "33", "hangs on", 10, u)
			}
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
		lead := num + s.Hook + strings.Repeat(" ", hw+2-len(s.Hook))
		pre := lead + wh + strings.Repeat(" ", max(2, ww+2-len(wh)))
		// What happened stands beside the chain. When it does not fit there, a step outside any
		// chain (routing, delivery) takes the chain's column as well, and in a terminal too narrow
		// to wrap it beside the chain it goes on lines of its own under it.
		col, under := utf8.RuneCountInString(pre), false
		switch {
		case utf8.RuneCountInString(s.Effect) <= t.w-col:
		case wh == "":
			pre, col = lead, utf8.RuneCountInString(lead)
		case t.w-col < minWrap:
			col, under = utf8.RuneCountInString(lead), true
			t.line(t.paint("2", num) + t.paint(code, lead[len(num):]+wh))
		}
		for j, ln := range fill(s.Effect, t.w-col) {
			if j == 0 && !under {
				t.line(t.paint("2", num) + t.paint(code, pre[len(num):]+ln))
				continue
			}
			t.line(strings.Repeat(" ", col) + t.paint(code, ln))
		}
		if s.Rule != "" {
			t.rule(len(num)+hw+2, ruleCode, s.Rule)
		}
	}
}

// fill wraps like wrap, and a paragraph that would end on one stray word takes the word before it
// down as well. Running text is set this way, so that paragraphs under one another keep one edge.
func fill(s string, width int) []string {
	lines := wrap(s, width)
	n := len(lines)
	if n < 2 || strings.Contains(lines[n-1], " ") {
		return lines
	}
	prev := lines[n-2]
	i := strings.LastIndexByte(prev, ' ')
	if i < 0 || !strings.Contains(prev[:i], " ") {
		return lines
	}
	last := prev[i+1:] + " " + lines[n-1]
	if utf8.RuneCountInString(last) > max(width, minWrap) {
		return lines
	}
	lines[n-2], lines[n-1] = prev[:i], last
	return lines
}

// wrapList sets a list out with commas and breaks it between entries only, so that an entry of
// several words ("9100/tcp from 198.51.100.0/24") is never cut in two.
func wrapList(items []string, width int) []string {
	const tie = "\x00"
	tied := make([]string, len(items))
	for i, it := range items {
		tied[i] = strings.Join(strings.Fields(it), tie)
	}
	lines := wrap(strings.Join(tied, ", "), width)
	for i := range lines {
		lines[i] = strings.ReplaceAll(lines[i], tie, " ")
	}
	return lines
}

// wrapNames breaks who reaches a port ("the local network, 198.51.100.8, 198.51.100.16 and 13
// more only") after a comma or before the "and", so that a name and the count at the end stay
// whole. A name longer than the column breaks between its words after all, and one word longer
// than the column, as a whole IPv6 address in a narrow terminal is, after one of its colons:
// nothing is cut off and no line runs past the edge.
func wrapNames(s string, width int) []string {
	if width < reachWrap {
		width = reachWrap
	}
	var names []string
	for i, w := range strings.Fields(s) {
		if i == 0 || w == "and" || strings.HasSuffix(names[len(names)-1], ",") {
			names = append(names, w)
		} else {
			names[len(names)-1] += " " + w
		}
	}
	var out []string
	line, n := "", 0
	for _, name := range names {
		nn := utf8.RuneCountInString(name)
		if line != "" && n+1+nn <= width {
			line, n = line+" "+name, n+1+nn
			continue
		}
		if line != "" {
			out = append(out, line)
		}
		parts := wrapWords(name, width)
		out = append(out, parts[:len(parts)-1]...)
		line = parts[len(parts)-1]
		n = utf8.RuneCountInString(line)
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// wrapWords is wrap for a column that has to hold whatever it is given: a word longer than the
// column is cut into pieces, and the words after it go on behind the last piece.
func wrapWords(s string, width int) []string {
	var out []string
	line, n := "", 0
	for _, w := range strings.Fields(s) {
		for i, piece := range splitWord(w, width) {
			pn := utf8.RuneCountInString(piece)
			if i == 0 && line != "" && n+1+pn <= width {
				line, n = line+" "+piece, n+1+pn
				continue
			}
			if line != "" {
				out = append(out, line)
			}
			line, n = piece, pn
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// splitWord cuts a word that is longer than width into pieces that fit: after the last colon,
// dot, slash or hyphen that still fits, or where the room ends.
func splitWord(w string, width int) []string {
	var out []string
	r := []rune(w)
	for len(r) > width {
		at := width
		for i := width; i > width/2; i-- {
			if strings.ContainsRune(":./-", r[i-1]) {
				at = i
				break
			}
		}
		out = append(out, string(r[:at]))
		r = r[at:]
	}
	return append(out, string(r))
}

// balance wraps like wrap, then narrows the lines as far as it can without adding one, so that
// they come out about equally long. The two sentences that stand alone are set this way: the
// verdict at the top and the caveat at the foot.
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

// wrapRule breaks a rule like wrap, but keeps an option with what belongs to it where there is
// room: "-j ACCEPT" stays whole, and so does "! -i eth0". A rule written without options, as nft
// writes them, breaks between words.
func wrapRule(s string, width int) []string {
	if width < minWrap {
		width = minWrap
	}
	words := strings.Fields(s)
	option := func(w string) bool {
		return len(w) > 1 && w[0] == '-' && (w[1] == '-' || w[1] >= 'a' && w[1] <= 'z' || w[1] >= 'A' && w[1] <= 'Z')
	}
	var groups []string
	for i, w := range words {
		starts := i == 0
		switch {
		case w == "!":
			starts = starts || i+1 < len(words) && option(words[i+1])
		case option(w):
			starts = starts || words[i-1] != "!"
		}
		if starts {
			groups = append(groups, w)
		} else {
			groups[len(groups)-1] += " " + w
		}
	}
	var out []string
	line, n := "", 0
	for _, g := range groups {
		gn := utf8.RuneCountInString(g)
		if line != "" && n+1+gn <= width {
			line, n = line+" "+g, n+1+gn
			continue
		}
		if line != "" {
			out = append(out, line)
		}
		// an option with more behind it than a line holds breaks between its words after all
		parts := wrap(g, width)
		out = append(out, parts[:len(parts)-1]...)
		line = parts[len(parts)-1]
		n = utf8.RuneCountInString(line)
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// minWrap is the narrowest column text is wrapped to, however little room is left. reachWrap is
// the same for a column of the table of ports, where the narrowest terminal leaves less.
const (
	minWrap   = 24
	reachWrap = 12
)

// wrap breaks text between words so that no line is longer than width, unless one word is.
func wrap(s string, width int) []string {
	if width < minWrap {
		width = minWrap
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
