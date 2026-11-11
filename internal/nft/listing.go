package nft

// What "nft list ruleset" prints, the listing as text, is read for one thing: the interfaces a
// base chain is attached to. The JSON listing of an older nft (1.0.9 is one) leaves them out
// altogether, and the text of the same version has them:
//
//	type filter hook ingress device "eth0" priority -500; policy accept;
//	type filter hook ingress devices = { eth0, eth1 } priority -300; policy accept;
//
// An ingress or egress chain with no interface sees no packet, and one with an interface nobody
// knows may see any, so the difference decides whole machines.

// textChain is a base chain as the text listing declares it.
type textChain struct {
	hook string
	devs []string // the interfaces it names; none when the declaration names none
}

// textTok is one word of the text listing: a bare word, a string that stood in double quotes, or
// one of the marks { } ; , = that the listing sets apart.
type textTok struct {
	s      string
	quoted bool
}

func (t textTok) is(mark string) bool { return !t.quoted && t.s == mark }

// textTokens cuts the listing into words. A string in double quotes is one word whatever it
// holds: a comment may hold braces and anything else. It ends at the next double quote. The nft
// command takes no double quote inside a string, so it prints none. One put into a comment some
// other way would upset the pairing for the rest of the text; a declaration is then not found,
// and a chain that is not found is not known, which is never read as idle.
func textTokens(text string) []textTok {
	var out []textTok
	for i := 0; i < len(text); {
		switch c := text[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			// A handle or a position, when the listing was asked for them: up to the line's end.
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '"':
			j := i + 1
			for j < len(text) && text[j] != '"' {
				j++
			}
			out = append(out, textTok{s: text[i+1 : j], quoted: true})
			i = j + 1
		case c == '{' || c == '}' || c == ';' || c == ',' || c == '=':
			out = append(out, textTok{s: text[i : i+1]})
			i++
		default:
			j := i
			for j < len(text) && !isTextMark(text[j]) {
				j++
			}
			out = append(out, textTok{s: text[i:j]})
			i = j
		}
	}
	return out
}

func isTextMark(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '#', '"', '{', '}', ';', ',', '=':
		return true
	}
	return false
}

// textKey names a chain of the text listing.
func textKey(family, table, chain string) string { return family + "\x00" + table + "\x00" + chain }

// textChains reads the base chains out of a text listing. A chain with no hook is not in the
// answer, and neither is anything of a listing that breaks off or is not one: what was whole
// before that stands.
func textChains(text string) map[string]textChain {
	toks := textTokens(text)
	out := map[string]textChain{}
	at := func(i int) textTok {
		if i < len(toks) {
			return toks[i]
		}
		return textTok{}
	}
	// skip goes from the word after an opening brace to the word after the brace that closes it.
	skip := func(i int) int {
		for depth := 1; i < len(toks) && depth > 0; i++ {
			switch {
			case toks[i].is("{"):
				depth++
			case toks[i].is("}"):
				depth--
			}
		}
		return i
	}
	for i := 0; i < len(toks); {
		// table <family> <name> {
		if !toks[i].is("table") || !at(i+3).is("{") {
			i++
			continue
		}
		family, table := at(i+1).s, at(i+2).s
		i += 4
		for i < len(toks) && !toks[i].is("}") {
			switch {
			case toks[i].is("chain") && at(i+2).is("{"):
				name := toks[i+1].s
				i += 3
				if at(i).is("comment") && at(i+1).quoted {
					i += 2
				}
				// type <kind> hook <hook> [device "<name>" | devices = { <name>, ... }] priority ... ;
				if at(i).is("type") && at(i+2).is("hook") {
					c := textChain{hook: at(i + 3).s}
					for i += 4; i < len(toks) && !toks[i].is(";") && !toks[i].is("}"); i++ {
						switch {
						case toks[i].is("device"):
							if d := at(i + 1); d.quoted || !isTextMark(firstByte(d.s)) {
								c.devs = append(c.devs, d.s)
								i++
							}
						case toks[i].is("devices") && at(i+1).is("="):
							i += 2
							if !at(i).is("{") {
								c.devs = append(c.devs, at(i).s)
								break
							}
							for i++; i < len(toks) && !toks[i].is("}"); i++ {
								if !toks[i].is(",") {
									c.devs = append(c.devs, toks[i].s)
								}
							}
						}
					}
					// A declaration ends with its priority and a semicolon. One that breaks off
					// before that says nothing: its interface may be what is missing.
					if at(i).is(";") {
						out[textKey(family, table, name)] = c
					}
				}
				i = skip(i)
			case toks[i].is("{"):
				i = skip(i + 1) // a set, a map, a flowtable or another named thing
			default:
				i++
			}
		}
		i++
	}
	return out
}

func firstByte(s string) byte {
	if s == "" {
		return ' '
	}
	return s[0]
}
