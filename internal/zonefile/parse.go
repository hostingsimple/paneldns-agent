// Package zonefile parses RFC 1035 master files (with the BIND extensions
// the agent meets in practice), strips DNSSEC and private record types
// (spec 7.3), and produces the canonical text and content hash shared with
// the PanelDNS app (spec 7.4, 8.7; docs/PROTOCOL.md).
//
// The parser works on presentation tokens and does not decode every record
// type: rdata is kept as tokens and normalised per type only where the
// canonical form says so. That keeps the rules small enough for the PHP
// side to implement identically.
package zonefile

import (
	"bytes"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Token is one rdata or directive token. Text is the raw presentation text
// with escapes left as written; for a quoted token it is the text between
// the quotes.
type Token struct {
	Text   string
	Quoted bool
}

// RR is one resource record as read from the file.
type RR struct {
	Name  string // absolute owner name in presentation form, trailing dot
	TTL   uint32
	Class string // always "IN" after parsing
	Type  string // upper case mnemonic or TYPEnnn
	Data  []Token
	File  string
	Line  int
}

// Options controls Parse.
type Options struct {
	// Origin is the zone apex, absolute or not; a trailing dot is added.
	Origin string
	// File is the name used in error messages.
	File string
	// IncludeDir resolves relative $INCLUDE paths. With ReadFile nil,
	// $INCLUDE is refused.
	IncludeDir string
	// IncludeRoot is prefixed to absolute $INCLUDE paths (a chroot).
	IncludeRoot string
	// ReadFile reads an $INCLUDE file. nil refuses $INCLUDE.
	ReadFile func(name string) ([]byte, error)
	// MaxRecords stops parsing beyond this many records (0 = no limit).
	MaxRecords int
}

// MaxIncludeDepth bounds nested $INCLUDE.
const MaxIncludeDepth = 8

// Error is a parse error with its position.
type Error struct {
	File string
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
}

type parser struct {
	opt        Options
	rrs        []RR
	defaultTTL int64 // $TTL, -1 when unset
	lastTTL    int64 // last explicit TTL, -1 when unset
}

// Parse reads a master file and returns its records in file order.
func Parse(data []byte, opt Options) ([]RR, error) {
	origin, err := absName(opt.Origin)
	if err != nil {
		return nil, fmt.Errorf("origin: %w", err)
	}
	p := &parser{opt: opt, defaultTTL: -1, lastTTL: -1}
	if err := p.parse(data, opt.File, origin, 0); err != nil {
		return nil, err
	}
	return p.rrs, nil
}

func absName(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty name")
	}
	if !endsWithDot(s) {
		s += "."
	}
	return s, nil
}

// endsWithDot reports whether s ends in an unescaped dot.
func endsWithDot(s string) bool {
	if !strings.HasSuffix(s, ".") {
		return false
	}
	// Count the backslashes before the final dot.
	n := 0
	for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 0
}

func (p *parser) parse(data []byte, file, origin string, depth int) error {
	lines, err := lex(data, file)
	if err != nil {
		return err
	}
	lastOwner := ""
	for _, ln := range lines {
		if len(ln.toks) == 0 {
			continue
		}
		errf := func(format string, a ...any) error {
			return &Error{File: file, Line: ln.line, Msg: fmt.Sprintf(format, a...)}
		}
		first := ln.toks[0]
		if !ln.indented && !first.Quoted && strings.HasPrefix(first.Text, "$") {
			switch strings.ToUpper(first.Text) {
			case "$ORIGIN":
				if len(ln.toks) != 2 {
					return errf("$ORIGIN takes one name")
				}
				o, err := expandName(ln.toks[1].Text, origin)
				if err != nil {
					return errf("$ORIGIN: %v", err)
				}
				origin = o
			case "$TTL":
				if len(ln.toks) != 2 {
					return errf("$TTL takes one value")
				}
				ttl, err := ParseTTL(ln.toks[1].Text)
				if err != nil {
					return errf("$TTL: %v", err)
				}
				p.defaultTTL = int64(ttl)
			case "$INCLUDE":
				if p.opt.ReadFile == nil {
					return errf("$INCLUDE is not allowed here")
				}
				if depth >= MaxIncludeDepth {
					return errf("$INCLUDE nested too deep")
				}
				if len(ln.toks) < 2 || len(ln.toks) > 3 {
					return errf("$INCLUDE takes a file name and an optional origin")
				}
				name := ln.toks[1].Text
				if !path.IsAbs(name) {
					name = path.Join(p.opt.IncludeDir, name)
				} else if p.opt.IncludeRoot != "" {
					name = path.Join(p.opt.IncludeRoot, name)
				}
				incOrigin := origin
				if len(ln.toks) == 3 {
					incOrigin, err = expandName(ln.toks[2].Text, origin)
					if err != nil {
						return errf("$INCLUDE origin: %v", err)
					}
				}
				b, err := p.opt.ReadFile(name)
				if err != nil {
					return errf("$INCLUDE %s: %v", name, err)
				}
				// The included file's origin changes stay inside it
				// (RFC 1035 section 5.1).
				if err := p.parse(b, name, incOrigin, depth+1); err != nil {
					return err
				}
			case "$GENERATE":
				return errf("$GENERATE needs named-compilezone, which expands it")
			default:
				return errf("unknown directive %s", first.Text)
			}
			continue
		}

		toks := ln.toks
		var owner string
		if ln.indented {
			if lastOwner == "" {
				return errf("record without an owner name")
			}
			owner = lastOwner
		} else {
			if first.Quoted {
				return errf("owner name may not be quoted")
			}
			owner, err = expandName(first.Text, origin)
			if err != nil {
				return errf("owner: %v", err)
			}
			toks = toks[1:]
		}
		lastOwner = owner

		ttl := int64(-1)
		class := ""
		for len(toks) > 0 && !toks[0].Quoted {
			t := toks[0].Text
			if ttl < 0 && isTTL(t) {
				v, err := ParseTTL(t)
				if err != nil {
					return errf("TTL: %v", err)
				}
				ttl = int64(v)
				toks = toks[1:]
				continue
			}
			if class == "" && isClass(t) {
				class = strings.ToUpper(t)
				toks = toks[1:]
				continue
			}
			break
		}
		if len(toks) == 0 {
			return errf("record has no type")
		}
		if toks[0].Quoted {
			return errf("record type may not be quoted")
		}
		typ := strings.ToUpper(toks[0].Text)
		if !validType(typ) {
			return errf("unknown record type or bad token %q", toks[0].Text)
		}
		data := toks[1:]
		if class == "" {
			class = "IN"
		}
		if class != "IN" {
			return errf("class %s is not supported (only IN)", class)
		}
		if ttl >= 0 {
			p.lastTTL = ttl
		} else if p.defaultTTL >= 0 {
			ttl = p.defaultTTL
		} else if p.lastTTL >= 0 {
			ttl = p.lastTTL
		} else if typ == "SOA" && len(data) == 7 {
			// No $TTL and no TTL on the SOA: BIND uses the SOA minimum.
			v, err := ParseTTL(data[6].Text)
			if err != nil {
				return errf("SOA minimum: %v", err)
			}
			ttl = int64(v)
			p.lastTTL = ttl
		} else {
			return errf("no TTL for this record and no $TTL before it")
		}
		p.rrs = append(p.rrs, RR{
			Name: owner, TTL: uint32(ttl), Class: class, Type: typ,
			Data: data, File: file, Line: ln.line,
		})
		if p.opt.MaxRecords > 0 && len(p.rrs) > p.opt.MaxRecords {
			return errf("more than %d records", p.opt.MaxRecords)
		}
	}
	return nil
}

// expandName makes name absolute against origin and resolves "@".
func expandName(name, origin string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	if name == "@" {
		return origin, nil
	}
	if endsWithDot(name) {
		return name, nil
	}
	if origin == "." {
		return name + ".", nil
	}
	return name + "." + origin, nil
}

func isClass(t string) bool {
	switch strings.ToUpper(t) {
	case "IN", "CH", "CS", "HS", "NONE", "ANY":
		return true
	}
	u := strings.ToUpper(t)
	if strings.HasPrefix(u, "CLASS") && len(u) > 5 {
		_, err := strconv.ParseUint(u[5:], 10, 16)
		return err == nil
	}
	return false
}

func validType(t string) bool {
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "TYPE") && len(t) > 4 {
		_, err := strconv.ParseUint(t[4:], 10, 16)
		return err == nil
	}
	c := t[0]
	if c < 'A' || c > 'Z' {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return !isClass(t)
}

func isTTL(t string) bool {
	return t != "" && t[0] >= '0' && t[0] <= '9'
}

// MaxTTL is the largest TTL accepted (RFC 2181 section 8).
const MaxTTL = 1<<31 - 1

// ParseTTL parses a TTL in seconds or BIND units (1w2d3h4m5s, any case).
func ParseTTL(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	if n, err := strconv.ParseUint(s, 10, 64); err == nil {
		if n > MaxTTL {
			return 0, fmt.Errorf("TTL %s too large", s)
		}
		return uint32(n), nil
	}
	var total uint64
	num := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			num += string(c)
			continue
		}
		if num == "" {
			return 0, fmt.Errorf("bad TTL %q", s)
		}
		n, err := strconv.ParseUint(num, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("bad TTL %q", s)
		}
		var mul uint64
		switch c | 0x20 {
		case 'w':
			mul = 604800
		case 'd':
			mul = 86400
		case 'h':
			mul = 3600
		case 'm':
			mul = 60
		case 's':
			mul = 1
		default:
			return 0, fmt.Errorf("bad TTL unit in %q", s)
		}
		total += n * mul
		num = ""
		if total > MaxTTL {
			return 0, fmt.Errorf("TTL %s too large", s)
		}
	}
	if num != "" {
		return 0, fmt.Errorf("bad TTL %q: number without unit after units", s)
	}
	return uint32(total), nil
}

// lexLine is one logical line: tokens joined across parentheses.
type lexLine struct {
	toks     []Token
	indented bool // the line started with white space (owner omitted)
	line     int  // first physical line
}

func lex(data []byte, file string) ([]lexLine, error) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	var out []lexLine
	cur := lexLine{line: 1}
	lineNo := 1
	depth := 0
	startOfLine := true
	i := 0
	errAt := func(msg string) error { return &Error{File: file, Line: lineNo, Msg: msg} }
	flush := func() {
		if len(cur.toks) > 0 {
			out = append(out, cur)
		}
		cur = lexLine{line: lineNo}
	}
	for i < len(data) {
		c := data[i]
		switch {
		case c == '\n':
			lineNo++
			i++
			if depth == 0 {
				flush()
				startOfLine = true
			}
			continue
		case c == ' ' || c == '\t' || c == '\r':
			if startOfLine && depth == 0 && len(cur.toks) == 0 {
				cur.indented = true
			}
			i++
			continue
		case c == ';':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		case c == '(':
			depth++
			i++
			startOfLine = false
			continue
		case c == ')':
			if depth == 0 {
				return nil, errAt("unbalanced ')'")
			}
			depth--
			i++
			continue
		case c == '"':
			i++
			start := i
			for i < len(data) && data[i] != '"' {
				if data[i] == '\\' {
					i++
				}
				if i < len(data) && data[i] == '\n' {
					return nil, errAt("newline inside a quoted string")
				}
				i++
			}
			if i >= len(data) {
				return nil, errAt("unterminated quoted string")
			}
			cur.toks = append(cur.toks, Token{Text: string(data[start:i]), Quoted: true})
			i++
			startOfLine = false
			continue
		}
		start := i
		for i < len(data) {
			c := data[i]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' || c == '(' || c == ')' || c == '"' {
				break
			}
			if c == '\\' {
				i++
				if i >= len(data) || data[i] == '\n' {
					return nil, errAt("backslash at end of line")
				}
			}
			i++
		}
		if startOfLine && depth == 0 && len(cur.toks) == 0 && !cur.indented {
			cur.line = lineNo
		}
		cur.toks = append(cur.toks, Token{Text: string(data[start:i])})
		startOfLine = false
	}
	if depth != 0 {
		return nil, errAt("unbalanced '(' at end of file")
	}
	flush()
	return out, nil
}
