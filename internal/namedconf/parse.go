// Package namedconf reads BIND's named.conf, following include statements,
// and finds the primary zones of one view (spec 7.3).
//
// It understands the generic statement grammar (words, quoted strings,
// blocks, ';') and the three comment styles, which is enough for every
// named.conf named accepts, including `named-checkconf -p` output.
package namedconf

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Stmt is one statement: its words and an optional block of statements.
type Stmt struct {
	Args     []string
	Block    []*Stmt
	HasBlock bool
	File     string // host path of the file it came from
	Line     int
}

// Name returns the statement keyword in lower case.
func (s *Stmt) Name() string {
	if len(s.Args) == 0 {
		return ""
	}
	return strings.ToLower(s.Args[0])
}

// Arg returns argument i (0 = keyword) or "".
func (s *Stmt) Arg(i int) string {
	if i < len(s.Args) {
		return s.Args[i]
	}
	return ""
}

// Find returns the first statement in block named name.
func Find(block []*Stmt, name string) *Stmt {
	for _, s := range block {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

// Include is one include statement met while reading.
type Include struct {
	Path     string // host path (chroot applied)
	Readable bool
	Err      string
	Denied   bool // the read failed with "permission denied"
	From     string
	Line     int
}

// Reader reads files; tests replace it.
type Reader func(path string) ([]byte, error)

// Globber expands an include pattern; tests replace it.
type Globber func(pattern string) ([]string, error)

// Loader reads a named.conf and its includes.
type Loader struct {
	ReadFile Reader
	Glob     Globber
	// Chroot is prefixed to every absolute path named itself would open.
	Chroot string
	// MaxDepth bounds nested includes.
	MaxDepth int

	Includes []Include
}

// MaxFileSize caps any one config file.
const MaxFileSize = 32 << 20

// Load parses the file at hostPath (a path on the host, outside any
// chroot) and returns its statements with includes expanded in place. An
// include that can't be read is recorded in l.Includes and skipped; the
// caller decides whether that matters (docs/DECISIONS.md D-02).
func (l *Loader) Load(hostPath string) ([]*Stmt, error) {
	if l.MaxDepth == 0 {
		l.MaxDepth = 16
	}
	b, err := l.ReadFile(hostPath)
	if err != nil {
		return nil, err
	}
	return l.parseFile(b, hostPath, path.Dir(hostPath), 0, map[string]bool{hostPath: true})
}

// HostPath maps a path as named sees it to a host path.
func (l *Loader) HostPath(p string, relativeTo string) string {
	if !strings.HasPrefix(p, "/") {
		return path.Join(relativeTo, p)
	}
	if l.Chroot != "" {
		return path.Join(l.Chroot, p)
	}
	return p
}

func (l *Loader) parseFile(data []byte, file, baseDir string, depth int, seen map[string]bool) ([]*Stmt, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", file, MaxFileSize)
	}
	toks, err := tokenize(data, file)
	if err != nil {
		return nil, err
	}
	p := &stmtParser{toks: toks, file: file}
	stmts, err := p.parseBlock(false)
	if err != nil {
		return nil, err
	}
	return l.expandIncludes(stmts, baseDir, depth, seen)
}

func (l *Loader) expandIncludes(stmts []*Stmt, baseDir string, depth int, seen map[string]bool) ([]*Stmt, error) {
	var out []*Stmt
	for _, s := range stmts {
		if s.Name() == "include" && !s.HasBlock {
			if len(s.Args) != 2 {
				return nil, fmt.Errorf("%s:%d: include takes one file name", s.File, s.Line)
			}
			if depth+1 > l.MaxDepth {
				return nil, fmt.Errorf("%s:%d: includes nested too deep", s.File, s.Line)
			}
			pattern := l.HostPath(s.Args[1], baseDir)
			paths := []string{pattern}
			if strings.ContainsAny(s.Args[1], "*?[") && l.Glob != nil {
				m, err := l.Glob(pattern)
				if err != nil {
					return nil, fmt.Errorf("%s:%d: include pattern: %v", s.File, s.Line, err)
				}
				sort.Strings(m)
				paths = m
			}
			for _, p := range paths {
				if seen[p] {
					return nil, fmt.Errorf("%s:%d: include loop through %s", s.File, s.Line, p)
				}
				inc := Include{Path: p, From: s.File, Line: s.Line}
				b, err := l.ReadFile(p)
				if err != nil {
					inc.Err = err.Error()
					inc.Denied = errors.Is(err, fs.ErrPermission)
					l.Includes = append(l.Includes, inc)
					continue
				}
				inc.Readable = true
				l.Includes = append(l.Includes, inc)
				seen[p] = true
				sub, err := l.parseFile(b, p, baseDir, depth+1, seen)
				delete(seen, p)
				if err != nil {
					return nil, err
				}
				out = append(out, sub...)
			}
			continue
		}
		if s.HasBlock {
			b, err := l.expandIncludes(s.Block, baseDir, depth, seen)
			if err != nil {
				return nil, err
			}
			s.Block = b
		}
		out = append(out, s)
	}
	return out, nil
}

type token struct {
	text   string
	quoted bool
	line   int
}

func tokenize(data []byte, file string) ([]token, error) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	var out []token
	line := 1
	i := 0
	for i < len(data) {
		c := data[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			start := line
			i += 2
			for {
				if i+1 >= len(data) {
					return nil, fmt.Errorf("%s:%d: unterminated /* comment", file, start)
				}
				if data[i] == '\n' {
					line++
				}
				if data[i] == '*' && data[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
		case c == '{' || c == '}' || c == ';':
			out = append(out, token{text: string(c), line: line})
			i++
		case c == '"':
			start := line
			i++
			var sb strings.Builder
			for {
				if i >= len(data) {
					return nil, fmt.Errorf("%s:%d: unterminated string", file, start)
				}
				if data[i] == '\\' && i+1 < len(data) {
					sb.WriteByte(data[i+1])
					i += 2
					continue
				}
				if data[i] == '"' {
					i++
					break
				}
				if data[i] == '\n' {
					line++
				}
				sb.WriteByte(data[i])
				i++
			}
			out = append(out, token{text: sb.String(), quoted: true, line: start})
		default:
			start := i
			for i < len(data) {
				c := data[i]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '{' || c == '}' || c == ';' || c == '"' || c == '#' {
					break
				}
				if c == '/' && i+1 < len(data) && (data[i+1] == '/' || data[i+1] == '*') {
					break
				}
				i++
			}
			out = append(out, token{text: string(data[start:i]), line: line})
		}
	}
	return out, nil
}

type stmtParser struct {
	toks []token
	pos  int
	file string
}

func (p *stmtParser) parseBlock(nested bool) ([]*Stmt, error) {
	var out []*Stmt
	for {
		if p.pos >= len(p.toks) {
			if nested {
				return nil, fmt.Errorf("%s: missing '}' at end of file", p.file)
			}
			return out, nil
		}
		t := p.toks[p.pos]
		if !t.quoted && t.text == "}" {
			if !nested {
				return nil, fmt.Errorf("%s:%d: unexpected '}'", p.file, t.line)
			}
			p.pos++
			return out, nil
		}
		if !t.quoted && t.text == ";" {
			p.pos++ // empty statement
			continue
		}
		s := &Stmt{File: p.file, Line: t.line}
		for p.pos < len(p.toks) {
			t := p.toks[p.pos]
			if !t.quoted && t.text == ";" {
				p.pos++
				break
			}
			if !t.quoted && t.text == "}" {
				// A missing ';' before '}' is tolerated.
				break
			}
			if !t.quoted && t.text == "{" {
				p.pos++
				b, err := p.parseBlock(true)
				if err != nil {
					return nil, err
				}
				s.Block = b
				s.HasBlock = true
				// named requires ';' after '}', but tolerate its absence.
				if p.pos < len(p.toks) && !p.toks[p.pos].quoted && p.toks[p.pos].text == ";" {
					p.pos++
				}
				break
			}
			s.Args = append(s.Args, t.text)
			p.pos++
		}
		out = append(out, s)
	}
}
