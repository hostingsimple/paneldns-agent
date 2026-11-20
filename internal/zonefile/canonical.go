package zonefile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Canonical is a zone in canonical form (docs/PROTOCOL.md section 5).
type Canonical struct {
	Origin string   // apex, canonical, trailing dot
	Serial uint32   // SOA serial
	Lines  []string // canonical records, de-duplicated, sorted bytewise
	Text   string   // the text pushed to PanelDNS
	Hash   string   // "sha256:" + hex of the hash input
}

// HashInput returns the bytes that are hashed: every canonical line, in
// sorted order, with the SOA serial field removed, each ending in "\n".
func (c *Canonical) HashInput() string {
	var b strings.Builder
	for _, l := range c.Lines {
		b.WriteString(hashLine(l))
		b.WriteByte('\n')
	}
	return b.String()
}

func hashLine(l string) string {
	f := strings.Split(l, " ")
	// owner ttl IN SOA mname rname serial refresh retry expire minimum
	if len(f) == 11 && f[3] == "SOA" {
		return strings.Join(append(f[:6:6], f[7:]...), " ")
	}
	return l
}

// MakeCanonical turns parsed, stripped records into canonical form. It
// fails only on structure: no SOA, more than one, an SOA away from the
// apex, or an owner name that is not a valid name.
func MakeCanonical(rrs []RR, origin string) (*Canonical, error) {
	apex, err := CanonicalName(origin, ".")
	if err != nil {
		return nil, fmt.Errorf("zone name: %w", err)
	}
	set := map[string]bool{}
	var soa string
	var serial uint32
	for _, rr := range rrs {
		owner, err := CanonicalName(rr.Name, apex)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: owner %q: %w", rr.File, rr.Line, rr.Name, err)
		}
		typ := CanonicalType(rr.Type)
		data := canonicalRdata(typ, rr.Data, apex)
		line := owner + " " + strconv.FormatUint(uint64(rr.TTL), 10) + " IN " + typ
		if data != "" {
			line += " " + data
		}
		if typ == "SOA" {
			if owner != apex {
				return nil, fmt.Errorf("%s:%d: SOA owner %s is not the zone apex %s", rr.File, rr.Line, owner, apex)
			}
			if soa != "" && soa != line {
				return nil, fmt.Errorf("%s:%d: more than one SOA record", rr.File, rr.Line)
			}
			f := strings.Split(line, " ")
			if len(f) != 11 {
				return nil, fmt.Errorf("%s:%d: SOA record must have 7 fields", rr.File, rr.Line)
			}
			n, err := strconv.ParseUint(f[6], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: SOA serial %q: %v", rr.File, rr.Line, f[6], err)
			}
			soa, serial = line, uint32(n)
		}
		set[line] = true
	}
	if soa == "" {
		return nil, fmt.Errorf("zone %s has no SOA record", apex)
	}
	lines := make([]string, 0, len(set))
	for l := range set {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	c := &Canonical{Origin: apex, Serial: serial, Lines: lines}

	var text strings.Builder
	text.WriteString("$ORIGIN " + apex + "\n")
	text.WriteString(soa + "\n")
	for _, l := range lines {
		if l != soa {
			text.WriteString(l + "\n")
		}
	}
	c.Text = text.String()
	sum := sha256.Sum256([]byte(c.HashInput()))
	c.Hash = "sha256:" + hex.EncodeToString(sum[:])
	return c, nil
}

// nameFields lists, per type, the rdata positions holding domain names.
var nameFields = map[string][]int{
	"NS": {0}, "CNAME": {0}, "DNAME": {0}, "PTR": {0}, "MB": {0}, "MG": {0}, "MR": {0},
	"MX": {1}, "RT": {1}, "KX": {1}, "AFSDB": {1}, "SRV": {3}, "SOA": {0, 1},
	"RP": {0, 1}, "MINFO": {0, 1}, "NAPTR": {5}, "PX": {1, 2}, "SVCB": {1}, "HTTPS": {1},
}

// arity is the exact token count a type's per-type rules need; other
// counts fall back to the generic rule.
var arity = map[string]int{
	"A": 1, "AAAA": 1, "NS": 1, "CNAME": 1, "DNAME": 1, "PTR": 1, "MB": 1, "MG": 1, "MR": 1,
	"MX": 2, "RT": 2, "KX": 2, "AFSDB": 2, "SRV": 4, "SOA": 7, "RP": 2, "MINFO": 2,
	"NAPTR": 6, "PX": 3, "CAA": 3, "HINFO": 2, "URI": 3,
}

// minArity is the least token count for types with a variable tail.
var minArity = map[string]int{"DS": 4, "TLSA": 4, "SSHFP": 3, "SVCB": 2, "HTTPS": 2, "TXT": 1, "SPF": 1}

type fieldKind int

const (
	kGeneric fieldKind = iota
	kName
	kUint    // decimal integer
	kTTL     // decimal or TTL units (SOA timers)
	kString  // character-string
	kLower   // token lower-cased (CAA tag)
	kHexTail // this and every later token, joined and upper-cased
	kStrTail // this and every later token as character-strings
	kIPv4    // dotted quad
	kIPv6    // RFC 5952
)

// layout gives the field kinds per type (names come from nameFields).
var layout = map[string][]fieldKind{
	"A":     {kIPv4},
	"AAAA":  {kIPv6},
	"MX":    {kUint, kName},
	"RT":    {kUint, kName},
	"KX":    {kUint, kName},
	"AFSDB": {kUint, kName},
	"SRV":   {kUint, kUint, kUint, kName},
	"SOA":   {kName, kName, kUint, kTTL, kTTL, kTTL, kTTL},
	"NAPTR": {kUint, kUint, kString, kString, kString, kName},
	"PX":    {kUint, kName, kName},
	"CAA":   {kUint, kLower, kString},
	"HINFO": {kString, kString},
	"RP":    {kName, kName},
	"MINFO": {kName, kName},
	"URI":   {kUint, kUint, kString},
	"DS":    {kUint, kUint, kUint, kHexTail},
	"TLSA":  {kUint, kUint, kUint, kHexTail},
	"SSHFP": {kUint, kUint, kHexTail},
	"TXT":   {kStrTail},
	"SPF":   {kStrTail},
	"SVCB":  {kUint, kName},
	"HTTPS": {kUint, kName},
}

func canonicalRdata(typ string, data []Token, origin string) string {
	if len(data) > 0 && !data[0].Quoted && data[0].Text == `\#` {
		return genericUnknown(data)
	}
	kinds, ok := layout[typ]
	if nf := nameFields[typ]; !ok && len(nf) == 1 && nf[0] == 0 {
		kinds = []fieldKind{kName} // NS, CNAME, PTR and the other one-name types
	}
	if kinds == nil || !arityOK(typ, len(data)) {
		return generic(data)
	}
	out := make([]string, 0, len(data))
	for i := 0; i < len(data); i++ {
		k := kGeneric
		if i < len(kinds) {
			k = kinds[i]
		} else if len(kinds) > 0 && (kinds[len(kinds)-1] == kStrTail) {
			k = kStrTail
		}
		t := data[i]
		var v string
		var err error
		switch k {
		case kName:
			if t.Quoted {
				return generic(data)
			}
			v, err = CanonicalName(t.Text, origin)
		case kUint:
			v, err = canonUint(t)
		case kTTL:
			if t.Quoted {
				return generic(data)
			}
			var n uint32
			n, err = ParseTTL(t.Text)
			v = strconv.FormatUint(uint64(n), 10)
		case kString, kStrTail:
			v, err = CharString(t.Text)
		case kLower:
			if t.Quoted {
				return generic(data)
			}
			v = strings.ToLower(t.Text)
		case kHexTail:
			var sb strings.Builder
			for _, h := range data[i:] {
				if h.Quoted || !isHex(h.Text) {
					return generic(data)
				}
				sb.WriteString(strings.ToUpper(h.Text))
			}
			out = append(out, sb.String())
			i = len(data)
			continue
		case kIPv4:
			var a netip.Addr
			a, err = netip.ParseAddr(t.Text)
			if err == nil && !a.Is4() {
				err = fmt.Errorf("not IPv4")
			}
			v = a.String()
		case kIPv6:
			var a netip.Addr
			a, err = netip.ParseAddr(t.Text)
			if err == nil && (!a.Is6() || a.Zone() != "") {
				err = fmt.Errorf("not IPv6")
			}
			v = a.String()
		default:
			v = genericToken(t)
		}
		if err != nil {
			return generic(data)
		}
		out = append(out, v)
	}
	return strings.Join(out, " ")
}

func arityOK(typ string, n int) bool {
	if want, ok := arity[typ]; ok {
		return n == want
	}
	if min, ok := minArity[typ]; ok {
		return n >= min
	}
	// Single-name types not in arity are covered above; anything else
	// generic.
	return n == 1
}

func canonUint(t Token) (string, error) {
	if t.Quoted {
		return "", fmt.Errorf("quoted number")
	}
	n, err := strconv.ParseUint(t.Text, 10, 32)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(n, 10), nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// genericUnknown canonicalises RFC 3597 rdata: \# <len> <hex...>.
func genericUnknown(data []Token) string {
	if len(data) < 2 || data[1].Quoted {
		return generic(data)
	}
	n, err := strconv.ParseUint(data[1].Text, 10, 16)
	if err != nil {
		return generic(data)
	}
	var hx strings.Builder
	for _, t := range data[2:] {
		if t.Quoted || !isHex(t.Text) {
			return generic(data)
		}
		hx.WriteString(strings.ToUpper(t.Text))
	}
	if n == 0 {
		return `\# 0`
	}
	return `\# ` + strconv.FormatUint(n, 10) + " " + hx.String()
}

// generic joins tokens with single spaces; quoted tokens become canonical
// character-strings and unquoted ones stay as written.
func generic(data []Token) string {
	out := make([]string, len(data))
	for i, t := range data {
		out[i] = genericToken(t)
	}
	return strings.Join(out, " ")
}

func genericToken(t Token) string {
	if t.Quoted {
		if s, err := CharString(t.Text); err == nil {
			return s
		}
		return `"` + t.Text + `"`
	}
	return t.Text
}

// decodeEscapes turns presentation text into bytes (\X and \DDD).
func decodeEscapes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+1 >= len(s) {
			return nil, fmt.Errorf("trailing backslash")
		}
		if isDigit(s[i+1]) {
			if i+3 >= len(s) || !isDigit(s[i+2]) || !isDigit(s[i+3]) {
				return nil, fmt.Errorf("bad \\DDD escape")
			}
			n, _ := strconv.Atoi(s[i+1 : i+4])
			if n > 255 {
				return nil, fmt.Errorf("\\DDD escape above 255")
			}
			out = append(out, byte(n))
			i += 3
			continue
		}
		out = append(out, s[i+1])
		i++
	}
	return out, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// CharString returns the canonical quoted form of a character-string given
// as presentation text (quoted content or an unquoted token).
func CharString(s string) (string, error) {
	b, err := decodeEscapes(s)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteByte('"')
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			sb.WriteString(fmt.Sprintf("\\%03d", c))
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String(), nil
}

// CanonicalName makes name absolute against origin ("@" is the origin),
// lower-cases ASCII letters and re-encodes every label with one escape
// form per byte.
func CanonicalName(name, origin string) (string, error) {
	if name == "@" {
		name = origin
	} else if !endsWithDot(name) {
		if origin == "." {
			name += "."
		} else {
			name += "." + origin
		}
	}
	if name == "." {
		return ".", nil
	}
	labels, err := splitLabels(name[:len(name)-1])
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	total := 0
	for _, l := range labels {
		if len(l) == 0 {
			return "", fmt.Errorf("empty label")
		}
		if len(l) > 63 {
			return "", fmt.Errorf("label longer than 63 bytes")
		}
		total += len(l) + 1
		for _, c := range l {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			switch {
			case c == '.' || c == '\\' || c == '"' || c == '(' || c == ')' || c == ';' || c == '@' || c == '$':
				sb.WriteByte('\\')
				sb.WriteByte(c)
			case c <= 0x20 || c >= 0x7f:
				sb.WriteString(fmt.Sprintf("\\%03d", c))
			default:
				sb.WriteByte(c)
			}
		}
		sb.WriteByte('.')
	}
	if total+1 > 255 {
		return "", fmt.Errorf("name longer than 255 bytes")
	}
	return sb.String(), nil
}

// splitLabels splits on unescaped dots and decodes each label.
func splitLabels(s string) ([][]byte, error) {
	var out [][]byte
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			if i+1 < len(s) && isDigit(s[i+1]) {
				i += 3
			} else {
				i++
			}
			continue
		}
		if s[i] == '.' {
			l, err := decodeEscapes(s[start:i])
			if err != nil {
				return nil, err
			}
			out = append(out, l)
			start = i + 1
		}
	}
	l, err := decodeEscapes(s[start:])
	if err != nil {
		return nil, err
	}
	return append(out, l), nil
}
