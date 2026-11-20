package zonefile

import (
	"strconv"
	"strings"
)

// typeNumbers maps the mnemonics the agent treats specially to their
// numbers (IANA DNS parameters), so a TYPEnnn spelling is recognised too.
var typeNumbers = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MB": 7, "MG": 8, "MR": 9,
	"PTR": 12, "HINFO": 13, "MINFO": 14, "MX": 15, "TXT": 16, "RP": 17,
	"AFSDB": 18, "RT": 21, "SIG": 24, "KEY": 25, "PX": 26, "AAAA": 28,
	"LOC": 29, "NXT": 30, "SRV": 33, "NAPTR": 35, "KX": 36, "CERT": 37,
	"DNAME": 39, "DS": 43, "SSHFP": 44, "RRSIG": 46, "NSEC": 47,
	"DNSKEY": 48, "DHCID": 49, "NSEC3": 50, "NSEC3PARAM": 51, "TLSA": 52,
	"SMIMEA": 53, "HIP": 55, "CDS": 59, "CDNSKEY": 60, "OPENPGPKEY": 61,
	"CSYNC": 62, "ZONEMD": 63, "SVCB": 64, "HTTPS": 65, "SPF": 99,
	"NID": 104, "L32": 105, "L64": 106, "LP": 107, "EUI48": 108,
	"EUI64": 109, "URI": 256, "CAA": 257, "AVC": 258, "DOA": 259,
	"AMTRELAY": 260, "RESINFO": 261, "WALLET": 262, "TA": 32768, "DLV": 32769,
}

var typeNames = func() map[uint16]string {
	m := make(map[uint16]string, len(typeNumbers))
	for k, v := range typeNumbers {
		m[v] = k
	}
	return m
}()

// TypeNumber returns the number of a mnemonic or TYPEnnn spelling.
func TypeNumber(t string) (uint16, bool) {
	t = strings.ToUpper(t)
	if n, ok := typeNumbers[t]; ok {
		return n, true
	}
	if strings.HasPrefix(t, "TYPE") {
		n, err := strconv.ParseUint(t[4:], 10, 16)
		if err == nil {
			return uint16(n), true
		}
	}
	return 0, false
}

// CanonicalType returns the upper-case mnemonic for t, turning TYPEnnn into
// the mnemonic when the number is known.
func CanonicalType(t string) string {
	t = strings.ToUpper(t)
	if strings.HasPrefix(t, "TYPE") {
		if n, ok := TypeNumber(t); ok {
			if name, ok := typeNames[n]; ok {
				return name
			}
			return "TYPE" + strconv.FormatUint(uint64(n), 10)
		}
	}
	return t
}

// Stripped types (spec 7.3): AbstractProvider::ZONE_READ_SKIPPED_TYPES of
// the app without SOA (the agent keeps SOA; see docs/DECISIONS.md D-03),
// plus the private-use range TYPE65280-TYPE65534.
var strippedTypes = map[uint16]bool{
	46: true, // RRSIG
	47: true, // NSEC
	48: true, // DNSKEY
	50: true, // NSEC3
	51: true, // NSEC3PARAM
	59: true, // CDS
	60: true, // CDNSKEY
}

// IsStripped reports whether records of type t are removed before pushing.
func IsStripped(t string) bool {
	n, ok := TypeNumber(t)
	if !ok {
		return false
	}
	return strippedTypes[n] || (n >= 65280 && n <= 65534)
}

// StripResult describes what Strip removed.
type StripResult struct {
	Removed        int
	SignedAtSource bool // a DNSKEY or RRSIG was removed
}

// Strip removes DNSSEC and private record types in place and reports
// whether the zone was signed at the source.
func Strip(rrs []RR) ([]RR, StripResult) {
	var res StripResult
	out := rrs[:0]
	for _, rr := range rrs {
		if IsStripped(rr.Type) {
			res.Removed++
			if n, _ := TypeNumber(rr.Type); n == 46 || n == 48 {
				res.SignedAtSource = true
			}
			continue
		}
		out = append(out, rr)
	}
	return out, res
}
