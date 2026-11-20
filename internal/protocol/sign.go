package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// Request headers (spec 8.2).
const (
	HeaderKey          = "X-PanelDNS-Key"
	HeaderTimestamp    = "X-PanelDNS-Timestamp"
	HeaderNonce        = "X-PanelDNS-Nonce"
	HeaderEpoch        = "X-PanelDNS-Epoch"
	HeaderSeq          = "X-PanelDNS-Seq"
	HeaderSignature    = "X-PanelDNS-Signature"
	HeaderAgentVersion = "X-PanelDNS-Agent-Version"
)

// BodyHash is the lower-case hex SHA-256 of the body bytes as sent on the
// wire (gzip-compressed).
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// SigningString is the message signed for a request (spec 8.2,
// docs/PROTOCOL.md section 3):
//
//	METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" EPOCH "\n" SEQ "\n" HEX(SHA-256(BODY))
//
// with no trailing newline. METHOD is upper case, PATH is the request
// path without scheme, host or query, numbers are decimal.
func SigningString(method, path string, timestamp int64, nonce string, epoch, seq uint64, body []byte) string {
	return strings.Join([]string{
		strings.ToUpper(method),
		path,
		strconv.FormatInt(timestamp, 10),
		nonce,
		strconv.FormatUint(epoch, 10),
		strconv.FormatUint(seq, 10),
		BodyHash(body),
	}, "\n")
}

// Sign returns the standard (padded) base64 Ed25519 signature of the
// signing string.
func Sign(key ed25519.PrivateKey, method, path string, timestamp int64, nonce string, epoch, seq uint64, body []byte) string {
	msg := SigningString(method, path, timestamp, nonce, epoch, seq, body)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(msg)))
}

// Verify checks a signature the way the server does.
func Verify(pub ed25519.PublicKey, sig, method, path string, timestamp int64, nonce string, epoch, seq uint64, body []byte) bool {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, []byte(SigningString(method, path, timestamp, nonce, epoch, seq, body)), raw)
}

// EncodePublicKey is the public key as sent at enrolment and rotation:
// standard base64 of the 32 raw bytes.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
